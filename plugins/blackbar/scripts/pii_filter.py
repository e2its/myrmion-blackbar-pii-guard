#!/usr/bin/env python3
"""
pii_filter.py
=============
Single entry point for every blackbar hook. The lifecycle event name is
passed as the first CLI argument (see hooks/hooks.json); the event payload
arrives as JSON on stdin. We emit Claude Code hook-output JSON on stdout.

Per-event behaviour (all configurable via env vars):

  UserPromptSubmit  detect PII in the prompt. A hook CANNOT rewrite a prompt,
                    so we either warn (inject additionalContext) or block.
                    PRESIDIO_GUARD_PROMPT_POLICY = warn | block | off   (warn)

  PreToolUse        two roles by tool:
                    * egress tools (WebFetch / WebSearch): PII in a URL or query
                      would leave the machine, so we ask or deny. Never decrypt.
                      PRESIDIO_GUARD_EGRESS_POLICY = ask | block | warn | off (ask)
                    * local tools (Bash / Write / Edit / ...): optionally decrypt
                      <ENC:...> tokens in the tool input via updatedInput, so
                      actions built from encrypted results use the real values
                      locally. Pairs with RESULT_MODE=encrypt; needs a key.
                      PRESIDIO_GUARD_INPUT_DECRYPT = on | off            (off)

  PostToolUse       scrub PII inside the tool RESULT before the model sees it,
                    via updatedToolOutput. The file/command output on disk is
                    untouched -- only what reaches the model is scrubbed.
                    PRESIDIO_GUARD_RESULT_REDACTION = on | off          (on)
                    PRESIDIO_GUARD_RESULT_MODE = redact | encrypt   (redact)
                      redact  -> one-way <EMAIL_ADDRESS> placeholders
                      encrypt -> reversible <ENC:TYPE:...> tokens (needs a key
                                 from BLACKBAR_KEY / `blackbar keygen`; restore
                                 with /blackbar:decrypt or `blackbar dec`).
                                 Falls back to redact if no key is found.

  MessageDisplay    redact PII from the on-screen assistant text (display only).
                    PRESIDIO_GUARD_DISPLAY_REDACTION = on | off         (off)

If Presidio is unreachable we FAIL OPEN by default (work continues) but surface
a one-line systemMessage so you know redaction is inactive. Set
PRESIDIO_GUARD_FAIL = closed to block instead.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bb_crypto  # noqa: E402
import bb_key  # noqa: E402
import pii_audit  # noqa: E402
from presidio_client import (  # noqa: E402
    PresidioClient,
    PresidioUnavailable,
    Span,
    _resolve_overlaps,
)

EGRESS_TOOLS = {"WebFetch", "WebSearch"}


def _env(name: str, default: str) -> str:
    v = os.environ.get(name)
    return v if v not in (None, "") else default


def _emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj))
    sys.stdout.flush()


def _summary(spans: list[Span]) -> str:
    types = sorted({s.entity_type for s in spans})
    return ", ".join(types)


def _fail(message: str) -> None:
    """Handle a Presidio outage according to the fail mode."""
    if _env("PRESIDIO_GUARD_FAIL", "open") == "closed":
        sys.stderr.write(f"[blackbar] blocked: {message}")
        sys.exit(2)
    _emit({"systemMessage": f"blackbar inactive: {message}"})
    sys.exit(0)


# --------------------------------------------------------------------------- #
# Event handlers
# --------------------------------------------------------------------------- #
def handle_user_prompt_submit(data: dict, client: PresidioClient) -> None:
    policy = _env("PRESIDIO_GUARD_PROMPT_POLICY", "warn")
    if policy == "off":
        sys.exit(0)
    spans = client.analyze(data.get("prompt", ""))
    if not spans:
        sys.exit(0)
    found = _summary(spans)
    if policy == "block":
        _emit(
            {
                "decision": "block",
                "reason": (
                    f"blackbar detected PII in your prompt ({found}). "
                    "Remove or redact it, then resubmit."
                ),
                "suppressOriginalPrompt": True,
            }
        )
        sys.exit(0)
    # warn: let it through but tell Claude what was present
    _emit(
        {
            "hookSpecificOutput": {
                "hookEventName": "UserPromptSubmit",
                "additionalContext": (
                    f"[blackbar] The user's prompt contains likely PII "
                    f"({found}). Treat these values as sensitive; do not repeat "
                    "them verbatim or write them to logs, files, or network calls."
                ),
            }
        }
    )
    sys.exit(0)


def handle_pre_tool_use(data: dict, client: PresidioClient) -> None:
    tool = data.get("tool_name", "")
    if tool in EGRESS_TOOLS:
        _egress_guard(data, client, tool)
    else:
        _decrypt_tool_input(data, client, tool)
    sys.exit(0)


def _egress_guard(data: dict, client: PresidioClient, tool: str) -> None:
    """Gate outbound network tools: PII in a URL/query would leave the machine.
    We never decrypt here — sending real values out is exactly what we prevent."""
    policy = _env("PRESIDIO_GUARD_EGRESS_POLICY", "ask")
    if policy == "off":
        return
    blob = json.dumps(data.get("tool_input", {}))
    spans = client.analyze(blob)
    if not spans:
        return
    found = _summary(spans)
    reason = (
        f"blackbar: this {tool} request contains likely PII ({found}) "
        "that would leave your machine."
    )
    if policy == "warn":
        _emit(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "additionalContext": f"[blackbar] {reason}",
                }
            }
        )
        return
    decision = "deny" if policy == "block" else "ask"
    _emit(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision,
                "permissionDecisionReason": reason,
            }
        }
    )


def _decrypt_tool_input(data: dict, client: PresidioClient, tool: str) -> None:
    """Restore <ENC:...> tokens inside a LOCAL tool's input via updatedInput, so
    actions the model builds from encrypted results operate on the real values.
    Opt-in (pairs with PRESIDIO_GUARD_RESULT_MODE=encrypt); never runs for
    egress tools, so decrypted PII never leaves the machine."""
    if _env("PRESIDIO_GUARD_INPUT_DECRYPT", "off") != "on":
        return
    key = bb_key.resolve_key(None)
    if not key:
        return
    tool_input = data.get("tool_input", None)
    if tool_input is None:
        return
    updated, count = client.map_strings(
        tool_input, lambda s: bb_crypto.decrypt_text(s, key)
    )
    if count == 0:
        return
    pii_audit.record_op(client.source, "decrypt", count)
    _emit(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "updatedInput": updated,
                "additionalContext": (
                    f"[blackbar] restored {count} encrypted value(s) into this "
                    f"{tool} call locally (they stay on your machine)."
                ),
            }
        }
    )


def handle_post_tool_use(data: dict, client: PresidioClient) -> None:
    if _env("PRESIDIO_GUARD_RESULT_REDACTION", "on") != "on":
        sys.exit(0)
    response = data.get("tool_response", None)
    if response is None:
        sys.exit(0)

    # redact (one-way, default) or encrypt (reversible tokens) the tool result.
    mode = _env("PRESIDIO_GUARD_RESULT_MODE", "redact")
    key = bb_key.resolve_key(None) if mode == "encrypt" else None

    if mode == "encrypt" and key:
        def _transform(text: str) -> tuple[str, int]:
            spans = client.analyze(text)
            if not spans:
                return text, 0
            resolved = _resolve_overlaps(spans)
            return bb_crypto.encrypt_spans(text, resolved, key), len(resolved)

        redacted, count = client.map_strings(response, _transform)
        note = (
            f"[blackbar] encrypted {count} PII value(s) in this tool result "
            "before you received it, as reversible <ENC:TYPE:...> tokens. "
            "Restore them locally with /blackbar:decrypt or `blackbar dec` "
            "(same key); do not attempt to guess the originals."
        )
    else:
        if mode == "encrypt" and not key:
            # Reversibility was requested but no key is available. Never leak by
            # doing nothing: fall back to one-way redaction and say so.
            sys.stderr.write(
                "[blackbar] PRESIDIO_GUARD_RESULT_MODE=encrypt but no key found "
                "(run `blackbar keygen` or set BLACKBAR_KEY); using one-way "
                "redaction for this result.\n"
            )
        redacted, count = client.redact_structure(response)
        note = (
            f"[blackbar] redacted {count} PII value(s) from this tool result "
            "before you received it. Placeholders like <EMAIL_ADDRESS> stand "
            "in for the originals."
        )

    if count:
        # Record what the anonymization actually did, so the trail shows the
        # operation (and any encrypt->redact fallback), not just the detection.
        if mode == "encrypt" and key:
            pii_audit.record_op(client.source, "encrypt", count)
        elif mode == "encrypt" and not key:
            pii_audit.record_op(
                client.source, client.cfg.operator, count,
                requested="encrypt", fallback="no_key",
            )
        else:
            pii_audit.record_op(client.source, client.cfg.operator, count)

    if count == 0:
        sys.exit(0)
    output = redacted if isinstance(redacted, str) else json.dumps(redacted)
    _emit(
        {
            "suppressOutput": True,
            "hookSpecificOutput": {
                "hookEventName": "PostToolUse",
                "updatedToolOutput": output,
                "additionalContext": note,
            },
        }
    )
    sys.exit(0)


def handle_message_display(data: dict, client: PresidioClient) -> None:
    if _env("PRESIDIO_GUARD_DISPLAY_REDACTION", "off") != "on":
        sys.exit(0)
    delta = data.get("delta", "")
    redacted, spans = client.redact(delta)
    if not spans:
        sys.exit(0)
    _emit(
        {
            "hookSpecificOutput": {
                "hookEventName": "MessageDisplay",
                "displayContent": redacted,
            }
        }
    )
    sys.exit(0)


HANDLERS = {
    "UserPromptSubmit": handle_user_prompt_submit,
    "PreToolUse": handle_pre_tool_use,
    "PostToolUse": handle_post_tool_use,
    "MessageDisplay": handle_message_display,
}


def main() -> None:
    event = sys.argv[1] if len(sys.argv) > 1 else ""
    handler = HANDLERS.get(event)
    if handler is None:
        sys.exit(0)
    try:
        data = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        sys.exit(0)  # malformed payload: never block on our own bug
    client = PresidioClient(source=f"hook:{event}")
    try:
        handler(data, client)
    except PresidioUnavailable as exc:
        _fail(str(exc))


if __name__ == "__main__":
    main()
