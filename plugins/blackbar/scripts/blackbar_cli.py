#!/usr/bin/env python3
"""
blackbar_cli.py
===============
A tiny, interface-agnostic command-line front end for blackbar. It is the
universal engine behind "anonymize before it enters any app, de-anonymize after
it leaves" — drive it from a shell, a pipe, or an OS clipboard hotkey, and it
works the same for the Claude Chrome extension, Office add-ins, claude.ai web,
Claude Desktop, and Claude Code.

It reuses the exact same pieces as the rest of blackbar:
  * presidio_client.PresidioClient  -> PII detection (service or library mode)
  * bb_crypto                       -> reversible <ENC:...> token format

Commands
--------
  blackbar enc   [text]   detect PII and replace it with reversible tokens
  blackbar dec   [text]   restore <ENC:...> tokens back to their values
  blackbar scan  [text]   list the PII found (no transformation)
  blackbar keygen         create a persistent random key (0600) for enc/dec

Text comes from the positional argument(s) or, if absent, from stdin — so both
of these work:

  blackbar enc "Call Ada at ada@example.com"
  pbpaste | blackbar enc | pbcopy        # clipboard round-trip on macOS
  wl-paste | blackbar dec | wl-copy      # ...or Wayland

Only the transformed text goes to STDOUT (pipe/clipboard friendly). Diagnostics
(entity counts, notices) go to STDERR, so piping stays clean.

Key resolution (first match wins)
---------------------------------
  1. --key <value>
  2. $BLACKBAR_KEY
  3. the key file at $BLACKBAR_KEY_FILE (default ~/.config/blackbar/key)

`enc`/`dec` need a key; run `blackbar keygen` once to create the default file.
Detection settings reuse the standard PRESIDIO_* env vars (see presidio_client).
"""

from __future__ import annotations

import argparse
import os
import secrets
import stat
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bb_crypto  # noqa: E402
import bb_key  # noqa: E402
import pii_audit  # noqa: E402
from presidio_client import (  # noqa: E402
    Config,
    PresidioClient,
    PresidioUnavailable,
    _resolve_overlaps,
)


def _err(msg: str) -> None:
    sys.stderr.write(f"[blackbar] {msg}\n")


def _read_text(args) -> str:
    if args.text:
        return " ".join(args.text)
    return sys.stdin.read()


def _client(args) -> PresidioClient:
    cfg = Config.load()
    if getattr(args, "language", None):
        cfg.language = args.language
    return PresidioClient(cfg, source=f"cli:{getattr(args, 'cmd', 'unknown')}")


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
def cmd_keygen(args) -> int:
    kf = Path(args.out).expanduser() if args.out else bb_key.default_key_file()
    if kf.exists() and not args.force:
        _err(f"key file already exists: {kf} (use --force to overwrite)")
        return 1
    kf.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_urlsafe(32)
    kf.write_text(key + "\n", encoding="utf-8")
    kf.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600
    _err(f"wrote new key to {kf} (mode 0600)")
    _err("keep this file safe — without it, encrypted values cannot be restored")
    return 0


def cmd_enc(args) -> int:
    key = bb_key.resolve_key(args.key)
    if not key:
        _err("no key found. Run `blackbar keygen`, set $BLACKBAR_KEY, or pass --key")
        return 2
    text = _read_text(args)
    client = _client(args)
    try:
        spans = client.analyze(text)
    except PresidioUnavailable as exc:
        _err(f"analyzer unavailable: {exc}")
        return 3
    resolved = _resolve_overlaps(spans)
    out = bb_crypto.encrypt_spans(text, resolved, key)
    sys.stdout.write(out)
    if sys.stdout.isatty():
        sys.stdout.write("\n")
    types = sorted({s.entity_type for s in resolved})
    _err(f"encrypted {len(resolved)} value(s): {', '.join(types) or '(none)'}")
    return 0


def cmd_dec(args) -> int:
    key = bb_key.resolve_key(args.key)
    if not key:
        _err("no key found. Set $BLACKBAR_KEY, pass --key, or create a key file")
        return 2
    text = _read_text(args)
    out, count = bb_crypto.decrypt_text(text, key)
    sys.stdout.write(out)
    if sys.stdout.isatty():
        sys.stdout.write("\n")
    _err(f"restored {count} token(s)")
    return 0


def cmd_scan(args) -> int:
    text = _read_text(args)
    client = _client(args)
    try:
        spans = client.analyze(text)
    except PresidioUnavailable as exc:
        _err(f"analyzer unavailable: {exc}")
        return 3
    if not spans:
        _err("no PII detected")
        return 0
    for s in sorted(spans, key=lambda s: s.start):
        sys.stdout.write(
            f"{s.entity_type}\t{s.start}-{s.end}\t{round(s.score, 3)}\t{text[s.start:s.end]}\n"
        )
    _err(f"{len(spans)} entity(ies) found")
    return 0


def cmd_audit(args) -> int:
    import json

    if args.action == "stats":
        print(json.dumps(pii_audit.stats(), indent=2, ensure_ascii=False))
        return 0
    if args.action == "prune":
        removed = pii_audit.prune()
        _err(f"pruned {len(removed)} file(s) past {pii_audit.retention_days()}-day retention")
        return 0
    if args.action == "purge":
        if not args.yes:
            reply = input(f"Delete ALL audit files in {pii_audit.audit_dir()}? [y/N] ").strip().lower()
            if reply not in {"y", "yes"}:
                _err("aborted")
                return 1
        removed = pii_audit.purge()
        _err(f"purged {len(removed)} file(s)")
        return 0
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="blackbar", description="Local PII anonymize/de-anonymize")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_common(sp):
        sp.add_argument("text", nargs="*", help="text (default: read stdin)")
        sp.add_argument("--key", help="encryption key (overrides env/key file)")
        sp.add_argument("--language", help="detection language, e.g. en or es")

    sp = sub.add_parser("enc", help="encrypt PII into reversible tokens")
    add_common(sp)
    sp.set_defaults(func=cmd_enc)

    sp = sub.add_parser("dec", help="restore <ENC:...> tokens")
    add_common(sp)
    sp.set_defaults(func=cmd_dec)

    sp = sub.add_parser("scan", help="list detected PII (no change)")
    add_common(sp)
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("keygen", help="create a persistent random key")
    sp.add_argument("--out", help="key file path (default ~/.config/blackbar/key)")
    sp.add_argument("--force", action="store_true", help="overwrite an existing key file")
    sp.set_defaults(func=cmd_keygen)

    sp = sub.add_parser("audit", help="manage the PII audit trail (stats/prune/purge)")
    sp.add_argument("action", choices=["stats", "prune", "purge"], help="audit action")
    sp.add_argument("--yes", action="store_true", help="skip confirmation for purge")
    sp.set_defaults(func=cmd_audit)

    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
