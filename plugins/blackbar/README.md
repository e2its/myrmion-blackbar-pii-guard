# Myrmion blackbar

PII detection and redaction for Claude Code and Claude for VS Code, powered by
[Microsoft Presidio](https://github.com/microsoft/presidio).

It hooks four points in the Claude Code lifecycle and exposes two on-demand
tools, so personal data is caught at the boundaries where it matters.

## What it does

| Boundary | Hook event | Capability | Default |
| --- | --- | --- | --- |
| Your prompt | `UserPromptSubmit` | Detect → **warn** or **block** (a hook cannot rewrite a prompt) | warn |
| Outbound request | `PreToolUse` (`WebFetch`, `WebSearch`) | Detect → **ask** or **block** before PII leaves the machine | ask |
| Tool result | `PostToolUse` (`Read`, `Bash`, `WebFetch`, `Grep`, `Glob`) | **Redact** PII in the result before the model sees it (`updatedToolOutput`) | on |
| On screen | `MessageDisplay` | **Redact** PII from displayed text (display only) | off |

Plus an MCP server with `presidio_analyze`, `presidio_anonymize`, and
`presidio_decrypt`, and the slash commands `/blackbar:scan`,
`/blackbar:anonymize`, and `/blackbar:decrypt`.

The `encrypt` operator is reversible and **needs no extra dependencies**: it
emits self-contained `<ENC:TYPE:...>` tokens (a salt, nonce, ciphertext, and
HMAC tag, all base64url) using only the Python standard library, and
`presidio_decrypt` restores them with the same key. The same token format is
shared with the Claude Desktop server, so a value encrypted in one decrypts in
the other.

### Reversible tool-result encryption (`PostToolUse`)

Set `PRESIDIO_GUARD_RESULT_MODE=encrypt` (plus a key via `blackbar keygen` or
`BLACKBAR_KEY`) and tool results reach the model as reversible `<ENC:…>` tokens
instead of one-way placeholders — restore them locally with `/blackbar:decrypt`
or `blackbar dec`. Without a key it safely falls back to one-way redaction.

### Any interface (subscription-friendly): the `blackbar` CLI

`bin/blackbar` is an interface-agnostic CLI (`enc` / `dec` / `scan` / `keygen`)
that anonymizes text before it enters *any* app and restores it after — bind it
to a clipboard hotkey and it works in the Claude Chrome extension, claude.ai
web, Office, Claude Desktop, and Claude Code alike. It never touches your login
token or proxies traffic, so it is safe on a Pro/Max subscription. See
[`../../docs/clipboard.md`](../../docs/clipboard.md).

> The strongest, safest win is `PostToolUse`: it scrubs PII out of what the
> model ingests **without changing the file on disk or what your command
> actually ran**. The prompt boundary can only warn or block — Claude Code
> does not let a hook silently rewrite your prompt.

## Requirements

- Python 3.9+ on `PATH` as `python3` (on Windows, change `python3` to `python`
  in `hooks/hooks.json` and `plugin.json`).
- Either a running Presidio Analyzer service (recommended) **or** the Presidio
  Python library installed (heavier; slower per hook).

In the default **service** mode there are **no Python package dependencies** —
the hooks talk to the analyzer over HTTP using only the standard library.

## Setup

### 1. Start the Presidio analyzer (recommended)

```bash
docker compose -f docker-compose.yml up -d
export PRESIDIO_ANALYZER_URL=http://localhost:5002   # this is also the default
```

Or run library mode instead (no Docker, slower cold starts):

```bash
pip install -r requirements.txt
python -m spacy download en_core_web_lg
export PRESIDIO_GUARD_MODE=library
```

### 2. Add the marketplace and install

```bash
# from a clone of this repo, or by GitHub owner/repo once published
/plugin marketplace add ./e2its
/plugin install blackbar@e2its
```

### 3. Claude for VS Code

The VS Code extension runs the same Claude Code engine, so the same plugin,
hooks, and MCP server apply once installed — no separate build. Set the
environment variables above in the shell/profile that launches VS Code (or in
your `.claude/settings.json` env block) so the extension's hook processes
inherit them.

## Configuration

All behavior is controlled by environment variables:

| Variable | Values | Default | Meaning |
| --- | --- | --- | --- |
| `PRESIDIO_GUARD_MODE` | `service`, `library` | `service` | Detection backend |
| `PRESIDIO_ANALYZER_URL` | URL | `http://localhost:5002` | Analyzer service endpoint |
| `PRESIDIO_GUARD_OPERATOR` | `replace`, `redact`, `mask`, `hash` | `replace` | How detected PII is rewritten |
| `PRESIDIO_GUARD_LANGUAGE` | e.g. `en`, `es` | `en` | Detection language |
| `PRESIDIO_GUARD_THRESHOLD` | `0.0`–`1.0` | `0.5` | Minimum confidence to act |
| `PRESIDIO_GUARD_ENTITIES` | comma list | (all) | Restrict to specific entity types |
| `PRESIDIO_GUARD_PROMPT_POLICY` | `warn`, `block`, `off` | `warn` | Prompt boundary behavior |
| `PRESIDIO_GUARD_EGRESS_POLICY` | `ask`, `block`, `warn`, `off` | `ask` | Outbound request behavior (WebFetch/WebSearch) |
| `PRESIDIO_GUARD_INPUT_DECRYPT` | `on`, `off` | `off` | Decrypt `<ENC:…>` tokens in **local** tool inputs (Bash/Write/Edit/…) so actions use real values; never for egress tools. Pairs with `encrypt` mode. |
| `PRESIDIO_GUARD_RESULT_REDACTION` | `on`, `off` | `on` | Scrub tool results before the model sees them |
| `PRESIDIO_GUARD_RESULT_MODE` | `redact`, `encrypt` | `redact` | `redact` = one-way placeholders; `encrypt` = reversible `<ENC:…>` tokens (needs a key) |
| `BLACKBAR_KEY` / `BLACKBAR_KEY_FILE` | string / path | — / `~/.config/blackbar/key` | Session key for `encrypt` mode and the `blackbar` CLI. Create one with `blackbar keygen`. |
| `PRESIDIO_GUARD_DISPLAY_REDACTION` | `on`, `off` | `off` | Redact on-screen text |
| `PRESIDIO_GUARD_FAIL` | `open`, `closed` | `open` | Behavior when Presidio is unreachable |
| `BLACKBAR_AUDIT_ENABLED` | `1`/`true`/`on`, off | off | Write a PII-safe audit record for every detector call |
| `BLACKBAR_AUDIT_DIR` | path | `$XDG_DATA_HOME/blackbar/audit` | Where audit day-files are stored |
| `BLACKBAR_AUDIT_RETENTION_DAYS` | integer | `90` | Days to keep audit files; `<=0` keeps them forever |
| `PII_AUDIT_SALT` | string | — | Secret salt for fingerprints — **set a real secret in production** |

`fail=open` keeps you working (with a one-line notice) if the analyzer is down;
`fail=closed` blocks instead — choose based on your risk posture.

## Audit trail (opt-in)

Set `BLACKBAR_AUDIT_ENABLED=1` and every PII detection — from hooks, the MCP
server, the CLI and the proxy — is logged at the single chokepoint
(`PresidioClient.analyze`), reusing the spans already computed (no re-detection).

Records carry an `event` field:

* `detect` — what the detector found (entities, scores, decision process).
* `anonymize` — what the anonymization step actually **did**: the operator
  applied (`replace`/`redact`/`mask`/`hash`/`encrypt`/`decrypt`), how many values
  it transformed, and any `fallback` (e.g. `encrypt` → `redact` when no key was
  available). This makes process problems visible in the trail, not just
  detections. It records the operator name and counts only — never the values or
  the `<ENC:…>` tokens.

The log is designed so it can never be the leak: it stores a salted SHA-256
**fingerprint** of the input (correlate identical inputs without keeping them),
the redacted text, and each entity's type/score/span — **never the raw PII**.
Set `PII_AUDIT_SALT` to a real secret kept in your secrets manager, not in code.

Each entity also records *why* it was detected — the Presidio **recognizer** and
named **pattern** (e.g. `EmailRecognizer` / `Email (Medium)`, or `SpacyRecognizer`
with a null pattern for NER hits). This decision process is requested only while
auditing is enabled, so the normal detection path is untouched; it works in both
`service` mode (the analyzer returns it on request) and `library` mode. A sample
record:

```json
{
  "ts": "2026-06-30T08:48:59Z", "source": "cli:scan",
  "fingerprint": "be6bdae9ff1fee1a", "lang": "es", "mode": "service",
  "n_entities": 2,
  "entities": [
    {"type": "EMAIL_ADDRESS", "score": 1.0, "start": 23, "end": 45,
     "recognizer": "EmailRecognizer", "pattern": "Email (Medium)"},
    {"type": "PERSON", "score": 0.85, "start": 11, "end": 21,
     "recognizer": "SpacyRecognizer", "pattern": null}
  ],
  "redacted": "El cliente <PERSON> (<EMAIL_ADDRESS>) llamo desde +34 600 123 456"
}
```

…and the matching `anonymize` record for the hook that encrypted that result:

```json
{
  "ts": "2026-06-30T08:49:01Z", "event": "anonymize",
  "source": "hook:PostToolUse", "operator": "encrypt",
  "n_transformed": 2, "ok": true
}
```

(An `encrypt` that fell back for lack of a key reads
`"operator": "redact", "requested": "encrypt", "fallback": "no_key"`.)

Records are appended as JSON lines, one file per UTC day
(`pii-audit-YYYY-MM-DD.jsonl`) under `BLACKBAR_AUDIT_DIR`. Retention works by
deleting whole day-files: when the day rolls over, files older than
`BLACKBAR_AUDIT_RETENTION_DAYS` (default 90) are pruned automatically
(storage-limitation, GDPR Art. 5(1)(e)). The fingerprint is one-way, so
per-subject erasure is neither possible nor needed — the retention window is the
control. Manage the trail by hand with:

```bash
blackbar audit stats          # files, record count, days, size
blackbar audit prune          # delete files past the retention window now
blackbar audit purge --yes    # delete every audit file
```

## Does PII reach the model? (guarantees & limits)

**Short answer: no configuration *guarantees* that zero PII reaches the model.**
blackbar is defense-in-depth that removes a large share of personal data —
especially from tool results — but several paths remain by design. Know them so
you can choose your posture deliberately.

### What is covered vs what gets through

| Path | Default | Detected PII reaches the model? |
| --- | --- | --- |
| **Your prompt** | `warn` | **Yes.** A hook cannot rewrite a prompt; `warn` only adds a note. Only `block` stops it — by rejecting the whole prompt. |
| **Tool results from `Read`/`Bash`/`WebFetch`/`Grep`/`Glob`** | redacted/encrypted | **No** (while the analyzer is reachable). |
| **Tool results from other tools** (`Edit`, `Write`, MCP tools, `Task`/subagents…) | not intercepted | **Yes.** `PostToolUse` only matches the five tools above. |
| **Analyzer unreachable** | `fail=open` | **Yes.** Results pass unredacted (with a one-line notice) unless `fail=closed`. |
| **Anything Presidio misses** | — | **Yes.** Only *detected* spans are removed; recall is high, not perfect. |

So PII detected in a covered tool result, with `:5002` up, does **not** reach the
model. Outside that — prompts, non-matched tools, outages, false negatives — it
can.

### What each setting actually does to a PII-bearing input

| Setting | Effect | Cost |
| --- | --- | --- |
| `PRESIDIO_GUARD_PROMPT_POLICY=warn` | Prompt passes; Claude is told to treat it as sensitive. | PII still reaches the model. |
| `PRESIDIO_GUARD_PROMPT_POLICY=block` | The **entire prompt** is rejected (`suppressOriginalPrompt`); you get the detected entity *types* and must rewrite and resubmit. Nothing is auto-redacted. | High friction: Presidio's false positives (names, URLs, locations in ordinary text) block normal prompts. |
| `PRESIDIO_GUARD_FAIL=open` | On analyzer outage, work continues unredacted with a notice. | A detector outage = a redaction gap. |
| `PRESIDIO_GUARD_FAIL=closed` | On analyzer outage, the action is blocked. | If `:5002` is down you cannot submit prompts or run matched tools. |
| `PRESIDIO_GUARD_RESULT_MODE=encrypt` | Covered tool results reach the model as reversible `<ENC:…>` tokens instead of placeholders. | Needs a key; changes *how* PII is hidden, not *which paths* are covered. |

### Tightening the net (opt-in, still not a certificate)

To close the structural gaps — at the cost above — you would: set
`PRESIDIO_GUARD_FAIL=closed`, set `PRESIDIO_GUARD_PROMPT_POLICY=block`, broaden
the `PostToolUse` matcher in `hooks/hooks.json` to cover more tools (`Edit`,
`Write`, MCP, `Task`…), and raise recall (`BLACKBAR_MODEL_SIZE=lg`, a lower
`PRESIDIO_GUARD_THRESHOLD`, the right languages). Even then it covers the *known*
paths, not "100%".

## Test it without Claude

```bash
# service mode, analyzer running:
echo '{"prompt":"summarize the notes on Ada Lovelace"}' | \
  python3 scripts/pii_filter.py UserPromptSubmit

python3 scripts/presidio_client.py "Ada Lovelace met Charles Babbage in London"
```

## Limitations & honesty

- Presidio is high-recall, not infallible. For regulated data, keep a human in
  the loop.
- Prompts cannot be silently redacted — only warned on or blocked (see
  [Does PII reach the model?](#does-pii-reach-the-model-guarantees--limits)).
- `PostToolUse` intercepts only `Read`/`Bash`/`WebFetch`/`Grep`/`Glob`; results
  from other tools (including MCP and subagents) are not scrubbed.
- `PreToolUse` only inspects `WebFetch`/`WebSearch` by default; it does not
  rewrite Bash commands (doing so would change what actually executes).
- The audit trail records detections and operations for observability; it does
  not itself prevent anything from reaching the model.
- This is a starting point, not a certified DLP product.
