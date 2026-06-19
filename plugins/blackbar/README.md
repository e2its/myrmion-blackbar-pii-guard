# blackbar

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
| `PRESIDIO_GUARD_EGRESS_POLICY` | `ask`, `block`, `warn`, `off` | `ask` | Outbound request behavior |
| `PRESIDIO_GUARD_RESULT_REDACTION` | `on`, `off` | `on` | Scrub tool results before the model sees them |
| `PRESIDIO_GUARD_RESULT_MODE` | `redact`, `encrypt` | `redact` | `redact` = one-way placeholders; `encrypt` = reversible `<ENC:…>` tokens (needs a key) |
| `BLACKBAR_KEY` / `BLACKBAR_KEY_FILE` | string / path | — / `~/.config/blackbar/key` | Session key for `encrypt` mode and the `blackbar` CLI. Create one with `blackbar keygen`. |
| `PRESIDIO_GUARD_DISPLAY_REDACTION` | `on`, `off` | `off` | Redact on-screen text |
| `PRESIDIO_GUARD_FAIL` | `open`, `closed` | `open` | Behavior when Presidio is unreachable |

`fail=open` keeps you working (with a one-line notice) if the analyzer is down;
`fail=closed` blocks instead — choose based on your risk posture.

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
- Prompts cannot be silently redacted — only warned on or blocked.
- `PreToolUse` only inspects `WebFetch`/`WebSearch` by default; it does not
  rewrite Bash commands (doing so would change what actually executes).
- This is a starting point, not a certified DLP product.
