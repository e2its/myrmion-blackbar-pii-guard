<p align="center">
  <img src="assets/banner.svg" alt="blackbar — PII redaction for Claude Code & Claude Desktop" width="100%">
</p>

<p align="center">
  <a href="#license"><img src="https://img.shields.io/badge/license-MIT-1D9E75" alt="MIT license"></a>
  <img src="https://img.shields.io/badge/Claude_Code-plugin-378ADD" alt="Claude Code plugin">
  <img src="https://img.shields.io/badge/Claude_Desktop-.mcpb-378ADD" alt="Claude Desktop extension">
  <img src="https://img.shields.io/badge/engine-Microsoft_Presidio-7F77DD" alt="Microsoft Presidio">
  <img src="https://img.shields.io/badge/PII-redaction-444">
</p>

<p align="center">
  <b>blackbar</b> keeps personal data out of the model. It detects PII with
  <a href="https://github.com/microsoft/presidio">Microsoft Presidio</a> and
  redacts it at the boundaries where it matters — automatically in Claude Code,
  on demand in Claude Desktop.
</p>

---

## Why

When you point an AI agent at real files, real commands, and the live web, personal
data leaks in by accident — an email in a log, a customer name in a CSV, an SSN in a
stack trace. `blackbar` puts a redaction layer between your machine and the model so
that data is caught before it travels.

The honest framing: in **Claude Code** it's a *filter in the pipe* — tool results are
scrubbed automatically. In **Claude Desktop** it's a *tap you turn on* — you ask it to
scan or anonymize text, because Desktop only loads third-party code as MCP tools, not
lifecycle hooks.

## What it does

| Boundary | Where | What blackbar can do | Default |
| --- | --- | --- | --- |
| Your prompt | `UserPromptSubmit` | detect → **warn** or **block** (a hook can't rewrite a prompt) | warn |
| Outbound request | `PreToolUse` (`WebFetch`, `WebSearch`) | detect → **ask** or **block** before PII leaves the machine | ask |
| Tool result | `PostToolUse` (`Read`, `Bash`, `WebFetch`, …) | **redact** PII before the model sees it | on |
| On screen | `MessageDisplay` | **redact** displayed text (display only) | off |
| On demand | MCP tools | `presidio_analyze` · `presidio_anonymize` | — |

> The strongest win is the tool-result boundary: it scrubs what the model ingests
> **without changing the file on disk or what your command actually ran.**

## Quickstart — Claude Code (and Claude for VS Code)

```bash
# 1. Run the local Presidio analyzer (detection stays on your machine)
docker compose -f plugins/blackbar/docker-compose.yml up -d

# 2. Add the marketplace and install the plugin
/plugin marketplace add e2its/blackbar-pii-guard
/plugin install blackbar@e2its
```

That's it. The hooks start guarding immediately; tune behavior with environment
variables (see [`plugins/blackbar/README.md`](plugins/blackbar/README.md)).

## Quickstart — Claude Desktop

```bash
# Same analyzer service
docker run -d -p 5002:3000 mcr.microsoft.com/presidio-analyzer:latest
```

Then drag **`blackbar.mcpb`** onto Claude Desktop (or Settings → Extensions →
Install Extension). The bundle is a zero-dependency Node server — no Python, no
install. Ask Claude: *"scan this for PII"* or *"anonymize this with masking."*
Details in [`desktop/README.md`](desktop/README.md).

## On-demand tools

| Tool | Purpose |
| --- | --- |
| `presidio_analyze(text, language?, entities?)` | find PII: types, spans, scores |
| `presidio_anonymize(text, operator?, key?)` | `replace` · `redact` · `mask` · `hash` · `encrypt` |
| `presidio_decrypt(text, key)` | reverse `encrypt`: restore `<ENC:…>` tokens with the same key |

Only `encrypt` is reversible — it emits self-contained `<ENC:TYPE:…>` tokens
(zero extra dependencies on either client) that `presidio_decrypt` turns back
into the originals with the same key; the same token decrypts in both Claude
Code and Claude Desktop. The other operators are one-way.

Slash commands in Claude Code: `/blackbar:scan`, `/blackbar:anonymize`, and
`/blackbar:decrypt`.

## Repo layout

```
blackbar-pii-guard/
├── .claude-plugin/marketplace.json   # Claude Code marketplace catalog
├── plugins/blackbar/                 # the Claude Code plugin (hooks + MCP + skill)
│   ├── hooks/hooks.json
│   ├── scripts/{pii_filter,presidio_client,mcp_server}.py
│   ├── commands/{scan,anonymize}.md
│   └── skills/pii-handling/SKILL.md
├── desktop/                          # the Claude Desktop extension (.mcpb source)
│   ├── manifest.json
│   └── server/index.js               # zero-dependency Node MCP server
├── docs/custom-presidio-image.md     # build & publish your own analyzer image
└── assets/banner.svg
```

## Bring your own Presidio image

Want Spanish detection (DNI/NIF) or your own internal ID recognizers? Build a custom
analyzer image and publish it to your registry. See
[`docs/custom-presidio-image.md`](docs/custom-presidio-image.md).

## Limitations & honesty

- Presidio is high-recall, not infallible — keep a human in the loop for regulated data.
- Prompts can't be silently redacted, only warned on or blocked.
- `PreToolUse` inspects network tools; it does not rewrite Bash commands (that would
  change what actually executes).
- Claude Desktop gets the on-demand tools, not the automatic hooks.
- Not affiliated with or endorsed by Anthropic or Microsoft.

## License

MIT — see [LICENSE](LICENSE).
