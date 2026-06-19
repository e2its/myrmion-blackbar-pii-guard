# blackbar for Claude Desktop

The on-demand half of blackbar, packaged as a one-click Claude Desktop
extension (`.mcpb`). Zero dependencies — a small Node server that ships with the
bundle. It adds three tools:

- `presidio_analyze` — find PII in text (types, spans, scores)
- `presidio_anonymize` — replace / mask / hash / redact / encrypt it
- `presidio_decrypt` — restore values that were encrypted, with the same key

## What carries over from the Claude Code plugin — and what doesn't

| Capability | Claude Code | Claude Desktop |
| --- | --- | --- |
| `presidio_analyze` / `presidio_anonymize` / `presidio_decrypt` tools (MCP) | yes | **yes** |
| Reversible `encrypt` + `presidio_decrypt` (shared token format) | yes | **yes** |
| Automatic redaction of tool results (`PostToolUse` hook) | yes | no |
| Prompt / egress / display guards (hooks) | yes | no |

Claude Desktop only loads third-party code as **MCP servers** — it has no hook
lifecycle — so the automatic guard does not exist there. You ask for redaction
explicitly ("scan this", "anonymize this") instead of it happening invisibly.
For the automatic behavior on the desktop, use the **Code** tab (Claude Code)
inside the desktop app and install the Claude Code plugin there.

## Prerequisites

- **No runtime to install** — Claude Desktop bundles Node, and this server has
  zero npm dependencies.
- A running **Presidio Analyzer** (detection runs locally on your machine):
  ```bash
  docker run -d -p 5002:3000 mcr.microsoft.com/presidio-analyzer:latest
  ```
- Nothing else: the reversible `encrypt`/`presidio_decrypt` operators use Node's
  built-in crypto, so **no Presidio Anonymizer service is required**.

## Install (one click)

1. Use the provided `blackbar.mcpb`, or rebuild it:
   ```bash
   npm install -g @anthropic-ai/mcpb
   mcpb pack            # validates the manifest and produces blackbar.mcpb
   # (the provided file is simply: zip -r blackbar.mcpb manifest.json package.json server)
   ```
2. In Claude Desktop: **Settings → Extensions → Advanced settings → Install
   Extension…**, or drag the `.mcpb` onto the window.
3. Review permissions, set the analyzer URL if needed, and install.

## Install (manual JSON, full control)

Add this to `claude_desktop_config.json` (Settings → Developer → Edit Config):

```json
{
  "mcpServers": {
    "blackbar": {
      "command": "node",
      "args": ["/absolute/path/to/blackbar-desktop/server/index.js"],
      "env": {
        "PRESIDIO_ANALYZER_URL": "http://localhost:5002"
      }
    }
  }
}
```

Restart Claude Desktop, then ask e.g. "scan this paragraph for PII" or
"anonymize this with masking".
