# Blackbar Web — a local PII "firewall" for Claude Desktop

A small, localhost-only web app for the **manual copy/paste** workflow with
Claude Desktop (or any chat model). You paste a prompt, it anonymizes the
personal data into reversible `<ENC:…>` tokens, you copy that into Claude, and
when you paste Claude's reply back it restores the original values.

```
 ①  your text  ──Anonymize──▶  ②  <ENC:…> tokens  ──copy──▶  Claude Desktop
                                                                   │
 ④  restored text  ◀──Restore──  ③  paste Claude's reply  ◀──copy──┘
```

It reuses the exact same engine as the rest of blackbar (`bb_crypto`,
`presidio_client`, `bb_key`), so tokens are **interchangeable** with the CLI,
the Claude Code hooks/MCP, the proxy, and the Claude Desktop extension.

## Why it's safe

- **Localhost only.** The server binds `127.0.0.1` and refuses non-local `Host`
  headers, cross-origin POSTs, and any request without the per-launch CSRF token.
- **PII never touches disk.** Your text and the restored output live only in the
  browser tab's memory; the backend is stateless and never logs request bodies.
- **The key never enters the browser.** All crypto runs server-side; the UI only
  ever sees a short, non-reversible *fingerprint* of the key.
- **Decrypt needs no analyzer.** Restoring tokens uses only the text + the key,
  so the paste-back half keeps working even if Presidio is down.

## Quick start

1. **Start the Presidio analyzer** (needed for anonymize/scan; not for restore):
   ```sh
   cd plugins/blackbar/presidio-native && ./setup.sh && ./run.sh
   # or: docker compose -f plugins/blackbar/docker-compose.yml up -d
   curl http://localhost:5002/health      # {"status":"ok",...}
   ```

2. **Make sure you have a key** (or generate one in the UI later):
   ```sh
   bin/blackbar keygen          # writes ~/.config/blackbar/key (mode 0600)
   ```

3. **Launch the app** — any of:
   ```sh
   python3 web/blackbar_web.py            # opens http://127.0.0.1:8765
   bin/blackbar-web --port 9000 --no-open
   bin/blackbar web                       # via the CLI subcommand
   ```

## Features

- **Session ladder** — every turn tracks the four steps and keeps the multi-turn
  conversation in the sidebar (**newest first**), each stamped with its
  `date · time · timezone`. Turns can be **archived** (folded into a collapsible
  "Archived" group) or **deleted** from the sidebar.
- **Choose what to detect, per turn** — a **Detect** combo lists every entity type
  grouped by family (identity, contact, gov-id, financial, health, GDPR special
  categories, dates) with All / None. Untick what you don't care about. The default
  is *all types, sent explicitly* — which also makes names (`PERSON`) reliably
  detected (Presidio otherwise drops them when no list is given).
- **Partial-restore diagnostics** — because the app remembers the exact tokens it
  handed out, when Claude mangles one (line-wraps, retypes, truncates) it tells
  you *which* token failed and hands you the correct one to re-paste. Line-wrapped
  tokens are auto-repaired.
- **Live PII preview** — highlights detected entities by type before you send,
  with a confidence slider, per-type toggles, per-occurrence exclusion, per-entity
  operators, and manual "mark as" spans.
- **Copy-with-backticks** and a one-click **guardrail prompt** to keep tokens intact.
- **Document ingestion** — drop a `.docx / .xlsx / .pptx / .odt / .ods / .csv /
  .json / .txt / .md` and it extracts the text (zero dependencies). **PDF** is an
  optional extra: `pip install -r web/requirements-docs.txt`.
- **Key management** — status/fingerprint, generate, and rotate (with a warning),
  never showing the raw key.
- **Audit viewer** — when `BLACKBAR_AUDIT_ENABLED=1`, browse the PII-safe trail.
- **Export/import** the **tokenized** transcript only (never real PII), light/dark
  theme, keyboard shortcuts, and a **Panic** button that wipes memory instantly.

## Configuration (environment)

| Variable | Default | Purpose |
|---|---|---|
| `BLACKBAR_WEB_PORT` | `8765` | listen port |
| `BLACKBAR_WEB_MAX_UPLOAD` | 25 MiB | max document upload size |
| `PRESIDIO_ANALYZER_URL` | `http://localhost:5002` | detector service |
| `PRESIDIO_GUARD_LANGUAGE` | `en` | default language (`auto` also works) |
| `BLACKBAR_KEY` / `BLACKBAR_KEY_FILE` | — / `~/.config/blackbar/key` | encryption key |
| `BLACKBAR_AUDIT_ENABLED` | off | enable the PII-safe audit trail |

Only `encrypt` is reversible; `replace / redact / mask / hash` are one-way and the
UI warns you when you pick them.
