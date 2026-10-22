# Myrmion blackbar proxy — transparent anonymization for Claude Code (API key)

Path 3 of the [anonymization architecture](../docs/architecture-anonymization.md):
a local proxy that makes the round-trip **fully transparent** — you type and read
plaintext, while the model only ever sees `<ENC:…>` tokens.

```
Claude Code ──► blackbar_proxy ─────────────► api.anthropic.com
 (ANTHROPIC_     1. Presidio finds PII          (only tokens travel)
  BASE_URL)      2. bb_crypto encrypts it
                 ◄── 3. decrypts <ENC:…> in   ◄──
                       the streamed reply (local)
```

## Requirements & the subscription caveat

- A **Console API key** (`https://console.anthropic.com`). This path is API-key
  only **by design**: routing a Claude **Pro/Max subscription** OAuth token
  through a proxy violates Anthropic's Terms and is blocked server-side. For
  subscription use the universal CLI / clipboard flow instead (see
  [`../docs/clipboard.md`](../docs/clipboard.md)).
- A running **Presidio analyzer** (detection):
  `docker compose -f ../plugins/blackbar/docker-compose.yml up -d`
- A key for the tokens: `blackbar keygen` (shared with the hooks & CLI).
- Python 3.9+ — **no third-party dependencies**.

Works with **Claude Code (CLI and the VS Code extension)**. It does **not** apply
to Claude Desktop, which has no configurable API endpoint.

## Run it

```bash
blackbar keygen                                   # once, if you haven't
docker compose -f ../plugins/blackbar/docker-compose.yml up -d

python3 proxy/blackbar_proxy.py                   # listens on :8787

# in the shell that launches Claude Code / VS Code:
export ANTHROPIC_BASE_URL=http://localhost:8787
export ANTHROPIC_API_KEY=sk-ant-...               # Console key
```

Now use Claude Code normally. PII in your prompts, system prompt, and tool
results is encrypted before it leaves the machine; the model's replies are
decrypted locally — streaming included.

## Configuration (env)

| Var | Default | Meaning |
| --- | --- | --- |
| `BLACKBAR_PROXY_PORT` | `8787` | Listen port |
| `BLACKBAR_PROXY_UPSTREAM` | `https://api.anthropic.com` | Upstream API base |
| `BLACKBAR_KEY` / `BLACKBAR_KEY_FILE` | — / `~/.config/blackbar/key` | Encryption key |
| `PRESIDIO_GUARD_LANGUAGE` | `en` | Detection language |
| `PRESIDIO_ANALYZER_URL` | `http://localhost:5002` | Analyzer service |

## What it transforms

- **Outbound:** the `system` prompt and each message's text (plain string,
  `text` blocks, and `tool_result` text). Images and tool schemas are left
  untouched.
- **Inbound:** `text` blocks in the response, and `text_delta` events in a
  stream — with a buffer that holds back a partial `<ENC:…>` token split across
  SSE chunks and flushes it on `content_block_stop`, so reassembly is exact.

## Honesty & limits

- Detection is best-effort (Presidio is high-recall, not perfect); pair with a
  strict entity allow-list for sensitive data.
- MVP scope: it transforms text content. It does not yet rewrite PII the model
  emits inside *new* `tool_use` inputs, and assumes the upstream speaks the
  standard Messages API. No auth is added or removed — your key passes through.
- Fails closed: with no key or an unreachable analyzer, a Messages request
  (`/v1/messages`, its `?beta=true` form and `/v1/messages/count_tokens`) is
  answered `503` and never forwarded; any other `POST` route is answered `403`,
  because the proxy cannot scan it (this includes any other `POST` Claude Code
  sends through `ANTHROPIC_BASE_URL`, such as batches). A path with `;` or `..`
  is answered `400`. `PRESIDIO_GUARD_FAIL=open` forwards the first two
  unmodified instead, with a stderr notice.

| Variable | Values | Default | Effect |
|---|---|---|---|
| `PRESIDIO_GUARD_FAIL` | `open`, `closed` | `closed` | `closed` refuses what cannot be scanned; `open` forwards it unscanned |
