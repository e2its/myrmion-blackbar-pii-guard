---
name: pii-handling
description: >-
  Guidance for detecting and redacting personally identifiable information (PII)
  with Microsoft Presidio. Use whenever the user asks to find, scrub, mask,
  anonymize, or pseudonymize sensitive data (names, emails, phone numbers,
  credit cards, SSNs, IPs, etc.) in text, files, logs, or datasets, or when
  about to share content that may contain personal data externally.
---

# Handling PII with Presidio

This plugin wraps Microsoft Presidio. Three tools are available from the
`blackbar` MCP server:

- `presidio_analyze(text, language?, entities?)` — detects PII and returns each
  entity's type, span, score, and matched text.
- `presidio_anonymize(text, operator?, language?, entities?)` — returns a
  transformed copy. Operators: `replace` (default, `<EMAIL_ADDRESS>`), `redact`
  (delete), `mask` (`****1234`), `hash`, and `encrypt`. Only `encrypt` is
  reversible: it emits self-contained `<ENC:TYPE:...>` tokens with the local
  key (`BLACKBAR_KEY` or the `blackbar keygen` file). The rest are one-way.
- `presidio_decrypt(text)` — restores every `<ENC:TYPE:...>` token in the
  text back to its original value with the local key (no spans, no Presidio
  service). Tokens that fail to authenticate (wrong key or tampered) are left
  untouched, never guessed. The restored values come back as plaintext into
  the conversation, which is sent to the model provider.
- Never ask the user to type a key in the chat, and never pass one to a tool.

## When to use which

- "Is there any personal data in this?" → `presidio_analyze`, then summarize.
- "Clean this up before I share it" → `presidio_anonymize` with `replace` or
  `mask`.
- "I need to re-identify later" → `presidio_anonymize` with `encrypt`; restore
  with `presidio_decrypt` (same local key) or locally with `blackbar dec`.
- Bulk files / datasets → read the content, analyze in chunks, then anonymize.

## Reversible encrypt / decrypt

`encrypt` replaces each value with a `<ENC:TYPE:base64>` token that embeds
everything needed to reverse it (a salt, a nonce, the ciphertext, and an
authentication tag) — so the only thing you must keep is the key. The same
token round-trips between Claude Code and Claude Desktop. The key is local
configuration (`BLACKBAR_KEY` or `~/.config/blackbar/key`; in Claude Desktop the
extension's *Encryption key* setting) and never travels through the chat: never
request it, never accept one typed into the conversation, never persist it.
Prefer that the user restores tokens locally with `blackbar dec`;
`presidio_decrypt` puts the real values into the conversation. A wrong key
cannot corrupt the data: mismatched tokens are returned unchanged.

## Behavioral rules

- Never paste detected PII values back into chat, files, logs, or network calls
  beyond what's strictly necessary to answer.
- Tool results in this session may already be scrubbed by the PostToolUse hook;
  placeholders such as `<PERSON>` or `<EMAIL_ADDRESS>` are intentional — do not
  try to recover the originals.
- Presidio is high-recall but not perfect. For compliance-critical work, tell
  the user that a human should review the output.
- If a tool reports the analyzer is unavailable, point the user to the plugin
  README to start the Presidio service or install the library.

## Default entity coverage

PERSON, EMAIL_ADDRESS, PHONE_NUMBER, CREDIT_CARD, US_SSN, IBAN_CODE, IP_ADDRESS,
LOCATION, DATE_TIME, URL, US_BANK_NUMBER, US_DRIVER_LICENSE, US_PASSPORT,
CRYPTO, MEDICAL_LICENSE, and more. Restrict scope by passing `entities`.
