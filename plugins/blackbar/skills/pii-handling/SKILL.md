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
- `presidio_anonymize(text, operator?, language?, entities?, key?)` — returns a
  transformed copy. Operators: `replace` (default, `<EMAIL_ADDRESS>`), `redact`
  (delete), `mask` (`****1234`), `hash`, and `encrypt`. Only `encrypt` is
  reversible: it emits self-contained `<ENC:TYPE:...>` tokens and requires a
  `key`. The rest are one-way.
- `presidio_decrypt(text, key)` — restores every `<ENC:TYPE:...>` token in the
  text back to its original value using the same key. Needs only the text and
  the key (no spans, no Presidio service). Tokens that fail to authenticate
  (wrong key or tampered) are left untouched, never guessed.

## When to use which

- "Is there any personal data in this?" → `presidio_analyze`, then summarize.
- "Clean this up before I share it" → `presidio_anonymize` with `replace` or
  `mask`.
- "I need to re-identify later" → `presidio_anonymize` with `encrypt` and a key
  the user controls; restore with `presidio_decrypt` and the same key.
- Bulk files / datasets → read the content, analyze in chunks, then anonymize.

## Reversible encrypt / decrypt

`encrypt` replaces each value with a `<ENC:TYPE:base64>` token that embeds
everything needed to reverse it (a salt, a nonce, the ciphertext, and an
authentication tag) — so the only thing you must keep is the key. The same
token round-trips between Claude Code and Claude Desktop. To restore, pass the
encrypted text and the key to `presidio_decrypt`. A wrong key cannot corrupt the
data: mismatched tokens are returned unchanged. Always ask the user for the key
rather than inventing one, and never persist it.

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
