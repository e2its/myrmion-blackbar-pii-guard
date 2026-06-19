---
description: Restore PII that was reversibly encrypted by blackbar, using the same key
argument-hint: "[text or file path with <ENC:...> tokens] [--key <key>]"
---

Use the `presidio_decrypt` tool from the blackbar MCP server to turn
`<ENC:TYPE:...>` tokens back into their original values.

Input: $ARGUMENTS

Steps:
1. Determine the text to decrypt (the argument, a referenced file's contents,
   or the current selection). It should contain `<ENC:...>` tokens produced by
   a previous `encrypt` run.
2. Determine the key. If the user did not supply one (e.g. `--key abc`), ask for
   it — decryption is impossible without the exact key used to encrypt.
3. Call `presidio_decrypt` with the text and key.
4. Return the restored text in a copyable code block and report how many tokens
   were restored. If some tokens remained as `<ENC:...>`, warn that the key was
   wrong for those (or the token was altered) — they are left untouched on
   purpose, never guessed.

Only reveal the decrypted values to the user who supplied the key; never write
them to logs or send them over the network.
