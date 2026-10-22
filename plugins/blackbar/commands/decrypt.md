---
description: Restore PII that was reversibly encrypted by blackbar, with the local key
argument-hint: "[text or file path with <ENC:...> tokens]"
---

Use the `presidio_decrypt` tool from the blackbar MCP server to turn
`<ENC:TYPE:...>` tokens back into their original values.

Input: $ARGUMENTS

Steps:
1. Determine the text to decrypt (the argument, a referenced file's contents,
   or the current selection). It should contain `<ENC:...>` tokens produced by
   a previous `encrypt` run.
2. Warn first: the restored values come back as plaintext into this
   conversation, which is sent to the model provider. If the user only needs
   the originals locally, point them at `blackbar dec` instead.
3. Call `presidio_decrypt` with the text. The key is resolved locally
   (`BLACKBAR_KEY` or the `blackbar keygen` file). Never ask the user to type
   a key in the chat; if none is configured, tell them to run `blackbar keygen`.
4. Return the restored text in a copyable code block and report how many tokens
   were restored. If some tokens remained as `<ENC:...>`, warn that the key was
   wrong for those (or the token was altered) — they are left untouched on
   purpose, never guessed.

Never write the decrypted values to logs or send them over the network.
