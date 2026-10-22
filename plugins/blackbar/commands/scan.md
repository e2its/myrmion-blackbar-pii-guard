---
description: Scan text or a file for PII using Microsoft Presidio
argument-hint: "[text or file path]"
---

Use the `presidio_analyze` tool from the blackbar MCP server to find
personally identifiable information.

Target: $ARGUMENTS

Steps:
1. If the argument looks like a file path, read the file first; otherwise treat
   the argument (or the current selection) as the text to scan.
2. Call `presidio_analyze` with that text.
3. Present the findings as a short table: entity type, the matched snippet, and
   the confidence score. Do not echo any value you weren't already shown.
   Note to the user once: the scanned text and the matched values are part of
   this conversation, which is sent to the model provider — to scan without
   that, use `blackbar scan` locally.
4. If nothing is found, say so plainly.

If the MCP tool is unavailable, tell the user the Presidio analyzer service or
library isn't reachable and point them at the plugin README for setup.
