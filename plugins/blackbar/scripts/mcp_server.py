#!/usr/bin/env python3
"""
mcp_server.py
=============
A minimal, dependency-free Model Context Protocol (MCP) server over stdio that
exposes Presidio as two on-demand tools:

  presidio_analyze   -> list the PII entities found in a piece of text
  presidio_anonymize -> return a redacted/masked/hashed/encrypted copy

It speaks newline-delimited JSON-RPC 2.0 (the MCP stdio transport) directly, so
it needs no `mcp` SDK. PII detection reuses presidio_client (service or library
mode). Encryption/decryption, if requested, uses the optional
presidio-anonymizer library; otherwise the local operators are used.

Because this process is long-lived, library mode loads the spaCy model only
once -- which is why detection here can afford library mode even though the
per-invocation hooks prefer the HTTP service.
"""

from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bb_crypto  # noqa: E402
from presidio_client import (  # noqa: E402
    Config,
    PresidioClient,
    PresidioUnavailable,
    _apply_operator,
    _resolve_overlaps,
)

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "blackbar", "version": "0.2.0"}

TOOLS = [
    {
        "name": "presidio_analyze",
        "description": (
            "Detect personally identifiable information (PII) in text using "
            "Microsoft Presidio. Returns each entity's type, character span, "
            "confidence score, and the matched text."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string", "description": "Text to scan for PII."},
                "language": {"type": "string", "description": "Language code (default en)."},
                "entities": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional list of entity types to detect; default is all.",
                },
            },
            "required": ["text"],
        },
    },
    {
        "name": "presidio_anonymize",
        "description": (
            "Return a copy of the text with PII removed using the chosen "
            "operator: replace (<EMAIL_ADDRESS>), redact (delete), mask "
            "(****1234), hash, or encrypt. Only encrypt is reversible: it emits "
            "self-contained <ENC:TYPE:...> tokens that presidio_decrypt turns "
            "back into the originals with the same key. The other operators are "
            "one-way."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {"type": "string"},
                "operator": {
                    "type": "string",
                    "enum": ["replace", "redact", "mask", "hash", "encrypt"],
                    "description": "Anonymization operator (default replace).",
                },
                "language": {"type": "string"},
                "entities": {"type": "array", "items": {"type": "string"}},
                "key": {
                    "type": "string",
                    "description": "Encryption key (required only for operator=encrypt).",
                },
            },
            "required": ["text"],
        },
    },
    {
        "name": "presidio_decrypt",
        "description": (
            "Reverse a previous encrypt: find every <ENC:TYPE:...> token in the "
            "text and restore the original value using the same key. Needs only "
            "the text and the key — no spans, no Presidio service. Tokens that "
            "fail to authenticate (wrong key or tampered) are left untouched."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "Text containing <ENC:...> tokens to restore.",
                },
                "key": {
                    "type": "string",
                    "description": "The same key used when the text was encrypted.",
                },
            },
            "required": ["text", "key"],
        },
    },
]


def _client(language: str | None, entities: list | None) -> PresidioClient:
    cfg = Config.load()
    if language:
        cfg.language = language
    if entities:
        cfg.entities = tuple(entities)
    return PresidioClient(cfg)


def tool_analyze(args: dict) -> str:
    client = _client(args.get("language"), args.get("entities"))
    text = args.get("text", "")
    spans = client.analyze(text)
    findings = [
        {
            "entity_type": s.entity_type,
            "start": s.start,
            "end": s.end,
            "score": round(s.score, 3),
            "text": text[s.start : s.end],
        }
        for s in spans
    ]
    return json.dumps({"count": len(findings), "entities": findings}, indent=2)


def tool_anonymize(args: dict) -> str:
    operator = args.get("operator", "replace")
    text = args.get("text", "")
    client = _client(args.get("language"), args.get("entities"))

    if operator == "encrypt":
        return _anonymize_encrypt(client, text, args.get("key", ""))

    redacted, spans = client.redact(text) if operator == client.cfg.operator else (
        _apply_operator(text, client.analyze(text), operator),
        client.analyze(text),
    )
    return json.dumps(
        {"text": redacted, "entities_found": sorted({s.entity_type for s in spans})},
        indent=2,
    )


def _anonymize_encrypt(client: PresidioClient, text: str, key: str) -> str:
    if not key:
        return json.dumps({"error": "operator=encrypt requires a 'key'."})
    spans = client.analyze(text)
    # Apply right-to-left so earlier offsets stay valid as tokens change length.
    encrypted = bb_crypto.encrypt_spans(text, _resolve_overlaps(spans), key)
    return json.dumps(
        {
            "text": encrypted,
            "entities_found": sorted({s.entity_type for s in spans}),
            "note": "reversible: call presidio_decrypt with the same key",
        },
        indent=2,
    )


def tool_decrypt(args: dict) -> str:
    text = args.get("text", "")
    key = args.get("key", "")
    if not key:
        return json.dumps({"error": "presidio_decrypt requires a 'key'."})
    restored, count = bb_crypto.decrypt_text(text, key)
    return json.dumps({"text": restored, "restored": count}, indent=2)


def _dispatch_tool(name: str, args: dict) -> dict:
    try:
        if name == "presidio_analyze":
            text = tool_analyze(args)
        elif name == "presidio_anonymize":
            text = tool_anonymize(args)
        elif name == "presidio_decrypt":
            text = tool_decrypt(args)
        else:
            return {"content": [{"type": "text", "text": f"Unknown tool: {name}"}], "isError": True}
        return {"content": [{"type": "text", "text": text}]}
    except PresidioUnavailable as exc:
        return {"content": [{"type": "text", "text": f"Presidio unavailable: {exc}"}], "isError": True}


def _handle(msg: dict):
    method = msg.get("method")
    msg_id = msg.get("id")

    if method == "initialize":
        requested = msg.get("params", {}).get("protocolVersion", PROTOCOL_VERSION)
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": requested,
                "capabilities": {"tools": {}},
                "serverInfo": SERVER_INFO,
            },
        }
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = msg.get("params", {})
        result = _dispatch_tool(params.get("name", ""), params.get("arguments", {}) or {})
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {}}
    if method and method.startswith("notifications/"):
        return None  # notifications get no response
    if msg_id is not None:
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }
    return None


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        response = _handle(msg)
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
