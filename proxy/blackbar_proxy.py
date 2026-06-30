#!/usr/bin/env python3
"""
blackbar_proxy.py
=================
Path 3: a local, transparent anonymizing proxy for the Anthropic Messages API.

It implements ``POST /v1/messages`` (streaming and non-streaming), sits between
Claude Code and ``api.anthropic.com``, and on every request:

  * ENCRYPTS PII in the outbound payload (system prompt + message text +
    tool_result text) into reversible ``<ENC:TYPE:...>`` tokens, so only tokens
    reach the model — plaintext PII never leaves the machine.
  * DECRYPTS those tokens back to the originals in the response (including the
    streamed SSE deltas), so the user sees real values.

Point Claude Code at it:

    export ANTHROPIC_BASE_URL=http://localhost:8787
    # use a Console API key (subscription OAuth may NOT be proxied — see docs)

This requires a **Console API key** (pay-per-token). Using a Pro/Max
subscription OAuth token through a proxy violates Anthropic's Terms and is
blocked server-side; that is why this path is API-key only.

Detection reuses the local Presidio analyzer; crypto reuses bb_crypto with the
same key/keyfile as the hooks and CLI (so tokens are interchangeable). Zero
third-party dependencies — standard library only.

Env:
  BLACKBAR_PROXY_PORT      listen port              (default 8787)
  BLACKBAR_PROXY_UPSTREAM  upstream base URL        (default https://api.anthropic.com)
  BLACKBAR_KEY / _FILE     encryption key (see bb_key)
  PRESIDIO_GUARD_LANGUAGE  detection language       (default en)
  PRESIDIO_ANALYZER_URL    analyzer service         (default http://localhost:5002)
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(
    0,
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "plugins", "blackbar", "scripts"),
)
import bb_crypto  # noqa: E402
import bb_key  # noqa: E402
from presidio_client import (  # noqa: E402
    Config,
    PresidioClient,
    PresidioUnavailable,
    _resolve_overlaps,
)

UPSTREAM = os.environ.get("BLACKBAR_PROXY_UPSTREAM", "https://api.anthropic.com").rstrip("/")
PORT = int(os.environ.get("BLACKBAR_PROXY_PORT", "8787"))

# Headers we must not forward verbatim (recomputed or hop-by-hop).
_SKIP_REQ_HEADERS = {"host", "content-length", "accept-encoding", "connection"}
_SKIP_RESP_HEADERS = {"content-length", "content-encoding", "transfer-encoding", "connection"}


# --------------------------------------------------------------------------- #
# Request: encrypt PII in the outbound Messages payload
# --------------------------------------------------------------------------- #
def _encrypt_str(text: str, key: str, client: PresidioClient) -> str:
    if not text or not text.strip():
        return text
    spans = client.analyze(text)
    if not spans:
        return text
    return bb_crypto.encrypt_spans(text, _resolve_overlaps(spans), key)


def _encrypt_content(content, key: str, client: PresidioClient):
    """A message/tool_result `content` is either a plain string or a list of
    blocks. Encrypt the user-facing text; leave images/tool schemas alone."""
    if isinstance(content, str):
        return _encrypt_str(content, key, client)
    if isinstance(content, list):
        out = []
        for block in content:
            if isinstance(block, dict):
                btype = block.get("type")
                if btype == "text" and isinstance(block.get("text"), str):
                    block = {**block, "text": _encrypt_str(block["text"], key, client)}
                elif btype == "tool_result" and "content" in block:
                    block = {**block, "content": _encrypt_content(block["content"], key, client)}
            out.append(block)
        return out
    return content


def encrypt_request_body(body: dict, key: str, client: PresidioClient) -> dict:
    """Return a copy of an Anthropic Messages request with PII encrypted in the
    system prompt and message contents."""
    out = dict(body)
    if "system" in out:
        out["system"] = _encrypt_content(out["system"], key, client)
    if isinstance(out.get("messages"), list):
        out["messages"] = [
            {**m, "content": _encrypt_content(m.get("content"), key, client)}
            if isinstance(m, dict)
            else m
            for m in out["messages"]
        ]
    return out


# --------------------------------------------------------------------------- #
# Response: decrypt tokens, with streaming-safe partial-token buffering
# --------------------------------------------------------------------------- #
class TailDecryptor:
    """Decrypts <ENC:...> tokens in a growing text stream, holding back a
    trailing fragment that might be the start of a not-yet-complete token."""

    def __init__(self, key: str) -> None:
        self.key = key
        self.buf = ""

    def _safe_cut(self) -> int:
        # A token starts with '<' and contains no '<'/'>' until its closing '>'.
        # If the last '<' has no '>' after it, it may be a partial token: hold it.
        idx = self.buf.rfind("<")
        if idx != -1 and ">" not in self.buf[idx:]:
            return idx
        return len(self.buf)

    def feed(self, text: str) -> str:
        self.buf += text
        cut = self._safe_cut()
        ready, self.buf = self.buf[:cut], self.buf[cut:]
        decrypted, _ = bb_crypto.decrypt_text(ready, self.key)
        return decrypted

    def flush(self) -> str:
        decrypted, _ = bb_crypto.decrypt_text(self.buf, self.key)
        self.buf = ""
        return decrypted


def decrypt_response_body(body: dict, key: str) -> dict:
    """Non-streaming: decrypt every text block in a Messages response."""
    out = dict(body)
    if isinstance(out.get("content"), list):
        new = []
        for block in out["content"]:
            if isinstance(block, dict) and block.get("type") == "text" and isinstance(block.get("text"), str):
                text, _ = bb_crypto.decrypt_text(block["text"], key)
                block = {**block, "text": text}
            new.append(block)
        out["content"] = new
    return out


def transform_sse_event(event_text: str, decryptors: dict, key: str) -> str:
    """Transform one SSE event (the lines between blank-line separators).

    Decrypts text in content_block_delta events; on content_block_stop, flushes
    any held partial token as a synthetic delta emitted BEFORE the stop event.
    Returns the (possibly multi-event) text to write downstream, terminated with
    the blank-line separator."""
    data = None
    for line in event_text.splitlines():
        if line.startswith("data:"):
            try:
                data = json.loads(line[5:].strip())
            except json.JSONDecodeError:
                data = None
            break
    if not isinstance(data, dict):
        return event_text + "\n"

    etype = data.get("type")
    if etype == "content_block_delta":
        delta = data.get("delta") or {}
        if delta.get("type") == "text_delta" and isinstance(delta.get("text"), str):
            idx = data.get("index", 0)
            dec = decryptors.setdefault(idx, TailDecryptor(key))
            data["delta"] = {**delta, "text": dec.feed(delta["text"])}
            return f"event: content_block_delta\ndata: {json.dumps(data)}\n\n"
    elif etype == "content_block_stop":
        idx = data.get("index", 0)
        dec = decryptors.get(idx)
        prefix = ""
        if dec is not None:
            tail = dec.flush()
            if tail:
                synth = {"type": "content_block_delta", "index": idx, "delta": {"type": "text_delta", "text": tail}}
                prefix = f"event: content_block_delta\ndata: {json.dumps(synth)}\n\n"
        return prefix + event_text + "\n"

    return event_text + "\n"


# --------------------------------------------------------------------------- #
# HTTP handler
# --------------------------------------------------------------------------- #
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "blackbar-proxy/0.1"

    def log_message(self, *args):  # quiet by default
        pass

    def _client(self) -> PresidioClient:
        cfg = Config.load()
        lang = os.environ.get("PRESIDIO_GUARD_LANGUAGE")
        if lang:
            cfg.language = lang
        return PresidioClient(cfg, source="proxy")

    def _upstream_headers(self) -> dict:
        return {
            k: v for k, v in self.headers.items() if k.lower() not in _SKIP_REQ_HEADERS
        }

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length else b""

        if self.path.rstrip("/") != "/v1/messages":
            return self._passthrough(raw)  # forward anything else untouched

        key = bb_key.resolve_key(None)
        try:
            body = json.loads(raw.decode("utf-8")) if raw else {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            body = None

        if key and isinstance(body, dict):
            try:
                body = encrypt_request_body(body, key, self._client())
                raw = json.dumps(body).encode("utf-8")
            except PresidioUnavailable as exc:
                sys.stderr.write(f"[blackbar-proxy] analyzer down, forwarding as-is: {exc}\n")

        streaming = isinstance(body, dict) and bool(body.get("stream"))
        self._forward(raw, key, streaming)

    def _open_upstream(self, raw: bytes):
        req = urllib.request.Request(
            UPSTREAM + self.path, data=raw, headers=self._upstream_headers(), method="POST"
        )
        return urllib.request.urlopen(req, timeout=600)

    def _forward(self, raw: bytes, key, streaming: bool):
        try:
            resp = self._open_upstream(raw)
        except urllib.error.HTTPError as e:
            payload = e.read()
            self.send_response(e.code)
            self._copy_resp_headers(e.headers)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        except Exception as exc:  # noqa: BLE001
            msg = json.dumps({"error": f"blackbar-proxy upstream error: {exc}"}).encode()
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)
            return

        if streaming and key:
            self._stream_decrypt(resp, key)
        elif key:
            self._whole_decrypt(resp, key)
        else:
            self._whole_passthrough(resp)

    def _stream_decrypt(self, resp, key: str):
        self.send_response(resp.status)
        self._copy_resp_headers(resp.headers)
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        decryptors: dict = {}
        event_lines: list[str] = []
        for raw_line in resp:
            line = raw_line.decode("utf-8", "replace")
            if line.strip() == "":  # event separator
                out = transform_sse_event("\n".join(event_lines), decryptors, key)
                self._write_chunk(out.encode("utf-8"))
                event_lines = []
            else:
                event_lines.append(line.rstrip("\n"))
        if event_lines:
            out = transform_sse_event("\n".join(event_lines), decryptors, key)
            self._write_chunk(out.encode("utf-8"))
        self._end_chunks()

    def _whole_decrypt(self, resp, key: str):
        data = resp.read()
        try:
            body = decrypt_response_body(json.loads(data.decode("utf-8")), key)
            data = json.dumps(body).encode("utf-8")
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass
        self.send_response(resp.status)
        self._copy_resp_headers(resp.headers)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _whole_passthrough(self, resp):
        data = resp.read()
        self.send_response(resp.status)
        self._copy_resp_headers(resp.headers)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _passthrough(self, raw: bytes):
        try:
            resp = self._open_upstream(raw)
        except urllib.error.HTTPError as e:
            data = e.read()
            self.send_response(e.code)
            self._copy_resp_headers(e.headers)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        self._whole_passthrough(resp)

    # -- response helpers (chunked transfer for streaming) ----------------- #
    def _copy_resp_headers(self, headers):
        for k, v in headers.items():
            if k.lower() not in _SKIP_RESP_HEADERS:
                self.send_header(k, v)

    def _write_chunk(self, data: bytes):
        if not data:
            return
        self.wfile.write(f"{len(data):X}\r\n".encode() + data + b"\r\n")
        self.wfile.flush()

    def _end_chunks(self):
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()


def main() -> None:
    key = bb_key.resolve_key(None)
    if not key:
        sys.stderr.write(
            "[blackbar-proxy] WARNING: no key (BLACKBAR_KEY / `blackbar keygen`); "
            "running as a plain pass-through with no encryption.\n"
        )
    sys.stderr.write(
        f"[blackbar-proxy] listening on http://localhost:{PORT} -> {UPSTREAM}\n"
        f"[blackbar-proxy] point Claude Code at it: export ANTHROPIC_BASE_URL=http://localhost:{PORT}\n"
    )
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
