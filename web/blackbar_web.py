#!/usr/bin/env python3
"""
blackbar_web.py
===============
A local, single-file "PII firewall" web app for the manual copy/paste workflow
with Claude Desktop (or any chat model). You paste a prompt, it anonymizes the
PII into reversible ``<ENC:TYPE:...>`` tokens, you copy that into Claude, and
when you paste Claude's reply back it restores the original values.

Design goals (matching the rest of blackbar):
  * ZERO third-party Python dependencies — standard library only. Detection is
    delegated to the Presidio analyzer service; crypto reuses ``bb_crypto`` with
    the same key/keyfile as the CLI, hooks, proxy and Claude Desktop, so tokens
    are interchangeable everywhere.
  * Binds ``127.0.0.1`` only. Plaintext PII never touches disk and never gets
    logged. The encryption key never leaves this process — the browser only ever
    sees a non-reversible fingerprint.
  * Decryption is self-contained (text + key), so the paste-back half keeps
    working even when the analyzer is down.

Run it:

    python3 web/blackbar_web.py          # opens http://127.0.0.1:8765
    python3 web/blackbar_web.py --no-open --port 9000

Env:
  BLACKBAR_WEB_PORT        listen port                (default 8765)
  BLACKBAR_WEB_MAX_BODY    max JSON body bytes        (default 8 MiB)
  BLACKBAR_WEB_MAX_UPLOAD  max document upload bytes   (default 25 MiB)
  BLACKBAR_KEY / _FILE     encryption key             (see bb_key)
  PRESIDIO_ANALYZER_URL    analyzer service            (default http://localhost:5002)
  PRESIDIO_GUARD_LANGUAGE  default detection language  (default en; "auto" also ok)
  BLACKBAR_AUDIT_ENABLED   enable the PII-safe audit trail (see pii_audit)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import stat
import sys
import time
import urllib.error
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPTS_DIR = os.path.join(HERE, "..", "plugins", "blackbar", "scripts")
sys.path.insert(0, SCRIPTS_DIR)
sys.path.insert(0, HERE)  # so `extract` and `langdetect` resolve from web/

import bb_crypto  # noqa: E402
import bb_key  # noqa: E402
import pii_audit  # noqa: E402
from presidio_client import (  # noqa: E402
    Config,
    PresidioClient,
    PresidioUnavailable,
    Span,
    _replacement,
    _resolve_overlaps,
)

import extract  # noqa: E402  (web/extract.py)
import langdetect  # noqa: E402  (web/langdetect.py)

VERSION = "0.5.1"
STATIC_DIR = os.path.join(HERE, "static")
DEFAULT_PORT = int(os.environ.get("BLACKBAR_WEB_PORT", "8765"))
MAX_BODY = int(os.environ.get("BLACKBAR_WEB_MAX_BODY", str(8 * 1024 * 1024)))
MAX_UPLOAD = int(os.environ.get("BLACKBAR_WEB_MAX_UPLOAD", str(25 * 1024 * 1024)))
DEFAULT_LANGS = ["en", "es", "fr", "de", "it", "pt"]

# Per-launch CSRF token. Injected into index.html and required on every /api/*
# call as X-Blackbar-Token. A malicious local page cannot read it (same-origin)
# nor set the custom header cross-origin without a preflight we refuse.
CSRF_TOKEN = secrets.token_urlsafe(24)

# Domain-separated, non-reversible key fingerprint. Stable across launches (no
# random salt) so the UI can tell "same key" from "key changed mid-conversation"
# without ever seeing the key bytes.
_FP_PREFIX = "blackbar-web-fp:v1:"


def _key_fingerprint(key: str | None) -> str | None:
    if not key:
        return None
    return hashlib.sha256((_FP_PREFIX + key).encode("utf-8")).hexdigest()[:8]


def _pdf_available() -> bool:
    import importlib.util

    return importlib.util.find_spec("pypdf") is not None


# --------------------------------------------------------------------------- #
# Entity catalog (families drive the UI colour palette + allow-list toggles).
# Mirrors the coverage of presidio-native/analyzer_service.py — keep in sync.
# --------------------------------------------------------------------------- #
ENTITY_CATALOG = [
    # family: identity
    ("PERSON", "identity", "Person"),
    ("NRP", "identity", "Nationality / religion / group"),
    ("LOCATION", "identity", "Location"),
    ("ORGANIZATION", "identity", "Organization"),
    # family: contact
    ("EMAIL_ADDRESS", "contact", "Email"),
    ("PHONE_NUMBER", "contact", "Phone"),
    ("URL", "contact", "URL"),
    ("IP_ADDRESS", "contact", "IP address"),
    # family: gov_id
    ("ES_NIF", "gov_id", "Spanish NIF"),
    ("ES_NIE", "gov_id", "Spanish NIE"),
    ("ES_SSN", "gov_id", "Spanish social security"),
    ("US_SSN", "gov_id", "US SSN"),
    ("US_PASSPORT", "gov_id", "US passport"),
    ("US_DRIVER_LICENSE", "gov_id", "US driver license"),
    ("UK_NHS", "gov_id", "UK NHS number"),
    ("PT_NIF", "gov_id", "Portuguese NIF"),
    ("DE_STEUER_ID", "gov_id", "German tax ID"),
    ("FR_NIR_SSN", "gov_id", "French NIR / SSN"),
    ("EU_VAT", "gov_id", "EU VAT number"),
    ("PASSPORT_GENERIC", "gov_id", "Passport"),
    # family: financial
    ("CREDIT_CARD", "financial", "Credit card"),
    ("IBAN_CODE", "financial", "IBAN"),
    ("SWIFT_BIC", "financial", "SWIFT / BIC"),
    ("CRYPTO", "financial", "Crypto wallet"),
    # family: health
    ("MEDICAL_LICENSE", "health", "Medical license"),
    ("HEALTH_RECORD", "health", "Health record number"),
    ("ICD10_CODE", "health", "Diagnosis code (ICD-10)"),
    ("HEALTH_CONDITION", "health", "Health condition"),
    # family: special (GDPR Art. 9)
    ("RELIGIOUS_BELIEF", "special", "Religious belief"),
    ("POLITICAL_OPINION", "special", "Political opinion"),
    ("ETHNIC_ORIGIN", "special", "Ethnic origin"),
    ("SEXUAL_ORIENTATION", "special", "Sexual orientation"),
    ("TRADE_UNION", "special", "Trade union"),
    # family: temporal
    ("DATE_TIME", "temporal", "Date / time"),
]


def _entities_payload() -> list[dict]:
    return [{"type": t, "family": fam, "label": lbl} for (t, fam, lbl) in ENTITY_CATALOG]


# --------------------------------------------------------------------------- #
# Analyzer helpers
# --------------------------------------------------------------------------- #
def _analyzer_health(cfg: Config) -> dict:
    url = cfg.analyzer_url.rstrip("/") + "/health"
    start = time.monotonic()
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        latency = int((time.monotonic() - start) * 1000)
        return {
            "reachable": True,
            "url": cfg.analyzer_url,
            "languages": data.get("languages", DEFAULT_LANGS),
            "recognizers": data.get("recognizers"),
            "latency_ms": latency,
        }
    except Exception as exc:  # noqa: BLE001
        return {"reachable": False, "url": cfg.analyzer_url, "error": str(exc)}


def _supported_languages(cfg: Config) -> list[str]:
    h = _analyzer_health(cfg)
    langs = h.get("languages") or DEFAULT_LANGS
    return [l for l in langs if l]


# --------------------------------------------------------------------------- #
# Anonymize composer (reuses make_token / _replacement; one code path for the
# simple "one operator for everything" case and per-entity overrides).
# --------------------------------------------------------------------------- #
class NoKeyError(Exception):
    pass


def anonymize_text(text, spans, default_op, per_entity, key):
    """Return (out_text, entities_found, count, used_encrypt).

    ``per_entity`` maps entity_type -> operator and overrides ``default_op``.
    Encrypt spans share one salt (same contract as bb_crypto.encrypt_spans).
    """
    resolved = _resolve_overlaps(spans)  # sorted by start desc: right-to-left safe
    salt = bb_crypto.new_salt()
    out = text
    used_encrypt = False
    for s in resolved:
        op = (per_entity or {}).get(s.entity_type, default_op)
        original = out[s.start : s.end]
        if op == "encrypt":
            if not key:
                raise NoKeyError()
            repl = bb_crypto.make_token(s.entity_type, original, key, salt)
            used_encrypt = True
        else:
            repl = _replacement(original, s.entity_type, op)
        out = out[: s.start] + repl + out[s.end :]
    found = sorted({s.entity_type for s in resolved})
    return out, found, len(resolved), used_encrypt


# --------------------------------------------------------------------------- #
# Decrypt with integrity diagnostics
# --------------------------------------------------------------------------- #
_MARKER = "<ENC:"
_MIN_PAYLOAD_BYTES = 1 + bb_crypto.SALT_LEN + bb_crypto.NONCE_LEN + bb_crypto.TAG_LEN


def _classify_candidate(candidate: str, has_close: bool):
    """Return (entity_type, reason) for a malformed <ENC:...> fragment."""
    inner = candidate[len(_MARKER):]
    if has_close and inner.endswith(">"):
        inner = inner[:-1]
    etype = ""
    payload = inner
    if ":" in inner:
        etype, payload = inner.split(":", 1)
    if not has_close:
        return etype, "no-closing-bracket"
    if any(c.isspace() for c in inner):
        return etype, "interior-whitespace"
    # charset check on payload (base64url alphabet)
    if not payload or any(not (c.isalnum() or c in "_-") for c in payload):
        return etype, "bad-charset"
    try:
        raw = bb_crypto._b64decode(payload)
        if len(raw) < _MIN_PAYLOAD_BYTES:
            return etype, "truncated-payload"
    except Exception:  # noqa: BLE001
        return etype, "bad-charset"
    return etype, "auth-failed"


def _loose_scan(text: str):
    """Find <ENC:...>-shaped fragments the strict TOKEN_RE rejects."""
    out = []
    i = 0
    n = len(text)
    cap = 4096
    while True:
        j = text.find(_MARKER, i)
        if j == -1:
            break
        k = j + len(_MARKER)
        end = None
        limit = min(n, j + cap)
        while k < limit:
            c = text[k]
            if c == ">":
                end = k
                break
            if c == "<":
                break
            k += 1
        has_close = end is not None
        candidate = text[j : (end + 1) if has_close else k]
        m = bb_crypto.TOKEN_RE.fullmatch(candidate) if has_close else None
        if m:
            i = end + 1
            continue  # strict token, counted elsewhere
        etype, reason = _classify_candidate(candidate, has_close)
        out.append({"token": candidate, "entity_type": etype, "reason": reason})
        i = (end + 1) if has_close else max(k, j + 1)
    return out


def decrypt_with_integrity(text: str, key: str) -> dict:
    found_strict = len(bb_crypto.TOKEN_RE.findall(text))
    restored_text, restored = bb_crypto.decrypt_text(text, key)
    malformed = _loose_scan(text)

    # Auto-repair interior-whitespace (reflow / line-wrap by the model): the
    # base64url alphabet never contains whitespace, so stripping it is safe.
    repaired = 0
    remaining = []
    for frag in malformed:
        if frag["reason"] == "interior-whitespace":
            stripped = "".join(frag["token"].split())
            m = bb_crypto.TOKEN_RE.fullmatch(stripped)
            if m:
                try:
                    value = bb_crypto.decrypt_value(m.group(2), key)
                    restored_text = restored_text.replace(frag["token"], value, 1)
                    repaired += 1
                    continue
                except Exception:  # noqa: BLE001
                    pass
        remaining.append(frag)

    auth_failed = max(0, found_strict - restored)
    tokens_seen = found_strict + len(malformed)
    restored_total = restored + repaired
    wrong_key_suspected = restored == 0 and found_strict > 0
    integrity = {
        "found_strict": found_strict,
        "restored": restored,
        "repaired": repaired,
        "auth_failed": auth_failed,
        "malformed": remaining,
        "wrong_key_suspected": wrong_key_suspected,
    }
    return {
        "text": restored_text,
        "restored": restored_total,
        "tokens_seen": tokens_seen,
        "integrity": integrity,
    }


# --------------------------------------------------------------------------- #
# HTTP handler
# --------------------------------------------------------------------------- #
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = f"blackbar-web/{VERSION}"

    # never log request lines (they could echo pasted PII in query strings)
    def log_message(self, *args):  # noqa: D401
        pass

    # -- security gates ---------------------------------------------------- #
    def _allowed_hosts(self) -> set[str]:
        p = self.server.server_address[1]
        return {f"127.0.0.1:{p}", f"localhost:{p}", "127.0.0.1", "localhost"}

    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").strip().lower()
        return host in self._allowed_hosts()

    def _origin_ok(self) -> bool:
        p = self.server.server_address[1]
        allowed = {f"http://127.0.0.1:{p}", f"http://localhost:{p}"}
        origin = self.headers.get("Origin")
        if origin:
            return origin.rstrip("/") in allowed
        ref = self.headers.get("Referer")
        if ref:
            try:
                u = urlparse(ref)
                return f"{u.scheme}://{u.netloc}" in allowed
            except Exception:  # noqa: BLE001
                return False
        # No Origin/Referer (e.g. a local CLI/curl). The CSRF token is the guard.
        return True

    def _csrf_ok(self) -> bool:
        return secrets.compare_digest(self.headers.get("X-Blackbar-Token", ""), CSRF_TOKEN)

    def _api_guard(self, *, state_changing: bool) -> bool:
        if not self._host_ok():
            self._error(403, "bad_host", "Host not allowed (localhost only).")
            return False
        if not self._csrf_ok():
            self._error(403, "bad_token", "Missing or invalid X-Blackbar-Token.")
            return False
        if state_changing and not self._origin_ok():
            self._error(403, "bad_origin", "Cross-origin request refused.")
            return False
        return True

    # -- response helpers -------------------------------------------------- #
    def _security_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self'; "
            "script-src 'self'; connect-src 'self'; base-uri 'none'; "
            "form-action 'none'; frame-ancestors 'none'",
        )

    def _send_bytes(self, body: bytes, content_type: str, status: int = 200, *, no_store: bool = False):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if no_store:
            self.send_header("Cache-Control", "no-store")
        self._security_headers()
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, obj, status: int = 200):
        body = json.dumps(obj).encode("utf-8")
        self._send_bytes(body, "application/json; charset=utf-8", status, no_store=True)

    def _error(self, status: int, code: str, message: str, extra: dict | None = None):
        payload = {"error": code, "detail": message}
        if extra:
            payload.update(extra)
        self._json(payload, status)

    def _read_body(self, cap: int) -> bytes | None:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length > cap:
            self.close_connection = True
            self._error(413, "too_large", f"Body exceeds {cap} bytes.")
            return None
        return self.rfile.read(length) if length else b""

    def _read_json(self, cap: int = MAX_BODY):
        raw = self._read_body(cap)
        if raw is None:
            return None
        try:
            return json.loads(raw.decode("utf-8")) if raw else {}
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._error(400, "bad_json", "Request body is not valid JSON.")
            return None

    def _client(self, language: str | None) -> tuple[PresidioClient, str]:
        cfg = Config.load()
        used = cfg.language
        if language and language != "auto":
            cfg.language = language
            used = language
        return PresidioClient(cfg, source="web"), used

    # -- routing ----------------------------------------------------------- #
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            return self._serve_index()
        if path == "/app.js":
            return self._serve_static("app.js", "application/javascript; charset=utf-8")
        if path == "/styles.css":
            return self._serve_static("styles.css", "text/css; charset=utf-8")
        if path == "/myrmion-logo.png":
            return self._serve_static("myrmion-logo.png", "image/png")
        if path == "/favicon.ico":
            return self._serve_static("myrmion-logo.png", "image/png")
        if path.startswith("/api/"):
            if not self._api_guard(state_changing=False):
                return
            return self._route_get_api(path)
        return self._error(404, "not_found", "Not found.")

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        path = urlparse(self.path).path
        if not path.startswith("/api/"):
            return self._error(404, "not_found", "Not found.")
        if not self._api_guard(state_changing=True):
            return
        return self._route_post_api(path)

    # -- static ------------------------------------------------------------ #
    def _serve_index(self):
        try:
            with open(os.path.join(STATIC_DIR, "index.html"), "r", encoding="utf-8") as f:
                html = f.read()
        except OSError:
            return self._error(500, "no_index", "index.html missing.")
        html = html.replace("__CSRF_TOKEN__", CSRF_TOKEN)
        self._send_bytes(html.encode("utf-8"), "text/html; charset=utf-8")

    def _serve_static(self, name: str, content_type: str):
        try:
            with open(os.path.join(STATIC_DIR, name), "rb") as f:
                body = f.read()
        except OSError:
            return self._error(404, "not_found", f"{name} missing.")
        self._send_bytes(body, content_type)

    # -- GET api ----------------------------------------------------------- #
    def _route_get_api(self, path: str):
        if path == "/api/health":
            return self._api_health()
        if path == "/api/analyzer/health":
            return self._json(_analyzer_health(Config.load()))
        if path == "/api/entities":
            return self._json({"entities": _entities_payload()})
        if path == "/api/key":
            return self._json(self._key_status())
        if path == "/api/audit/stats":
            return self._json(self._audit_stats())
        if path == "/api/audit/records":
            return self._api_audit_records()
        return self._error(404, "not_found", "Unknown endpoint.")

    def _api_health(self):
        cfg = Config.load()
        key = bb_key.resolve_key(None)
        self._json(
            {
                "version": VERSION,
                "analyzer": _analyzer_health(cfg),
                "key": self._key_status(),
                "config": {
                    "mode": cfg.mode,
                    "language": cfg.language,
                    "default_operator": "encrypt",
                    "threshold": cfg.threshold,
                    "entities": list(cfg.entities),
                    "pdf_available": _pdf_available(),
                    "supported_formats": extract.SUPPORTED_EXTENSIONS,
                },
                "audit": {
                    "enabled": pii_audit.enabled(),
                    "retention_days": pii_audit.retention_days(),
                },
            }
        )

    def _key_status(self) -> dict:
        key = bb_key.resolve_key(None)
        source = None
        if key:
            if os.environ.get("BLACKBAR_KEY"):
                source = "environment"
            else:
                source = "keyfile"
        return {
            "present": bool(key),
            "source": source,
            "path": str(bb_key.default_key_file()),
            "fingerprint": _key_fingerprint(key),
        }

    def _audit_stats(self) -> dict:
        s = pii_audit.stats()
        s["enabled"] = pii_audit.enabled()
        s["retention_days"] = pii_audit.retention_days()
        return s

    def _api_audit_records(self):
        if not pii_audit.enabled():
            return self._json({"enabled": False, "records": []})
        qs = parse_qs(urlparse(self.path).query)
        day = (qs.get("day") or [None])[0]
        limit = int((qs.get("limit") or ["200"])[0])
        directory = pii_audit.audit_dir()
        records = []
        if day and os.path.isdir(directory):
            fname = f"pii-audit-{day}.jsonl"
            fpath = os.path.join(directory, fname)
            # guard against traversal: only the exact day-file name
            if os.path.basename(fpath) == fname and os.path.isfile(fpath):
                try:
                    with open(fpath, "r", encoding="utf-8") as f:
                        for line in f:
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                records.append(json.loads(line))
                            except json.JSONDecodeError:
                                continue
                            if len(records) >= limit:
                                break
                except OSError:
                    pass
        self._json({"enabled": True, "day": day, "records": records})

    # -- POST api ---------------------------------------------------------- #
    def _route_post_api(self, path: str):
        if path == "/api/scan":
            return self._api_scan()
        if path == "/api/anonymize":
            return self._api_anonymize()
        if path == "/api/decrypt":
            return self._api_decrypt()
        if path == "/api/extract":
            return self._api_extract()
        if path == "/api/key/generate":
            return self._api_key_generate(rotate=False)
        if path == "/api/key/rotate":
            return self._api_key_generate(rotate=True)
        if path == "/api/audit/prune":
            return self._json({"removed": pii_audit.prune()})
        if path == "/api/audit/purge":
            body = self._read_json()
            if body is None:
                return
            if not body.get("confirm"):
                return self._error(400, "confirm_required", "Set confirm:true to purge.")
            return self._json({"removed": pii_audit.purge()})
        return self._error(404, "not_found", "Unknown endpoint.")

    def _api_scan(self):
        body = self._read_json()
        if body is None:
            return
        text = body.get("text") or ""
        language, used = self._resolve_language(body.get("language"), text)
        threshold = body.get("threshold")
        client, _ = self._client(language)
        if threshold is not None:
            try:
                client.cfg.threshold = float(threshold)
            except (TypeError, ValueError):
                pass
        ents = body.get("entities")
        if ents:
            client.cfg.entities = tuple(ents)
        try:
            # An explicit empty list means "detect nothing" (the UI's type combo
            # with everything unchecked); otherwise analyze normally.
            spans = [] if ents == [] else client.analyze(text)
        except PresidioUnavailable as exc:
            return self._analyzer_down(exc)
        return self._json(
            {
                "count": len(spans),
                "language_used": used,
                "entities": [
                    {"entity_type": s.entity_type, "start": s.start, "end": s.end, "score": round(s.score, 3)}
                    for s in spans
                ],
            }
        )

    def _api_anonymize(self):
        body = self._read_json()
        if body is None:
            return
        text = body.get("text") or ""
        operator = body.get("operator") or "encrypt"
        per_entity = body.get("per_entity") or {}
        language, used = self._resolve_language(body.get("language"), text)
        threshold = body.get("threshold")
        needs_encrypt = operator == "encrypt" or "encrypt" in per_entity.values()
        key = bb_key.resolve_key(None) if needs_encrypt else None
        if needs_encrypt and not key:
            return self._error(400, "no_key", "operator=encrypt requires a key.", {"hint": "Generate a key first."})
        client, _ = self._client(language)
        if threshold is not None:
            try:
                client.cfg.threshold = float(threshold)
            except (TypeError, ValueError):
                pass
        ents = body.get("entities")
        if ents:
            client.cfg.entities = tuple(ents)
        try:
            # An explicit empty list means "detect nothing" (the UI's type combo
            # with everything unchecked); otherwise analyze normally.
            spans = [] if ents == [] else client.analyze(text)
        except PresidioUnavailable as exc:
            return self._analyzer_down(exc)
        # Per-occurrence exclusions (user un-checked a specific highlight) and
        # manual "mark as" additions. Offsets come from the client's /api/scan of
        # the SAME text, and Presidio detection is deterministic, so they align.
        exclude = {(int(a), int(b)) for a, b in (body.get("exclude_spans") or [])}
        if exclude:
            spans = [s for s in spans if (s.start, s.end) not in exclude]
        for item in body.get("include_spans") or []:
            try:
                a, b, etype = int(item[0]), int(item[1]), str(item[2])
                if 0 <= a < b <= len(text):
                    spans.append(Span(etype, a, b, 1.0))
            except (ValueError, IndexError, TypeError):
                continue
        try:
            out, found, count, used_encrypt = anonymize_text(text, spans, operator, per_entity, key)
        except NoKeyError:
            return self._error(400, "no_key", "operator=encrypt requires a key.", {"hint": "Generate a key first."})
        pii_audit.record_op(source="web:anonymize", operator=operator, n_transformed=count, ok=True)
        return self._json(
            {
                "text": out,
                "operator": operator,
                "reversible": used_encrypt,
                "count": count,
                "entities_found": found,
                "language_used": used,
            }
        )

    def _api_decrypt(self):
        body = self._read_json()
        if body is None:
            return
        text = body.get("text") or ""
        key = body.get("key") or bb_key.resolve_key(None)
        if not key:
            return self._error(400, "no_key", "Decrypt requires a key.", {"hint": "Generate or set a key."})
        result = decrypt_with_integrity(text, key)
        pii_audit.record_op(source="web:decrypt", operator="decrypt", n_transformed=result["restored"], ok=True)
        return self._json(result)

    def _api_extract(self):
        raw = self._read_body(MAX_UPLOAD)
        if raw is None:
            return
        filename = self.headers.get("X-Blackbar-Filename") or "upload"
        try:
            result = extract.extract_document(filename, raw)
        except extract.PdfSupportMissing:
            return self._error(
                400, "pdf_optional", "PDF support is not installed.",
                {"hint": "pip install -r web/requirements-docs.txt"},
            )
        except extract.ExtractError as exc:
            return self._error(422, "extract_failed", str(exc))
        return self._json(result)

    def _api_key_generate(self, *, rotate: bool):
        body = self._read_json()
        if body is None:
            return
        force = bool(body.get("force")) or rotate
        kf = bb_key.default_key_file()
        existed = kf.exists()
        if existed and not force:
            return self._error(409, "key_exists", "A key already exists.", {"path": str(kf)})
        try:
            kf.parent.mkdir(parents=True, exist_ok=True)
            new_key = secrets.token_urlsafe(32)
            kf.write_text(new_key + "\n", encoding="utf-8")
            kf.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600
        except OSError as exc:
            return self._error(500, "key_write_failed", str(exc))
        payload = {
            "created": True,
            "rotated": existed and force,
            "path": str(kf),
            "fingerprint": _key_fingerprint(new_key),
        }
        if existed and force:
            payload["warning"] = (
                "Key rotated. Text encrypted with the previous key can no longer "
                "be decrypted — restore the old keyfile if you still need it."
            )
        return self._json(payload)

    # -- shared ------------------------------------------------------------ #
    def _resolve_language(self, requested, text) -> tuple[str, str]:
        cfg = Config.load()
        if requested and requested != "auto":
            return requested, requested
        # auto (explicit "auto", or unset with default "auto")
        if requested == "auto" or cfg.language == "auto":
            langs = _supported_languages(cfg)
            default = langs[0] if langs else "en"
            guessed, _conf = langdetect.guess(text, tuple(langs), default=default)
            return guessed, guessed
        return cfg.language, cfg.language

    def _analyzer_down(self, exc):
        self._error(
            503,
            "analyzer_unavailable",
            str(exc),
            {"hint": "Start it: plugins/blackbar/presidio-native/run.sh (or docker compose in plugins/blackbar)."},
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="blackbar-web", description="Local PII firewall web app")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"listen port (default {DEFAULT_PORT})")
    parser.add_argument("--no-open", action="store_true", help="do not open the browser")
    args = parser.parse_args(argv)

    url = f"http://127.0.0.1:{args.port}"
    try:
        httpd = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    except OSError as exc:
        sys.stderr.write(f"[blackbar-web] cannot bind {url}: {exc}\n")
        return 1

    key = bb_key.resolve_key(None)
    if not key:
        sys.stderr.write(
            "[blackbar-web] no key yet (BLACKBAR_KEY / `blackbar keygen`); "
            "generate one in the app to enable encrypt/decrypt.\n"
        )
    sys.stderr.write(f"[blackbar-web] listening on {url}  (localhost only)\n")
    if not args.no_open:
        try:
            webbrowser.open(url)
        except Exception:  # noqa: BLE001
            pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\n[blackbar-web] stopped\n")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
