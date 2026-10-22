#!/usr/bin/env python3
"""
test_security.py
================
Self-contained checks for blackbar's security defaults. No Presidio service or
spaCy model needed: the analyzer is pointed at a closed port when an outage is
the case under test, and every other check drives the code directly.

    python3 test_security.py     # prints each check; exit 0 on success

Covers: the key never travels as a tool argument (MCP + Desktop) nor in a tool
result, fail-closed by default on any error (hooks + proxy), no decryption into
Bash, salted one-way hashes with a robust salt file, plaintext warnings on
scan/decrypt, the legacy image's bind and user, no stale .mcpb in the tree.

A tiny fake analyzer stands in for Presidio where a reply is the case under
test (spans for "ada@example.com", an empty list, or an HTML error page).
"""

from __future__ import annotations

import glob
import hashlib
import importlib.util
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, HERE)

DEAD_ANALYZER = "http://127.0.0.1:9"  # nothing listens on the discard port
FAILED: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f" -- {detail}"))
    if not ok:
        FAILED.append(name)


def _isolated_env(**extra: str) -> dict:
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("PRESIDIO_", "BLACKBAR_", "PII_AUDIT_"))
           and k.lower() not in ("http_proxy", "https_proxy", "all_proxy")}
    env["NO_PROXY"] = "127.0.0.1,localhost"
    env["XDG_CONFIG_HOME"] = tempfile.mkdtemp(prefix="bb-sec-cfg-")
    env["PRESIDIO_ANALYZER_URL"] = DEAD_ANALYZER
    env["PRESIDIO_GUARD_MODE"] = "service"
    env["PRESIDIO_GUARD_TIMEOUT"] = "1"
    env.update(extra)
    return env


def _hook(event: str, payload: dict, **env: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, os.path.join(HERE, "pii_filter.py"), event],
        input=json.dumps(payload), capture_output=True, text=True,
        env=_isolated_env(**env), timeout=30,
    )


def _use_env(**values: str) -> None:
    for k in [k for k in os.environ if k.startswith(("PRESIDIO_", "BLACKBAR_", "PII_AUDIT_"))]:
        del os.environ[k]
    os.environ["XDG_CONFIG_HOME"] = tempfile.mkdtemp(prefix="bb-sec-cfg-")
    os.environ.update(values)


def _unwritable_config() -> str:
    """A config dir that cannot be created, even as root: its parent is a file."""
    f = tempfile.NamedTemporaryFile(prefix="bb-sec-file-", delete=False)
    f.close()
    return os.path.join(f.name, "x")


class _Analyzer(BaseHTTPRequestHandler):
    mode = "spans"  # spans | empty | html

    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("Content-Length", "0") or "0")
        req = json.loads(self.rfile.read(n) or b"{}")
        if self.mode == "html":
            body, ctype = b"<html>upstream error</html>", "text/html"
        else:
            text, spans = req.get("text", ""), []
            i = text.find("ada@example.com") if self.mode == "spans" else -1
            while i != -1:
                spans.append({"entity_type": "EMAIL_ADDRESS", "start": i, "end": i + 15, "score": 1.0})
                i = text.find("ada@example.com", i + 1)
            body, ctype = json.dumps(spans).encode(), "application/json"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _analyzer(mode: str) -> str:
    srv = _serve(type(f"_Analyzer_{mode}", (_Analyzer,), {"mode": mode}))
    return f"http://127.0.0.1:{srv.server_port}"


def _node(script: str, *args: str, **env: str) -> dict | None:
    res = subprocess.run(
        ["node", "-e", script, os.path.join(ROOT, "desktop", "server", "index.js"), *args],
        capture_output=True, text=True, env=_isolated_env(**env), timeout=30,
    )
    try:
        return json.loads(res.stdout)
    except json.JSONDecodeError:
        check("desktop server: loads", False, res.stderr.strip()[-300:])
        return None


# --------------------------------------------------------------------------- #
def test_hash_is_salted() -> None:
    import presidio_client

    _use_env(BLACKBAR_SALT="salt-a")
    a = presidio_client._replacement("12345678Z", "ES_NIF", "hash")
    a2 = presidio_client._replacement("12345678Z", "ES_NIF", "hash")
    _use_env(BLACKBAR_SALT="salt-b")
    b = presidio_client._replacement("12345678Z", "ES_NIF", "hash")
    plain = hashlib.sha256(b"12345678Z").hexdigest()[:10]
    check("hash: not a plain SHA-256 of the value", plain not in a, a)
    check("hash: stable for one salt", a == a2, f"{a} != {a2}")
    check("hash: changes with the salt", a != b, a)


def test_salt_file() -> None:
    import bb_key

    _use_env()
    s1 = bb_key.local_salt()
    path = os.path.join(os.environ["XDG_CONFIG_HOME"], "blackbar", "salt")
    mode = stat.S_IMODE(os.stat(path).st_mode) if os.path.exists(path) else None
    check("salt: generated on first use", os.path.exists(path), path)
    check("salt: file is 0600", mode == 0o600, oct(mode or 0))
    check("salt: stable across calls", bb_key.local_salt() == s1)


def test_audit_fingerprint_salt() -> None:
    import pii_audit

    _use_env()
    weak = hashlib.sha256(b"blackbar-change-this-salt" + b"ada@example.com").hexdigest()[:16]
    check("audit: no shared default salt", pii_audit.fingerprint("ada@example.com") != weak)


def test_fail_closed_defaults() -> None:
    r = _hook("PostToolUse", {"tool_name": "Read", "tool_response": "contact ada@example.com"})
    out = r.stdout
    check("hook PostToolUse: result withheld when analyzer is down",
          "updatedToolOutput" in out and "ada@example.com" not in out, out or r.stderr)
    r = _hook("UserPromptSubmit", {"prompt": "my DNI is 12345678Z"})
    check("hook UserPromptSubmit: blocks (exit 2) when analyzer is down",
          r.returncode == 2, f"exit {r.returncode}")
    r = _hook("UserPromptSubmit", {"prompt": "my DNI is 12345678Z"}, PRESIDIO_GUARD_FAIL="open")
    check("hook: PRESIDIO_GUARD_FAIL=open still lets work continue",
          r.returncode == 0 and "inactive" in r.stdout, f"exit {r.returncode} {r.stdout}")


def test_no_decrypt_into_bash() -> None:
    import bb_crypto
    from presidio_client import Span

    key = "test-key-0123456789"
    token = bb_crypto.encrypt_spans("ada@example.com", [Span("EMAIL_ADDRESS", 0, 15, 1.0)], key)
    env = {"BLACKBAR_KEY": key, "PRESIDIO_GUARD_INPUT_DECRYPT": "on"}
    r = _hook("PreToolUse", {"tool_name": "Bash", "tool_input": {"command": f"curl -d {token} x"}}, **env)
    check("hook PreToolUse: never decrypts into Bash", "updatedInput" not in r.stdout, r.stdout)
    r = _hook("PreToolUse", {"tool_name": "Write", "tool_input": {"content": token}}, **env)
    check("hook PreToolUse: still decrypts into Write", "ada@example.com" in r.stdout, r.stdout or r.stderr)
    hooks = json.load(open(os.path.join(HERE, "..", "hooks", "hooks.json"), encoding="utf-8"))
    matchers = [m.get("matcher", "") for m in hooks["hooks"]["PreToolUse"]]
    check("hooks.json: Bash not in the decrypt matcher",
          not any("Bash" in m.split("|") for m in matchers if "Write" in m), str(matchers))


def test_mcp_key_not_an_argument() -> None:
    import bb_crypto
    import mcp_server
    from presidio_client import Span

    props = [p for t in mcp_server.TOOLS for p in t["inputSchema"]["properties"]]
    check("mcp: no tool takes a key argument", "key" not in props, str(props))
    key = "test-key-0123456789"
    _use_env(BLACKBAR_KEY=key)
    token = bb_crypto.encrypt_spans("ada@example.com", [Span("EMAIL_ADDRESS", 0, 15, 1.0)], key)
    out = json.loads(mcp_server.tool_decrypt({"text": token}))
    check("mcp: decrypt uses the local key", out.get("text") == "ada@example.com", str(out))
    _use_env()
    out = json.loads(mcp_server.tool_decrypt({"text": token}))
    check("mcp: no local key -> error naming keygen", "keygen" in out.get("error", ""), str(out))
    desc = {t["name"]: t["description"] for t in mcp_server.TOOLS}
    check("mcp: analyze/decrypt warn about plaintext",
          all("plaintext" in desc[n] for n in ("presidio_analyze", "presidio_decrypt")), str(desc))


def test_desktop() -> None:
    manifest = json.load(open(os.path.join(ROOT, "desktop", "manifest.json"), encoding="utf-8"))
    uc = manifest.get("user_config", {}).get("encryption_key", {})
    env = manifest["server"]["mcp_config"]["env"]
    check("desktop manifest: sensitive encryption_key",
          uc.get("sensitive") is True and env.get("BLACKBAR_KEY") == "${user_config.encryption_key}",
          json.dumps(uc))
    import bb_crypto
    from presidio_client import Span

    key = "test-key-0123456789"
    token = bb_crypto.encrypt_spans("ada@example.com", [Span("EMAIL_ADDRESS", 0, 15, 1.0)], key)
    script = (
        "const s=require(process.argv[1]);"
        "const r={};"
        "r.props=s.TOOLS.flatMap(t=>Object.keys(t.inputSchema.properties));"
        "r.dec=JSON.parse(s.toolDecrypt({text:process.argv[2]})).text;"
        "r.h1=s.replacement('12345678Z','ES_NIF','hash');"
        "console.log(JSON.stringify(r));"
    )
    res = subprocess.run(
        ["node", "-e", script, os.path.join(ROOT, "desktop", "server", "index.js"), token],
        capture_output=True, text=True, env=_isolated_env(BLACKBAR_KEY=key, BLACKBAR_SALT="salt-a"),
        timeout=30,
    )
    try:
        r = json.loads(res.stdout)
    except json.JSONDecodeError:
        check("desktop server: loads", False, res.stderr.strip()[-300:])
        return
    check("desktop server: no tool takes a key argument", "key" not in r["props"], str(r["props"]))
    check("desktop server: decrypt uses BLACKBAR_KEY", r["dec"] == "ada@example.com", str(r["dec"]))
    import presidio_client

    _use_env(BLACKBAR_SALT="salt-a")
    check("desktop server: hash salted, same as Python",
          r["h1"] == presidio_client._replacement("12345678Z", "ES_NIF", "hash"), r["h1"])


class _Upstream(BaseHTTPRequestHandler):
    calls = 0

    def do_POST(self):  # noqa: N802
        _Upstream.calls += 1
        body = b'{"content": []}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _serve(handler) -> ThreadingHTTPServer:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_proxy_fail_closed() -> None:
    # Config reads its env at import, so the proxy runs in a fresh child process.
    r = subprocess.run([sys.executable, os.path.abspath(__file__), "--proxy-child"],
                       capture_output=True, text=True, env=_isolated_env(), timeout=90)
    lines = [ln for ln in r.stdout.splitlines() if ln.startswith(("ok   ", "FAIL "))]
    for ln in lines:
        print(ln)
        if ln.startswith("FAIL "):
            FAILED.append(ln)
    check("proxy: every check ran", r.returncode == 0 and len(lines) == PROXY_CHECKS,
          f"exit {r.returncode}, {len(lines)}/{PROXY_CHECKS} lines; {r.stderr.strip()[-300:]}")


PROXY_CHECKS = 8


def _proxy_child() -> int:
    up = _serve(_Upstream)
    os.environ["BLACKBAR_PROXY_UPSTREAM"] = f"http://127.0.0.1:{up.server_port}"
    spec = importlib.util.spec_from_file_location("blackbar_proxy", os.path.join(ROOT, "proxy", "blackbar_proxy.py"))
    proxy = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(proxy)
    px = _serve(proxy.Handler)
    body = json.dumps({"messages": [{"role": "user", "content": "my DNI is 12345678Z"}]}).encode()

    def post(route: str = "/v1/messages") -> int:
        req = Request(f"http://127.0.0.1:{px.server_port}{route}", data=body,
                      headers={"Content-Type": "application/json"}, method="POST")
        try:
            return urlopen(req, timeout=20).status
        except HTTPError as e:
            return e.code

    code = post()
    check("proxy: no key -> 503, nothing forwarded", code == 503 and _Upstream.calls == 0,
          f"status {code}, upstream calls {_Upstream.calls}")
    os.environ["BLACKBAR_KEY"] = "test-key-0123456789"
    code = post()
    check("proxy: analyzer down -> 503, nothing forwarded", code == 503 and _Upstream.calls == 0,
          f"status {code}, upstream calls {_Upstream.calls}")
    for route in ("/v1/messages?beta=true", "/v1/messages/count_tokens"):
        code = post(route)
        check(f"proxy: {route} is scanned too (503 while analyzer is down)",
              code == 503 and _Upstream.calls == 0, f"status {code}, upstream calls {_Upstream.calls}")
    code = post("//v1/%6dessages")
    check("proxy: a non-canonical spelling of the route is scanned too",
          code == 503 and _Upstream.calls == 0, f"status {code}, upstream calls {_Upstream.calls}")
    code = post("/v1/messages;x/../batches")
    check("proxy: a path with ';' or '..' is refused, not forwarded",
          400 <= code < 500 and _Upstream.calls == 0, f"status {code}, upstream calls {_Upstream.calls}")
    code = post("/v1/messages/batches")
    check("proxy: an unscanned POST route is refused, not forwarded",
          400 <= code < 500 and _Upstream.calls == 0, f"status {code}, upstream calls {_Upstream.calls}")
    os.environ["PRESIDIO_GUARD_FAIL"] = "open"
    code = post()
    check("proxy: PRESIDIO_GUARD_FAIL=open forwards unmodified", code == 200 and _Upstream.calls == 1,
          f"status {code}, upstream calls {_Upstream.calls}")
    px.shutdown()
    up.shutdown()
    return 1 if FAILED else 0


def test_legacy_image() -> None:
    base = os.path.join(ROOT, "docs", "presidio-multilang")
    compose = open(os.path.join(base, "docker-compose.yml"), encoding="utf-8").read()
    check("legacy compose: binds 127.0.0.1 only", '"127.0.0.1:5002:3000"' in compose)
    users = [ln.split()[1] for ln in open(os.path.join(base, "Dockerfile"), encoding="utf-8")
             if ln.startswith("USER ")]
    check("legacy Dockerfile: does not end as root",
          bool(users) and users[-1].split(":")[0] not in ("root", "0"), str(users))


def test_fail_closed_on_any_error() -> None:
    html = _analyzer("html")
    r = _hook("UserPromptSubmit", {"prompt": "hi ada@example.com"}, PRESIDIO_ANALYZER_URL=html)
    check("hook: an unusable analyzer reply blocks the prompt (exit 2)", r.returncode == 2,
          f"exit {r.returncode} {r.stderr[-200:]}")
    r = _hook("PostToolUse", {"tool_name": "Read", "tool_response": "contact ada@example.com"},
              PRESIDIO_ANALYZER_URL=html)
    check("hook: an unusable analyzer reply withholds the result",
          "updatedToolOutput" in r.stdout and "ada@example.com" not in r.stdout, r.stdout or r.stderr[-200:])
    r = subprocess.run([sys.executable, os.path.join(HERE, "pii_filter.py"), "PostToolUse"],
                       input="[" * 5000, capture_output=True, text=True, env=_isolated_env(), timeout=30)
    check("hook: an unreadable payload withholds the result",
          r.returncode == 0 and "updatedToolOutput" in r.stdout, f"exit {r.returncode} {r.stdout or r.stderr[-200:]}")
    r = _hook("UserPromptSubmit", {"prompt": "hi"}, PRESIDIO_GUARD_TIMEOUT="8s")
    check("hook: a config error at import blocks (exit 2)", r.returncode == 2, f"exit {r.returncode}")
    r = _hook("PostToolUse", {"tool_name": "Read", "tool_response": "contact ada@example.com"},
              PRESIDIO_ANALYZER_URL=_analyzer("spans"), PRESIDIO_GUARD_OPERATOR="hash",
              XDG_CONFIG_HOME=_unwritable_config())
    check("hook: a salt that cannot be written withholds the result",
          r.returncode == 0 and "updatedToolOutput" in r.stdout and "ada@example.com" not in r.stdout,
          f"exit {r.returncode} {r.stdout or r.stderr[-200:]}")
    r = _hook("PreToolUse", {"tool_name": "WebFetch", "tool_input": {"url": "https://x/?q=ada@example.com"}})
    check("hook PreToolUse egress: blocks (exit 2) when analyzer is down", r.returncode == 2, f"exit {r.returncode}")
    r = _hook("MessageDisplay", {"delta": "ada@example.com"}, PRESIDIO_GUARD_DISPLAY_REDACTION="on")
    check("hook MessageDisplay: display-only, stays open", r.returncode == 0, f"exit {r.returncode}")
    r = _hook("PostToolUse", {"tool_name": "Read", "tool_response": "contact ada@example.com"},
              PRESIDIO_GUARD_FAIL="open")
    check("hook PostToolUse: PRESIDIO_GUARD_FAIL=open passes the result with a notice",
          r.returncode == 0 and "updatedToolOutput" not in r.stdout and "inactive" in r.stdout, r.stdout)


def test_audit_never_breaks_detection() -> None:
    code = ("import sys; sys.path.insert(0, sys.argv[1]); import presidio_client;"
            "print(len(presidio_client.PresidioClient(source='t').analyze('contact ada@example.com')))")
    for operator in ("replace", "hash"):
        r = subprocess.run([sys.executable, "-c", code, HERE], capture_output=True, text=True, timeout=30,
                           env=_isolated_env(PRESIDIO_ANALYZER_URL=_analyzer("spans"), BLACKBAR_AUDIT_ENABLED="1",
                                             BLACKBAR_AUDIT_DIR=tempfile.mkdtemp(prefix="bb-sec-audit-"),
                                             PRESIDIO_GUARD_OPERATOR=operator, XDG_CONFIG_HOME=_unwritable_config()))
        check(f"audit: an unwritable salt does not break detection (operator {operator})",
              r.returncode == 0 and r.stdout.strip() == "1", f"exit {r.returncode} {r.stdout} {r.stderr[-200:]}")
    import pii_audit

    _use_env(BLACKBAR_SALT="salt-a")
    fa = pii_audit.fingerprint("ada@example.com")
    _use_env(BLACKBAR_SALT="salt-b")
    fb = pii_audit.fingerprint("ada@example.com")
    check("audit: fingerprint follows BLACKBAR_SALT", fa != fb)
    _use_env(BLACKBAR_SALT="salt-a", PII_AUDIT_SALT="audit-c")
    fc = pii_audit.fingerprint("ada@example.com")
    _use_env(BLACKBAR_SALT="salt-b", PII_AUDIT_SALT="audit-c")
    check("audit: PII_AUDIT_SALT overrides for fingerprints",
          fc == pii_audit.fingerprint("ada@example.com") and fc != fa)


def test_salt_file_robust() -> None:
    import bb_key

    _use_env()
    path = os.path.join(os.environ["XDG_CONFIG_HOME"], "blackbar", "salt")
    os.makedirs(os.path.dirname(path))
    open(path, "w").close()
    check("salt: an empty file is replaced by a usable salt", len(bb_key.local_salt()) >= 16)
    if os.name == "posix":
        os.chmod(path, 0o644)
        bb_key.local_salt()
        check("salt: a lax file mode is tightened to 0600",
              stat.S_IMODE(os.stat(path).st_mode) == 0o600, oct(stat.S_IMODE(os.stat(path).st_mode)))
    env = _isolated_env()
    # Every child sleeps until the same instant, so all of them race the first write.
    code = ("import sys, time; sys.path.insert(0, sys.argv[1]); import bb_key;"
            "time.sleep(max(0.0, float(sys.argv[2]) - time.time())); print(bb_key.local_salt().hex())")
    start = str(time.time() + 2.0)
    procs = [subprocess.Popen([sys.executable, "-c", code, HERE, start], stdout=subprocess.PIPE, text=True, env=env)
             for _ in range(16)]
    outs = {p.communicate(timeout=30)[0].strip() for p in procs}
    check("salt: concurrent first use agrees on one salt", len(outs) == 1, str(outs))
    _use_env(XDG_CONFIG_HOME=_unwritable_config())
    try:
        bb_key.local_salt()
        raised = False
    except OSError:
        raised = True
    check("salt: an unwritable location raises, never an empty salt", raised)


def test_secrets_scrubbed_from_results() -> None:
    key, salt = "test-key-0123456789abcdef", "salt-secret-value-0123"
    r = _hook("PostToolUse", {"tool_name": "Bash", "tool_response": f"BLACKBAR_KEY={key}\nBLACKBAR_SALT={salt}"},
              PRESIDIO_ANALYZER_URL=_analyzer("empty"), BLACKBAR_KEY=key, BLACKBAR_SALT=salt)
    check("hook PostToolUse: key and salt never reach the model in a result",
          "updatedToolOutput" in r.stdout and key not in r.stdout and salt not in r.stdout,
          r.stdout or r.stderr[-200:])


def test_mcp_server_survives_errors() -> None:
    req = "\n".join(json.dumps(m) for m in (
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
         "params": {"name": "presidio_anonymize", "arguments": {"text": "contact ada@example.com", "operator": "hash"}}},
        {"jsonrpc": "2.0", "id": 2, "method": "ping"},
    )) + "\n"
    r = subprocess.run([sys.executable, os.path.join(HERE, "mcp_server.py")], input=req, capture_output=True,
                       text=True, timeout=30,
                       env=_isolated_env(PRESIDIO_ANALYZER_URL=_analyzer("spans"), XDG_CONFIG_HOME=_unwritable_config()))
    replies = [json.loads(ln) for ln in r.stdout.splitlines() if ln.strip()]
    check("mcp: an internal error is a tool error, the server keeps serving",
          len(replies) == 2 and replies[0]["result"].get("isError") is True and replies[1].get("result") == {},
          f"{r.stdout} {r.stderr[-200:]}")
    import bb_crypto
    import mcp_server
    from presidio_client import Span

    key = "test-key-0123456789"
    token = bb_crypto.encrypt_spans("ada@example.com", [Span("EMAIL_ADDRESS", 0, 15, 1.0)], key)
    _use_env()
    out = json.loads(mcp_server.tool_decrypt({"text": token, "key": key}))
    check("mcp: a key passed as an argument is ignored", "error" in out, str(out))


def test_desktop_parity_and_errors() -> None:
    import bb_crypto
    import bb_key
    import presidio_client
    from presidio_client import Span

    key = "test-key-0123456789"
    token = bb_crypto.encrypt_spans("ada@example.com", [Span("EMAIL_ADDRESS", 0, 15, 1.0)], key)
    r = _node("const s=require(process.argv[1]);"
              "console.log(JSON.stringify({desc:s.TOOLS.map(t=>[t.name,t.description]),"
              "dec:JSON.parse(s.toolDecrypt({text:process.argv[2],key:process.argv[3]}))}));", token, key)
    if r:
        desc = dict(r["desc"])
        check("desktop server: analyze/decrypt warn about plaintext",
              all("plaintext" in desc[n] for n in ("presidio_analyze", "presidio_decrypt")), str(desc))
        check("desktop server: a key passed as an argument is ignored", "error" in r["dec"], str(r["dec"]))
    _use_env()
    py_hash = presidio_client._replacement("12345678Z", "ES_NIF", "hash")
    r = _node("const s=require(process.argv[1]);console.log(JSON.stringify(s.replacement('12345678Z','ES_NIF','hash')));",
              XDG_CONFIG_HOME=os.environ["XDG_CONFIG_HOME"])
    check("desktop server: shares the salt file with Python", r == py_hash, f"{r} != {py_hash}")
    cfg = tempfile.mkdtemp(prefix="bb-sec-cfg-")
    os.makedirs(os.path.join(cfg, "blackbar"))
    open(os.path.join(cfg, "blackbar", "salt"), "w").close()
    r = _node("const s=require(process.argv[1]);s.replacement('x','T','hash');"
              "console.log(JSON.stringify(require('fs').readFileSync(process.env.XDG_CONFIG_HOME+'/blackbar/salt','utf8')));",
              XDG_CONFIG_HOME=cfg)
    _use_env(XDG_CONFIG_HOME=cfg)
    check("desktop server: replaces an empty salt file, readable by Python",
          isinstance(r, str) and len(bytes.fromhex(r)) >= 16 and bb_key.local_salt() == bytes.fromhex(r), str(r))


def test_docs_never_ask_for_the_key() -> None:
    files = (glob.glob(os.path.join(ROOT, "plugins", "blackbar", "skills", "**", "*.md"), recursive=True)
             + glob.glob(os.path.join(ROOT, "plugins", "blackbar", "commands", "*.md"))
             + [os.path.join(ROOT, p) for p in ("README.md", "desktop/README.md", "plugins/blackbar/README.md")])
    banned = re.compile(r"ask (the user )?for (the|a) key|pass(es)? (a|the) key|and the key to `?presidio_decrypt"
                        r"|`key` is required|key swordfish", re.I)
    hits = [f"{os.path.relpath(f, ROOT)}:{n}" for f in files
            for n, ln in enumerate(open(f, encoding="utf-8"), 1) if banned.search(ln)]
    check("docs: no instruction to ask for or pass the key", not hits, str(hits))


def test_no_stale_mcpb_tracked() -> None:
    r = subprocess.run(["git", "-C", ROOT, "ls-files", "--", "desktop/*.mcpb"], capture_output=True, text=True)
    check("desktop: no prebuilt .mcpb in the tree (the release builds it)",
          r.returncode == 0 and not r.stdout.strip(), r.stdout or r.stderr)


def main() -> int:
    for t in (test_hash_is_salted, test_salt_file, test_audit_fingerprint_salt,
              test_fail_closed_defaults, test_no_decrypt_into_bash,
              test_mcp_key_not_an_argument, test_desktop, test_proxy_fail_closed,
              test_legacy_image, test_fail_closed_on_any_error, test_audit_never_breaks_detection,
              test_salt_file_robust, test_secrets_scrubbed_from_results, test_mcp_server_survives_errors,
              test_desktop_parity_and_errors, test_docs_never_ask_for_the_key, test_no_stale_mcpb_tracked):
        try:
            t()
        except Exception as exc:  # noqa: BLE001 -- report and keep going
            check(t.__name__, False, f"{type(exc).__name__}: {exc}")
    if FAILED:
        print(f"\n{len(FAILED)} SECURITY CHECK(S) FAILED")
        return 1
    print("\nALL SECURITY TESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(_proxy_child() if "--proxy-child" in sys.argv else main())
