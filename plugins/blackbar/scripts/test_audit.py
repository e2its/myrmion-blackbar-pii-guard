#!/usr/bin/env python3
"""
test_audit.py
=============
Self-contained checks for the PII-safe audit trail (pii_audit.py). No Presidio
service or spaCy model needed: it drives pii_audit directly with synthetic spans
and reads the resulting JSON lines back from disk, so it validates the actual
log on disk, not just in-memory state.

    python3 test_audit.py        # prints each check + a sample of the log; exit 0 on success
"""

from __future__ import annotations

import glob
import json
import os
import sys
import tempfile
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _fresh_dir() -> str:
    import pii_audit

    d = tempfile.mkdtemp(prefix="bb-audit-test-")
    os.environ["BLACKBAR_AUDIT_ENABLED"] = "1"
    os.environ["BLACKBAR_AUDIT_DIR"] = d
    os.environ["PII_AUDIT_SALT"] = "test-salt"
    os.environ.pop("BLACKBAR_AUDIT_RETENTION_DAYS", None)
    # Reset the once-per-day prune guard so each sub-test's dir is independent.
    pii_audit._pruned_for_day = None
    return d


def _read(d: str) -> list[dict]:
    files = glob.glob(os.path.join(d, "pii-audit-*.jsonl"))
    return [json.loads(line) for f in files for line in open(f, encoding="utf-8")]


def main() -> int:
    import pii_audit
    from presidio_client import Config, Span

    cfg = Config.load()
    secret = "Juan Perez juan.perez@example.com"

    # --- detect record: shape, decision process, PII-safety ----------------- #
    d = _fresh_dir()
    spans = [
        Span("PERSON", 0, 10, 0.85, {"recognizer": "SpacyRecognizer", "pattern_name": None}),
        Span("EMAIL_ADDRESS", 11, 33, 0.99, {"recognizer": "EmailRecognizer", "pattern_name": "Email (Medium)"}),
    ]
    pii_audit.record(secret, spans, "test:detect", cfg, "<PERSON> <EMAIL_ADDRESS>")
    recs = _read(d)
    assert len(recs) == 1, recs
    r = recs[0]
    assert r["event"] == "detect" and r["source"] == "test:detect"
    assert r["n_entities"] == 2 and len(r["entities"]) == 2
    assert r["entities"][1]["recognizer"] == "EmailRecognizer"
    assert r["entities"][1]["pattern"] == "Email (Medium)"
    assert r["fingerprint"] == pii_audit.fingerprint(secret)
    assert secret not in json.dumps({k: v for k, v in r.items() if k != "redacted"}), "raw PII leaked"
    print("[ok] detect: event/entities/decision-process/fingerprint, no raw PII outside redacted")

    # --- anonymize records: operator + counts, and PII-safety --------------- #
    d = _fresh_dir()
    pii_audit.record_op("hook:PostToolUse", "encrypt", 2, requested="encrypt")
    pii_audit.record_op("hook:PostToolUse", "replace", 4, requested="encrypt", fallback="no_key")
    pii_audit.record_op("mcp:presidio_anonymize", "mask", 3)
    pii_audit.record_op("hook:PreToolUse", "decrypt", 1)
    ops = _read(d)
    assert all(o["event"] == "anonymize" for o in ops)
    by_op = {o["operator"]: o for o in ops}
    assert set(by_op) == {"encrypt", "replace", "mask", "decrypt"}, list(by_op)
    assert by_op["encrypt"]["n_transformed"] == 2 and by_op["encrypt"]["ok"] is True
    fb = by_op["replace"]
    assert fb["requested"] == "encrypt" and fb["fallback"] == "no_key", fb
    # an anonymize record carries only operator/counts -- no values, no fingerprint
    for o in ops:
        assert "fingerprint" not in o and "entities" not in o and "redacted" not in o, o
    print("[ok] anonymize: encrypt/redact/mask/decrypt + encrypt->redact fallback, metadata-only")

    # --- retention: 2-day window deletes older day-files -------------------- #
    d = _fresh_dir()
    from datetime import datetime, timedelta, timezone
    today = datetime.now(timezone.utc).date()
    for delta in (5, 3, 1):  # 5 and 3 days old must go, 1 day old stays (window=2)
        name = f"pii-audit-{(today - timedelta(days=delta)).strftime('%Y-%m-%d')}.jsonl"
        open(os.path.join(d, name), "w").write('{"x":1}\n')
    removed = pii_audit.prune(days=2)
    assert len(removed) == 2, removed
    assert glob.glob(os.path.join(d, "pii-audit-*.jsonl")), "kept file missing"
    print(f"[ok] retention(2d): pruned {len(removed)} old file(s), kept the recent one")

    # --- concurrency: many threads, no torn JSON lines ---------------------- #
    d = _fresh_dir()

    def writer(i: int) -> None:
        big = "x" * 6000  # exceed the write buffer to stress interleaving
        for n in range(120):
            pii_audit.record_op(f"t{i}", "encrypt", n, requested=big)

    threads = [threading.Thread(target=writer, args=(i,)) for i in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    lines = open(glob.glob(os.path.join(d, "*.jsonl"))[0], encoding="utf-8").read().splitlines()
    bad = sum(1 for ln in lines if _is_bad(ln))
    assert len(lines) == 12 * 120 and bad == 0, (len(lines), bad)
    print(f"[ok] concurrency: {len(lines)} lines, 0 corrupt")

    # --- show the log on disk (validate the records, not just asserts) ------ #
    print("\n--- sample of the audit log on disk ---")
    for o in ops:
        print("  " + json.dumps(o, ensure_ascii=False))

    print("\nALL AUDIT TESTS PASSED")
    return 0


def _is_bad(line: str) -> bool:
    try:
        json.loads(line)
        return False
    except Exception:
        return True


if __name__ == "__main__":
    raise SystemExit(main())
