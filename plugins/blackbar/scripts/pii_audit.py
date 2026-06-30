#!/usr/bin/env python3
"""
pii_audit.py
============
PII-safe audit trail for every Presidio detector call made anywhere in
blackbar -- hooks, the MCP server, the CLI and the proxy all reach detection
through ``presidio_client.PresidioClient.analyze``, which is the single place
that calls :func:`record`. So one chokepoint audits all three paths and never
re-runs detection: it logs the spans that were already computed.

Design rules (a leaky audit log would defeat the whole point):

  * The original text is NEVER written. We store a salted SHA-256 *fingerprint*
    (so identical inputs can be correlated across calls without keeping the
    value) plus the redacted form, entity types, scores and spans.
  * Auditing is OPT-IN. Nothing is written unless BLACKBAR_AUDIT_ENABLED is set.
  * Auditing must never break detection. Every failure here is swallowed -- a
    logging problem must not block a hook or fail a tool call.

Storage & lifecycle
--------------------
Records are appended as JSON lines to one file per UTC day:

    <BLACKBAR_AUDIT_DIR>/pii-audit-YYYY-MM-DD.jsonl

Append-only JSONL cannot drop a single record without rewriting the file, so
retention works by deleting whole day-files. When the day rolls over, files
older than the retention window are pruned automatically (storage-limitation,
GDPR Art. 5(1)(e)). The fingerprint is a one-way salted hash, so per-subject
erasure is neither possible nor needed; the retention window is the control.

Configuration (all via environment variables)
----------------------------------------------
  BLACKBAR_AUDIT_ENABLED          off unless "1"/"true"/"on"/"yes"   (off)
  BLACKBAR_AUDIT_DIR              audit directory      ($XDG_DATA_HOME/blackbar/audit)
  BLACKBAR_AUDIT_RETENTION_DAYS   days to keep; <=0 means keep forever      (90)
  PII_AUDIT_SALT                  salt for the fingerprint (set a real secret!)

CLI (lifecycle management)
--------------------------
  python pii_audit.py --stats     summarise stored records
  python pii_audit.py --prune     delete files older than the retention window
  python pii_audit.py --purge     delete every audit file (asks unless --yes)
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

try:
    import fcntl  # POSIX file locking; absent on Windows
except ImportError:  # pragma: no cover - platform dependent
    fcntl = None

_DAY_FILE_RE = re.compile(r"^pii-audit-(\d{4}-\d{2}-\d{2})\.jsonl$")
_MARKER = ".last-prune"
_TRUE = {"1", "true", "on", "yes"}

# Serialises writes/prunes within a process (the proxy and MCP server are
# multi-threaded); cross-process safety comes from flock on the day-file.
_lock = threading.Lock()

# Remembers the day we last pruned for, so we prune once per rollover rather
# than on every single record write. Backed by a marker file so the guard also
# holds across the short-lived hook processes, where this global is always cold.
_pruned_for_day: str | None = None

# One-time breadcrumb so an enabled-but-failing audit trail is not fully silent.
_warned = False


# --------------------------------------------------------------------------- #
# Configuration helpers
# --------------------------------------------------------------------------- #
def enabled() -> bool:
    return os.environ.get("BLACKBAR_AUDIT_ENABLED", "").strip().lower() in _TRUE


def audit_dir() -> str:
    explicit = os.environ.get("BLACKBAR_AUDIT_DIR")
    if explicit:
        return os.path.expanduser(explicit)
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "share"
    )
    return os.path.join(base, "blackbar", "audit")


def retention_days() -> int:
    try:
        return int(os.environ.get("BLACKBAR_AUDIT_RETENTION_DAYS", "90"))
    except ValueError:
        return 90


def _salt() -> bytes:
    return os.environ.get("PII_AUDIT_SALT", "blackbar-change-this-salt").encode("utf-8")


def fingerprint(text: str) -> str:
    """Stable, non-reversible correlation id for an input, without keeping it."""
    return hashlib.sha256(_salt() + text.encode("utf-8")).hexdigest()[:16]


def _entity_record(s: Any) -> dict:
    """One PII-safe entity entry: type/score/span, plus the recognizer and
    pattern name when the decision process is available (audit only)."""
    rec = {
        "type": s.entity_type,
        "score": round(s.score, 3),
        "start": s.start,
        "end": s.end,
    }
    exp = getattr(s, "explanation", None)
    if exp:
        rec["recognizer"] = exp.get("recognizer")
        rec["pattern"] = exp.get("pattern_name")
    return rec


# --------------------------------------------------------------------------- #
# Writing
# --------------------------------------------------------------------------- #
def _emit(rec: dict) -> None:
    """Append one record (any event) to today's day-file, stamping ``ts``.
    No-op when disabled. Never raises -- auditing must not break the caller;
    an enabled-but-broken trail (read-only dir, full disk) warns once instead
    of staying fully silent."""
    if not enabled():
        return
    try:
        directory = audit_dir()
        os.makedirs(directory, exist_ok=True)
        now = datetime.now(timezone.utc)
        day = now.strftime("%Y-%m-%d")
        # The audit owns "ts": strip any caller-supplied one so it can't be forged.
        body = {k: v for k, v in rec.items() if k != "ts"}
        line = json.dumps({"ts": now.isoformat(), **body}, ensure_ascii=False) + "\n"
        path = os.path.join(directory, f"pii-audit-{day}.jsonl")
        # In-process lock for proxy/MCP threads; flock for concurrent processes.
        # Both keep one record's bytes from interleaving with another's.
        with _lock:
            _maybe_prune(directory, day)
            with open(path, "a", encoding="utf-8") as f:
                if fcntl is not None:
                    fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    f.write(line)
                finally:
                    if fcntl is not None:
                        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except Exception as exc:
        _warn_once(exc)


def record(text: str, spans: Iterable[Any], source: str, cfg: Any, redacted: str) -> None:
    """Append a ``detect`` record: what the detector found on one call."""
    if not enabled():
        return
    spans = list(spans)
    _emit({
        "event": "detect",
        "source": source,
        "fingerprint": fingerprint(text),
        "lang": getattr(cfg, "language", None),
        "mode": getattr(cfg, "mode", None),
        "operator": getattr(cfg, "operator", None),
        "threshold": getattr(cfg, "threshold", None),
        "n_entities": len(spans),
        "entities": [_entity_record(s) for s in spans],
        "redacted": redacted,  # safe to store: PII already removed
    })


def record_op(
    source: str,
    operator: str,
    n_transformed: int,
    *,
    requested: str | None = None,
    fallback: str | None = None,
    ok: bool = True,
    error: str | None = None,
) -> None:
    """Append an ``anonymize`` record: what the anonymization step actually did,
    so process problems are visible in the trail (e.g. an encrypt that fell back
    to redact for lack of a key, or a detector outage). PII-safe: operator name
    and counts only, never the values or the tokens.

    ``operator``  is the operation applied (replace|redact|mask|hash|encrypt|decrypt).
    ``requested`` is what was asked for, when it differs (e.g. "encrypt" while the
    applied operator is "redact" because no key was available).
    """
    if not enabled():
        return
    rec: dict = {
        "event": "anonymize",
        "source": source,
        "operator": operator,
        "n_transformed": n_transformed,
        "ok": ok,
    }
    if requested is not None and requested != operator:
        rec["requested"] = requested
    if fallback is not None:
        rec["fallback"] = fallback
    if error is not None:
        rec["error"] = error
    _emit(rec)


def _warn_once(exc: Exception) -> None:
    global _warned
    if _warned:
        return
    _warned = True
    try:
        sys.stderr.write(
            f"[blackbar] audit trail write failed ({type(exc).__name__}: {exc}); "
            f"detection continues but records are NOT being written.\n"
        )
    except Exception:
        pass


# --------------------------------------------------------------------------- #
# Retention / lifecycle
# --------------------------------------------------------------------------- #
def _maybe_prune(directory: str, day: str) -> None:
    """Prune at most once per UTC day. The in-process global is the fast path;
    a marker file makes the guard hold across the short-lived hook processes
    too, so prune() doesn't scan the directory on every hook invocation.
    Callers hold ``_lock``."""
    global _pruned_for_day
    if _pruned_for_day == day:
        return
    marker = os.path.join(directory, _MARKER)
    try:
        with open(marker, "r", encoding="utf-8") as f:
            if f.read().strip() == day:
                _pruned_for_day = day  # already pruned today by another process
                return
    except (FileNotFoundError, OSError):
        pass
    _pruned_for_day = day
    try:
        prune(directory)
        with open(marker, "w", encoding="utf-8") as f:
            f.write(day)
    except Exception:
        pass


def prune(directory: str | None = None, days: int | None = None) -> list[str]:
    """Delete day-files older than the retention window. Returns the names
    removed. A retention of <=0 means 'keep forever' and removes nothing."""
    directory = directory or audit_dir()
    days = retention_days() if days is None else days
    if days <= 0 or not os.path.isdir(directory):
        return []
    cutoff = datetime.now(timezone.utc).date() - timedelta(days=days)
    removed: list[str] = []
    for name in os.listdir(directory):
        m = _DAY_FILE_RE.match(name)
        if not m:
            continue
        try:
            file_day = datetime.strptime(m.group(1), "%Y-%m-%d").date()
        except ValueError:
            continue
        if file_day < cutoff:
            os.remove(os.path.join(directory, name))
            removed.append(name)
    return removed


def purge(directory: str | None = None) -> list[str]:
    """Delete every audit day-file. Returns the names removed."""
    directory = directory or audit_dir()
    if not os.path.isdir(directory):
        return []
    removed: list[str] = []
    for name in os.listdir(directory):
        if _DAY_FILE_RE.match(name):
            os.remove(os.path.join(directory, name))
            removed.append(name)
    return removed


def stats(directory: str | None = None) -> dict:
    """Summarise stored audit data without reading any record bodies in full."""
    directory = directory or audit_dir()
    out = {"dir": directory, "files": 0, "records": 0, "days": [], "bytes": 0}
    if not os.path.isdir(directory):
        return out
    for name in sorted(os.listdir(directory)):
        if not _DAY_FILE_RE.match(name):
            continue
        path = os.path.join(directory, name)
        out["files"] += 1
        out["bytes"] += os.path.getsize(path)
        out["days"].append(name)
        with open(path, "r", encoding="utf-8") as f:
            out["records"] += sum(1 for _ in f)
    return out


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _main(argv: list[str] | None = None) -> int:
    import argparse

    p = argparse.ArgumentParser(
        prog="pii_audit", description="Manage the blackbar PII audit trail"
    )
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--stats", action="store_true", help="summarise stored records")
    g.add_argument("--prune", action="store_true", help="delete files past retention")
    g.add_argument("--purge", action="store_true", help="delete ALL audit files")
    p.add_argument("--yes", action="store_true", help="skip confirmation for --purge")
    args = p.parse_args(argv)

    if args.stats:
        s = stats()
        print(json.dumps(s, indent=2, ensure_ascii=False))
        return 0
    if args.prune:
        removed = prune()
        print(f"pruned {len(removed)} file(s) past {retention_days()}-day retention")
        for n in removed:
            print(f"  - {n}")
        return 0
    if args.purge:
        if not args.yes:
            reply = input(f"Delete ALL audit files in {audit_dir()}? [y/N] ").strip().lower()
            if reply not in {"y", "yes"}:
                print("aborted")
                return 1
        removed = purge()
        print(f"purged {len(removed)} file(s)")
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
