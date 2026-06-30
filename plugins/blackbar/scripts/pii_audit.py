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
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

_DAY_FILE_RE = re.compile(r"^pii-audit-(\d{4}-\d{2}-\d{2})\.jsonl$")
_TRUE = {"1", "true", "on", "yes"}

# Remembers the day we last pruned for, so we prune once per rollover rather
# than on every single record write.
_pruned_for_day: str | None = None


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


# --------------------------------------------------------------------------- #
# Writing
# --------------------------------------------------------------------------- #
def record(text: str, spans: Iterable[Any], source: str, cfg: Any, redacted: str) -> None:
    """Append one PII-safe audit record for a detector call. No-op when
    auditing is disabled. Never raises -- auditing must not break detection."""
    if not enabled():
        return
    try:
        spans = list(spans)
        directory = audit_dir()
        os.makedirs(directory, exist_ok=True)
        now = datetime.now(timezone.utc)
        day = now.strftime("%Y-%m-%d")
        _maybe_prune(directory, day)

        rec = {
            "ts": now.isoformat(),
            "source": source,
            "fingerprint": fingerprint(text),
            "lang": getattr(cfg, "language", None),
            "mode": getattr(cfg, "mode", None),
            "operator": getattr(cfg, "operator", None),
            "threshold": getattr(cfg, "threshold", None),
            "n_entities": len(spans),
            "entities": [
                {
                    "type": s.entity_type,
                    "score": round(s.score, 3),
                    "start": s.start,
                    "end": s.end,
                }
                for s in spans
            ],
            "redacted": redacted,  # safe to store: PII already removed
        }
        path = os.path.join(directory, f"pii-audit-{day}.jsonl")
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception:
        # A failed audit must never propagate into the detection path.
        pass


# --------------------------------------------------------------------------- #
# Retention / lifecycle
# --------------------------------------------------------------------------- #
def _maybe_prune(directory: str, day: str) -> None:
    global _pruned_for_day
    if _pruned_for_day == day:
        return
    _pruned_for_day = day
    try:
        prune(directory)
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
