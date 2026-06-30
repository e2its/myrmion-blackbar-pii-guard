"""
presidio_client.py
==================
A thin, dependency-light wrapper around Microsoft Presidio for use inside
Claude Code hooks.

Two analysis backends are supported:

  * "service" (recommended for hooks): POST to a long-running Presidio
    Analyzer HTTP service (e.g. the official docker image). The hook process
    is short-lived, so we never pay the multi-second spaCy model load on each
    invocation -- the service holds the model in memory.

  * "library": import presidio_analyzer in-process. Correct but slow on cold
    hook processes because the NLP model loads every time. Fine for the
    long-running MCP server, or as a no-Docker fallback.

Detection (finding PII spans) is delegated to Presidio. Anonymization
(turning a span into <EMAIL_ADDRESS>, ****, a hash, etc.) is applied LOCALLY
in this module. That keeps us independent of the Presidio Anonymizer REST
schema and means a single Analyzer service is all you need to run.

Everything is configured through environment variables so the same module
works identically from a hook, the MCP server, and the command-line tools.
"""

from __future__ import annotations

import hashlib
import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Iterable

import pii_audit


# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
def _env(name: str, default: str) -> str:
    val = os.environ.get(name)
    return val if val not in (None, "") else default


@dataclass
class Config:
    mode: str = _env("PRESIDIO_GUARD_MODE", "service")  # "service" | "library"
    analyzer_url: str = _env("PRESIDIO_ANALYZER_URL", "http://localhost:5002")
    language: str = _env("PRESIDIO_GUARD_LANGUAGE", "en")
    operator: str = _env("PRESIDIO_GUARD_OPERATOR", "replace")  # replace|redact|mask|hash
    threshold: float = float(_env("PRESIDIO_GUARD_THRESHOLD", "0.5"))
    # Comma-separated allow-list of entity types. Empty => all entities.
    entities: tuple[str, ...] = tuple(
        e.strip() for e in _env("PRESIDIO_GUARD_ENTITIES", "").split(",") if e.strip()
    )
    timeout: float = float(_env("PRESIDIO_GUARD_TIMEOUT", "8"))

    @classmethod
    def load(cls) -> "Config":
        return cls()


@dataclass
class Span:
    entity_type: str
    start: int
    end: int
    score: float


# --------------------------------------------------------------------------- #
# Detection backends
# --------------------------------------------------------------------------- #
class PresidioClient:
    def __init__(self, config: Config | None = None, source: str = "unknown") -> None:
        self.cfg = config or Config.load()
        self.source = source  # caller label for the audit trail
        self._engine = None  # lazily built AnalyzerEngine for library mode

    # -- public API -------------------------------------------------------- #
    def analyze(self, text: str) -> list[Span]:
        """Return PII spans found in `text`, filtered by score threshold.

        Every call is the single detection chokepoint for hooks, the MCP
        server, the CLI and the proxy, so it is also where the (opt-in) audit
        trail is emitted -- reusing the spans just computed, never re-detecting.
        """
        if not text or not text.strip():
            return []
        if self.cfg.mode == "library":
            raw = self._analyze_library(text)
        else:
            raw = self._analyze_service(text)
        spans = [s for s in raw if s.score >= self.cfg.threshold]
        if pii_audit.enabled():
            redacted = _apply_operator(text, spans, self.cfg.operator) if spans else text
            pii_audit.record(text, spans, self.source, self.cfg, redacted)
        return spans

    def redact(self, text: str) -> tuple[str, list[Span]]:
        """Return (redacted_text, spans). Applies the configured operator."""
        spans = self.analyze(text)
        if not spans:
            return text, []
        return _apply_operator(text, spans, self.cfg.operator), spans

    def map_strings(self, value: Any, transform) -> tuple[Any, int]:
        """Recursively apply ``transform`` to every string leaf in a JSON-like
        structure. ``transform`` takes a string and returns (new_string, count).
        Returns (new_value, total_count). This is the shared walker behind both
        one-way redaction and reversible encryption."""
        if isinstance(value, str):
            return transform(value)
        if isinstance(value, dict):
            out: dict[Any, Any] = {}
            count = 0
            for k, v in value.items():
                nv, c = self.map_strings(v, transform)
                out[k] = nv
                count += c
            return out, count
        if isinstance(value, list):
            out_list = []
            count = 0
            for v in value:
                nv, c = self.map_strings(v, transform)
                out_list.append(nv)
                count += c
            return out_list, count
        return value, 0

    def redact_structure(self, value: Any) -> tuple[Any, int]:
        """Recursively redact every string leaf in a JSON-like structure.

        Returns (redacted_value, number_of_entities_found).
        """

        def _transform(text: str) -> tuple[str, int]:
            new, spans = self.redact(text)
            return new, len(spans)

        return self.map_strings(value, _transform)

    # -- service backend --------------------------------------------------- #
    def _analyze_service(self, text: str) -> list[Span]:
        payload: dict[str, Any] = {"text": text, "language": self.cfg.language}
        if self.cfg.entities:
            payload["entities"] = list(self.cfg.entities)
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.cfg.analyzer_url.rstrip("/") + "/analyze",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.cfg.timeout) as resp:
                results = json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
            raise PresidioUnavailable(
                f"Presidio analyzer unreachable at {self.cfg.analyzer_url}: {exc}"
            ) from exc
        return [
            Span(r["entity_type"], int(r["start"]), int(r["end"]), float(r.get("score", 1.0)))
            for r in results
        ]

    # -- library backend --------------------------------------------------- #
    def _analyze_library(self, text: str) -> list[Span]:
        engine = self._get_engine()
        kwargs: dict[str, Any] = {"text": text, "language": self.cfg.language}
        if self.cfg.entities:
            kwargs["entities"] = list(self.cfg.entities)
        results = engine.analyze(**kwargs)
        return [Span(r.entity_type, r.start, r.end, r.score) for r in results]

    def _get_engine(self):
        if self._engine is None:
            try:
                from presidio_analyzer import AnalyzerEngine
            except ImportError as exc:
                raise PresidioUnavailable(
                    "library mode requires `presidio-analyzer` and a spaCy model. "
                    "Install with: pip install presidio-analyzer presidio-anonymizer "
                    "&& python -m spacy download en_core_web_lg"
                ) from exc
            self._engine = AnalyzerEngine()
        return self._engine


# --------------------------------------------------------------------------- #
# Local operators (replace / redact / mask / hash)
# --------------------------------------------------------------------------- #
def _resolve_overlaps(spans: Iterable[Span]) -> list[Span]:
    """Keep highest-scoring, non-overlapping spans, sorted by start desc."""
    ordered = sorted(spans, key=lambda s: (s.start, -(s.end - s.start), -s.score))
    kept: list[Span] = []
    last_end = -1
    for s in ordered:
        if s.start >= last_end:
            kept.append(s)
            last_end = s.end
    # apply right-to-left so earlier offsets stay valid
    return sorted(kept, key=lambda s: s.start, reverse=True)


def _replacement(original: str, entity_type: str, operator: str) -> str:
    if operator == "redact":
        return ""
    if operator == "mask":
        if len(original) <= 4:
            return "*" * len(original)
        return "*" * (len(original) - 4) + original[-4:]
    if operator == "hash":
        digest = hashlib.sha256(original.encode("utf-8")).hexdigest()[:10]
        return f"<{entity_type}:{digest}>"
    # default: "replace"
    return f"<{entity_type}>"


def _apply_operator(text: str, spans: Iterable[Span], operator: str) -> str:
    out = text
    for span in _resolve_overlaps(spans):
        original = out[span.start : span.end]
        out = out[: span.start] + _replacement(original, span.entity_type, operator) + out[span.end :]
    return out


class PresidioUnavailable(RuntimeError):
    """Raised when neither the service nor the library backend can run."""


if __name__ == "__main__":
    import sys

    sample = " ".join(sys.argv[1:]) or "Ada Lovelace met Charles Babbage in London"
    client = PresidioClient()
    try:
        redacted, found = client.redact(sample)
        print(f"mode={client.cfg.mode} operator={client.cfg.operator}")
        print(f"in : {sample}")
        print(f"out: {redacted}")
        print(f"entities: {[s.entity_type for s in found]}")
    except PresidioUnavailable as e:
        print(f"[blackbar] {e}", file=sys.stderr)
        sys.exit(1)
