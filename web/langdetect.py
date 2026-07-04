"""
langdetect.py
=============
Tiny, zero-dependency language guesser for the six languages the blackbar
analyzer loads (en, es, fr, de, it, pt). Presidio's NER is language-specific, so
picking the right model matters — but a full language-detection library would
break the "zero third-party deps" rule. This is a stop-word-frequency heuristic
with a few diacritic tie-breakers. It is deliberately conservative: on low
confidence it returns the caller's default so the UI can fall back cleanly, and
the user can always override the choice.
"""

from __future__ import annotations

import re

SUPPORTED = ("en", "es", "fr", "de", "it", "pt")

# Common function words, chosen to discriminate between the six languages.
_STOPWORDS: dict[str, set[str]] = {
    "en": {
        "the", "and", "of", "to", "in", "is", "you", "that", "it", "for", "was",
        "with", "as", "his", "they", "at", "be", "this", "have", "from", "or",
        "had", "by", "not", "but", "what", "all", "were", "we", "when", "your",
        "can", "there", "which", "their", "if", "will", "about",
    },
    "es": {
        "el", "la", "los", "las", "de", "que", "y", "en", "un", "una", "por",
        "con", "no", "se", "su", "para", "es", "al", "lo", "como", "más", "pero",
        "sus", "le", "ya", "o", "este", "sí", "porque", "esta", "son", "entre",
        "está", "mi", "nombre", "correo", "teléfono", "dni", "dirección",
    },
    "fr": {
        "le", "la", "les", "de", "un", "une", "et", "à", "que", "qui", "dans",
        "pour", "pas", "sur", "au", "ce", "il", "je", "vous", "nous", "est",
        "avec", "son", "ses", "mais", "ou", "où", "être", "avoir", "cette",
        "mon", "nom", "adresse", "téléphone", "courriel",
    },
    "de": {
        "der", "die", "das", "und", "ist", "ich", "nicht", "ein", "eine", "zu",
        "den", "mit", "sich", "auf", "für", "von", "aber", "auch", "als", "so",
        "wird", "war", "haben", "sind", "dem", "des", "im", "am", "name",
        "adresse", "telefon", "oder", "nach", "über",
    },
    "it": {
        "il", "la", "le", "di", "che", "e", "un", "una", "per", "con", "non",
        "si", "su", "come", "ma", "più", "sono", "anche", "questo", "questa",
        "gli", "nel", "alla", "dei", "delle", "è", "mi", "ha", "nome",
        "indirizzo", "telefono", "della", "sono",
    },
    "pt": {
        "o", "a", "os", "as", "de", "que", "e", "em", "um", "uma", "para", "com",
        "não", "se", "por", "mais", "como", "mas", "ao", "dos", "das", "à",
        "são", "está", "isto", "porque", "nome", "endereço", "telefone",
        "correio", "você", "também",
    },
}

_WORD_RE = re.compile(r"[a-zà-öø-ÿ]+", re.IGNORECASE)

# Diacritic / character hints (small nudges, not decisive on their own).
_HINTS = {
    "ñ": "es", "¿": "es", "¡": "es",
    "ß": "de", "ä": "de", "ö": "de", "ü": "de",
    "ç": "pt", "ã": "pt", "õ": "pt",
    "à": "it", "ò": "it", "ù": "it",
    "œ": "fr", "ê": "fr", "î": "fr", "û": "fr",
}


def guess(text: str, candidates: tuple[str, ...] | None = None,
          default: str = "en") -> tuple[str, float]:
    """Return (language, confidence in 0..1). Falls back to `default` when the
    signal is too weak. `candidates` restricts the choice (e.g. to the languages
    the analyzer actually loaded)."""
    langs = tuple(l for l in (candidates or SUPPORTED) if l in _STOPWORDS) or SUPPORTED
    tokens = _WORD_RE.findall(text.lower())
    scores = {l: 0.0 for l in langs}

    for tok in tokens:
        for l in langs:
            if tok in _STOPWORDS[l]:
                scores[l] += 1.0

    lowered = text.lower()
    for ch, l in _HINTS.items():
        if l in scores and ch in lowered:
            scores[l] += 0.5

    total = sum(scores.values())
    if total <= 0:
        return (default if default in langs else langs[0]), 0.0

    best = max(scores, key=lambda l: scores[l])
    confidence = scores[best] / total
    # Require a minimal amount of evidence; otherwise defer to the default.
    if scores[best] < 2 or confidence < 0.34:
        return (default if default in langs else best), round(confidence, 3)
    return best, round(confidence, 3)
