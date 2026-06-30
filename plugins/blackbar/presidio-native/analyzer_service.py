"""
blackbar comprehensive PII/PHI/financial analyzer service.

This is the single source of truth for blackbar's detection coverage. It runs
two ways with identical behaviour:
  * natively  — `setup.sh` + `run.sh` (no Docker), listening on :5002
  * in Docker — baked into the image by ../presidio-eu/Dockerfile, behind the
                compose 5002:3000 port map

It replicates the Presidio Analyzer REST contract blackbar's presidio_client.py
uses (POST /analyze {text, language, entities?} -> [{entity_type,start,end,score}])
while maximising sensitive-data coverage for GDPR / EU AI Act use:

  Tier 1 — ALL Presidio predefined recognizers, loaded for every supported
           language (names, locations, email, phone, URL, IP, MAC, dates,
           CREDIT_CARD, IBAN_CODE, CRYPTO, MEDICAL_LICENSE, and the
           country-specific national-ID recognizers: ES_NIF/ES_NIE, IT_*,
           UK_NHS, US_SSN/passport/driver, etc.).

  Tier 2 — Curated custom PatternRecognizers for sensitive identifiers Presidio
           lacks out of the box: SWIFT/BIC, EU VAT, EU national IDs and health
           identifiers. Numeric patterns carry a low base score and rely on
           context words to clear the client threshold, limiting false positives.

Languages and model size are configurable: BLACKBAR_LANGUAGES (comma list,
default "en,es,fr,de,it,pt") and BLACKBAR_MODEL_SIZE (md|lg, default md).
"""
import os
import re

from flask import Flask, request, jsonify
from presidio_analyzer import AnalyzerEngine, RecognizerRegistry, PatternRecognizer, Pattern
from presidio_analyzer.nlp_engine import NlpEngineProvider

LANGUAGES = [l.strip() for l in os.environ.get(
    "BLACKBAR_LANGUAGES", "en,es,fr,de,it,pt").split(",") if l.strip()]
MODEL_SIZE = os.environ.get("BLACKBAR_MODEL_SIZE", "md")


def _model(lang):
    return f"en_core_web_{MODEL_SIZE}" if lang == "en" else f"{lang}_core_news_{MODEL_SIZE}"


NLP_CONFIG = {
    "nlp_engine_name": "spacy",
    "models": [{"lang_code": l, "model_name": _model(l)} for l in LANGUAGES],
    "ner_model_configuration": {
        "model_to_presidio_entity_mapping": {
            "PER": "PERSON", "PERSON": "PERSON", "NORP": "NRP",
            "FAC": "LOCATION", "LOC": "LOCATION", "GPE": "LOCATION",
            "LOCATION": "LOCATION", "ORG": "ORGANIZATION",
            "ORGANIZATION": "ORGANIZATION", "DATE": "DATE_TIME", "TIME": "DATE_TIME",
        },
        "low_confidence_score_multiplier": 0.4,
        "low_score_entity_names": [],
        "labels_to_ignore": [
            "ORGANIZATION",  # many false positives (e.g. "seguridad social")
            "CARDINAL", "EVENT", "LANGUAGE", "LAW", "MONEY",
            "ORDINAL", "PERCENT", "PRODUCT", "QUANTITY", "WORK_OF_ART",
        ],
    },
}

# --- Tier 2: curated custom recognizers ------------------------------------- #
# (entity, [(label, regex, score)], context, case_sensitive). Numeric patterns
# carry a low base score and rely on single-word context tokens to clear the
# 0.5 client threshold. case_sensitive=True disables Presidio's default
# IGNORECASE so [A-Z] patterns (BIC, VAT, passport) don't match lowercase words.
CUSTOM = [
    ("SWIFT_BIC",
     [("bic", r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b", 0.4)],
     ["swift", "bic", "bank", "banco", "iban"], True),
    ("EU_VAT",
     [("vat", r"\b(?:ATU\d{8}|DE\d{9}|ES[A-Z0-9]\d{7}[A-Z0-9]|FR[A-Z0-9]{2}\d{9}|IT\d{11}|PT\d{9}|BE0?\d{9,10}|NL\d{9}B\d{2})\b", 0.6)],
     ["vat", "iva", "tax", "impuesto", "tva", "btw"], True),
    ("PT_NIF",
     [("pt_nif", r"\b[1235689]\d{8}\b", 0.2)],
     ["nif", "contribuinte", "fiscal"], False),
    ("DE_STEUER_ID",
     [("steuer", r"\b\d{11}\b", 0.2)],
     ["steuer", "steueridentifikationsnummer", "tax", "idnr"], False),
    ("FR_NIR_SSN",  # French social security number — also a health identifier
     [("nir", r"\b[12]\s?\d{2}\s?\d{2}\s?\d[0-9AB]\s?\d{3}\s?\d{3}\s?\d{2}\b", 0.5)],
     ["sécurité", "securite", "insee", "nir", "social", "vitale"], False),
    ("ES_SSN",  # Spanish Social Security number (NUSS / número de afiliación)
     [("es_ss", r"\b\d{2}[ /-]?\d{8}[ /-]?\d{2}\b", 0.3)],
     ["seguridad", "social", "nuss", "naf", "afiliación", "afiliacion"], False),
    ("HEALTH_RECORD",
     [("hrn", r"\b\d{6,12}\b", 0.2)],
     ["historia", "clínica", "clinica", "paciente", "expediente", "sanitaria",
      "record", "patient", "akte", "médical", "medical", "seguro"], False),
    ("ICD10_CODE",  # medical diagnosis code -> health (GDPR Art.9)
     [("icd10", r"\b[A-TV-Z]\d{2}(?:\.\d{1,3})?\b", 0.35)],
     ["icd", "cie", "diagnós", "diagnos", "diagnosis"], True),
    ("PASSPORT_GENERIC",
     [("passport", r"\b[A-Z]{1,2}\d{6,8}\b", 0.2)],
     ["passport", "pasaporte", "reisepass", "passeport", "passaporto"], True),
    ("PHONE_NUMBER",  # international fallback — Presidio misses +34/+39/+351 spaced formats
     [("intl_phone", r"\+\d{1,3}[\s.\-]?(?:\(?\d{1,4}\)?[\s.\-]?){2,6}\d{2,4}", 0.4)],
     ["tel", "teléfono", "telefono", "telefone", "téléphone", "phone", "telefon",
      "móvil", "movil", "celular", "mobile", "tel."], False),
    ("US_SSN",  # context-boosted US SSN (built-in recognizer scores some values too low)
     [("us_ssn", r"\b\d{3}-\d{2}-\d{4}\b", 0.3)],
     ["ssn", "social security"], False),
    ("EMAIL_ADDRESS",  # version-independent email (older presidio base images miss it)
     [("email", r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", 1.0)],
     [], False),
]

# --- Tier 3 / Layer 1: GDPR Art. 9 special-category lexicons ---------------- #
# Explicit-mention detection for special categories via multilingual term lists
# (Presidio deny_list). Catches "diagnosed with HIV", "is Muslim", "votes
# socialist" — NOT paraphrase ("he's been feeling down"); that is Layer 2's job
# (zero-shot, BLACKBAR_ENABLE_ZEROSHOT=1). Lexicons are representative, not
# exhaustive — extend per deployment. (entity, [terms], score)
SPECIAL_CATEGORIES = [
    ("HEALTH_CONDITION", 0.6, [
        "cáncer", "cancer", "cancro", "câncer", "krebs", "cancro",
        "vih", "hiv", "sida", "aids", "hepatitis", "hépatite", "epatite",
        "diabetes", "diabète", "diabete", "depresión", "depression", "dépression",
        "depressione", "depressão", "esquizofrenia", "schizophrenia", "schizophrénie",
        "embarazo", "pregnancy", "grossesse", "schwangerschaft", "gravidanza", "gravidez",
        "alzhéimer", "alzheimer", "discapacidad", "disability", "behinderung",
        "handicap", "disabilità", "deficiência"]),
    ("RELIGIOUS_BELIEF", 0.55, [
        "católico", "catholic", "catholique", "cattolico", "católica",
        "musulmán", "muslim", "musulman", "musulmano", "muçulmano", "islam",
        "judío", "jewish", "juif", "ebreo", "judeu", "protestante", "protestant",
        "cristiano", "christian", "chrétien", "evangélico", "budista", "buddhist",
        "hindú", "hindu", "ateo", "atheist", "athée", "agnóstico"]),
    ("POLITICAL_OPINION", 0.5, [
        "socialista", "socialist", "socialiste", "comunista", "communist",
        "communiste", "conservador", "conservative", "anarquista", "anarchist",
        "fascista", "fascist", "republicano", "republican", "demócrata", "democrat",
        "nacionalista", "nationalist", "ecologista"]),
    ("ETHNIC_ORIGIN", 0.5, [
        "gitano", "roma", "romaní", "afroamericano", "afro-american",
        "árabe", "arab", "arabe", "asiático", "asian", "asiatique",
        "indígena", "indigenous", "latino", "hispano"]),
    ("SEXUAL_ORIENTATION", 0.6, [
        "homosexual", "gay", "lesbiana", "lesbian", "lesbienne", "bisexual",
        "heterosexual", "transgénero", "transgender", "transexual", "queer"]),
    ("TRADE_UNION", 0.55, [
        "sindicato", "union", "syndicat", "gewerkschaft", "sindacato", "sindicato",
        "afiliado sindical", "trade union", "ccoo", "ugt"]),
]


def build_analyzer():
    nlp = NlpEngineProvider(nlp_configuration=NLP_CONFIG).create_engine()
    registry = RecognizerRegistry(supported_languages=LANGUAGES)
    registry.load_predefined_recognizers(languages=LANGUAGES, nlp_engine=nlp)
    registry.supported_languages = list(LANGUAGES)
    # Register every custom recognizer for every language.
    cs_flags = re.MULTILINE | re.DOTALL                       # case-sensitive
    ci_flags = re.MULTILINE | re.DOTALL | re.IGNORECASE       # case-insensitive
    for entity, pats, ctx, case_sensitive in CUSTOM:
        patterns = [Pattern(name=n, regex=r, score=s) for (n, r, s) in pats]
        flags = cs_flags if case_sensitive else ci_flags
        for lang in LANGUAGES:
            registry.add_recognizer(PatternRecognizer(
                supported_entity=entity, patterns=patterns,
                context=ctx, supported_language=lang,
                global_regex_flags=flags,
            ))
    # Layer 1: GDPR Art. 9 special-category lexicons (explicit mentions).
    for entity, score, terms in SPECIAL_CATEGORIES:
        for lang in LANGUAGES:
            registry.add_recognizer(PatternRecognizer(
                supported_entity=entity, deny_list=terms,
                deny_list_score=score, supported_language=lang,
                global_regex_flags=ci_flags,
            ))
    # Layer 2: optional local zero-shot classifier for free-text special
    # categories (paraphrase). Heavy deps (transformers/torch); off by default.
    if os.environ.get("BLACKBAR_ENABLE_ZEROSHOT") == "1":
        try:
            from zeroshot import ZeroShotRecognizer
            for lang in LANGUAGES:
                registry.add_recognizer(ZeroShotRecognizer(supported_language=lang))
        except Exception as exc:  # pragma: no cover - optional feature
            print(f"[blackbar] zero-shot disabled: {exc}")
    return AnalyzerEngine(nlp_engine=nlp, registry=registry, supported_languages=LANGUAGES)


analyzer = build_analyzer()
app = Flask(__name__)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "languages": LANGUAGES,
                    "recognizers": len(analyzer.registry.recognizers)})


def _explain(r):
    """PII-safe slice of Presidio's decision process: which recognizer fired
    and which named pattern. Never the matched value. None if unavailable.

    Mirrored by ``presidio_client._explain`` on the client side; this service
    is a standalone artifact (own venv/Docker image) so the two cannot share an
    import. Keep the two in sync.
    """
    exp = getattr(r, "analysis_explanation", None)
    if not exp:
        return None
    recognizer = getattr(exp, "recognizer", None)
    pattern_name = getattr(exp, "pattern_name", None)
    if recognizer is None and pattern_name is None:
        return None
    return {"recognizer": recognizer, "pattern_name": pattern_name}


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(force=True) or {}
    text = data.get("text", "")
    language = data.get("language", "en")
    if language not in LANGUAGES:
        language = "en"
    decision = bool(data.get("return_decision_process"))
    results = analyzer.analyze(text=text, language=language,
                               entities=data.get("entities") or None,
                               return_decision_process=decision)
    out = []
    for r in results:
        item = {"entity_type": r.entity_type, "start": r.start,
                "end": r.end, "score": round(r.score, 3)}
        if decision:
            explanation = _explain(r)
            if explanation:
                item["analysis_explanation"] = explanation
        out.append(item)
    return jsonify(out)


if __name__ == "__main__":
    # Bind to localhost by default: this service processes PII, so it must not
    # be reachable from the LAN unless you opt in. In Docker the port mapping
    # requires binding all interfaces, so the image sets BLACKBAR_BIND_HOST=0.0.0.0.
    # An empty BLACKBAR_BIND_HOST (e.g. set but blank in CI templating) would make
    # Flask bind every interface; fall back to localhost so PII stays off the LAN.
    host = os.environ.get("BLACKBAR_BIND_HOST", "").strip() or "127.0.0.1"
    app.run(host=host, port=int(os.environ.get("PORT", "3000")), threaded=True)
