#!/usr/bin/env python3
"""Patch the Presidio analyzer configuration in place for multilingual use.

Starts from the configuration files that ship inside the base image and
*extends* them, so no predefined recognizer is lost:

  1. default.yaml            -> load a spaCy model for each language
  2. default_analyzer.yaml   -> declare all languages as supported
  3. default_recognizers.yaml-> register every recognizer for every language,
                                plus add Spanish DNI (NIF) and NIE recognizers

Run inside the Docker build (pyyaml ships with Presidio). The English model
(en_core_web_lg) already ships in the base image; only the others are added.
"""
import os
import yaml

LANGS = ["en", "es", "pt", "fr", "de", "it"]
SIZE = os.environ.get("BLACKBAR_MODEL_SIZE", "lg")

# English uses the web model that ships in the base image; the rest use news models.
MODELS = {"en": "en_core_web_lg"}
for lang in ("es", "pt", "fr", "de", "it"):
    MODELS[lang] = f"{lang}_core_news_{SIZE}"

# Spanish DNI/NIF context words to also boost detection in the other languages.
ES_CONTEXT = ["dni", "nif", "nie", "documento", "identidad"]


def conf_dir():
    try:
        import presidio_analyzer
        return os.path.join(os.path.dirname(presidio_analyzer.__file__), "conf")
    except Exception:
        return "/usr/bin/presidio-analyzer/presidio_analyzer/conf"


def resolve(env_var, default_name):
    """Prefer the path the service actually reads (env var), else the package conf."""
    return os.environ.get(env_var) or os.path.join(conf_dir(), default_name)


def load(path):
    with open(path) as fh:
        return yaml.safe_load(fh) or {}


def dump(obj, path):
    with open(path, "w") as fh:
        yaml.safe_dump(obj, fh, sort_keys=False, allow_unicode=True)


def patch_nlp():
    path = resolve("NLP_CONF_FILE", "default.yaml")
    cfg = load(path)
    cfg["models"] = [{"lang_code": l, "model_name": MODELS[l]} for l in LANGS]
    dump(cfg, path)  # ner_model_configuration (entity mapping) is preserved as-is
    return path


def patch_analyzer():
    path = resolve("ANALYZER_CONF_FILE", "default_analyzer.yaml")
    cfg = load(path)
    cfg["supported_languages"] = LANGS
    dump(cfg, path)
    return path


def patch_recognizers():
    path = resolve("RECOGNIZER_REGISTRY_CONF_FILE", "default_recognizers.yaml")
    cfg = load(path)
    cfg["supported_languages"] = LANGS
    recs = cfg.get("recognizers") or []

    for rec in recs:
        if not isinstance(rec, dict):
            continue
        langs = rec.get("supported_languages")
        # Entries shaped like [{language: en, context: [...]}] -> replicate to all langs
        if isinstance(langs, list) and langs and isinstance(langs[0], dict):
            present = {e.get("language") for e in langs if isinstance(e, dict)}
            template = next((e for e in langs if e.get("language") == "en"), langs[0])
            ctx = list(template.get("context", []) or [])
            for l in LANGS:
                if l not in present:
                    langs.append({"language": l, "context": list(ctx)})
        # Make sure the NER recognizer (if listed explicitly) covers every language
        name = rec.get("name") or rec.get("class_name")
        if name == "SpacyRecognizer" and "supported_languages" not in rec:
            rec["supported_languages"] = [{"language": l, "context": []} for l in LANGS]

    existing = {(r.get("name") or r.get("class_name")) for r in recs if isinstance(r, dict)}
    for name in ("EsNifRecognizer", "EsNieRecognizer"):  # Spanish DNI/NIF and NIE
        if name not in existing:
            recs.append({
                "name": name,
                "type": "predefined",
                "supported_languages": [{"language": "es", "context": list(ES_CONTEXT)}],
            })

    cfg["recognizers"] = recs
    dump(cfg, path)
    return path


if __name__ == "__main__":
    p1, p2, p3 = patch_nlp(), patch_analyzer(), patch_recognizers()
    print("[blackbar] languages :", ", ".join(LANGS))
    print("[blackbar] models    :", MODELS)
    print("[blackbar] patched   :", p1, p2, p3)
    print("[blackbar] added     : EsNifRecognizer, EsNieRecognizer (es)")
