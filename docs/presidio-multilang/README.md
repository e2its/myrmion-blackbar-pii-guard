# Multilingual Presidio analyzer

The default `mcr.microsoft.com/presidio-analyzer` image ships **English only**, so
any request with `language=es` (or pt/fr/de/it) returns `HTTP 500`. This image adds
five more languages and a Spanish national-ID recognizer.

| | |
| --- | --- |
| **Languages** | English, Spanish, Portuguese, French, German, Italian |
| **Detects** (NER) | PERSON, LOCATION, NRP, ORGANIZATION in all six languages |
| **Spanish IDs** | DNI/NIF and NIE (`EsNifRecognizer`, `EsNieRecognizer`) |
| **Plus** | every predefined recognizer (email, phone, credit card, IBAN, IP…) extended to all six languages |

## How it works

The build doesn't hand-write the recognizer list (that would drop predefined
recognizers). Instead `patch_conf.py` runs during the build, loads the three
config files that ship inside the base image, and *extends* them:

1. `default.yaml` — one spaCy model per language.
2. `default_analyzer.yaml` — all six languages marked supported.
3. `default_recognizers.yaml` — each recognizer registered for each language, plus the two Spanish ID recognizers.

The English NER model (`en_core_web_lg`) already ships in the base image; only the
other five are downloaded.

## Build & run

```bash
cd docs/presidio-multilang

# full accuracy (large image, ~3 GB — five lg models)
docker compose up --build -d

# OR a much smaller image (medium models): edit MODEL_SIZE: md in
# docker-compose.yml, or build directly:
docker build --build-arg MODEL_SIZE=md -t e2its/presidio-analyzer-multilang:md .
docker run -d -p 5002:3000 e2its/presidio-analyzer-multilang:md
```

The first build is slow (downloading models). After that it's cached.

## Test each language

```bash
# Spanish — name, location and DNI
curl -s -X POST localhost:5002/analyze -H 'Content-Type: application/json' \
  -d '{"text":"Me llamo Ada Lovelace, vivo en Madrid, DNI 12345678Z","language":"es"}' | python3 -m json.tool

# Portuguese / French / German / Italian
curl -s -X POST localhost:5002/analyze -H 'Content-Type: application/json' \
  -d '{"text":"Je m'\''appelle Ada Lovelace et j'\''habite à Paris","language":"fr"}' | python3 -m json.tool
```

You should see `PERSON` and `LOCATION` entities, and for the Spanish example an
`ES_NIF` entity for the DNI.

## Point blackbar at it

Nothing else changes — the image still serves `http://localhost:5002/analyze`.

- **Claude Code (plugin):** set the language before launching `claude`, e.g.
  `export PRESIDIO_GUARD_LANGUAGE=es`, or pass `language` directly to the
  `presidio_analyze` / `presidio_anonymize` tools per call.
- **Replace the analyzer service** the plugin starts by pointing
  `plugins/blackbar/docker-compose.yml` at `e2its/presidio-analyzer-multilang`
  instead of the stock image.
- **Publish it** (optional) to your registry so you don't rebuild on every machine:
  `docker tag e2its/presidio-analyzer-multilang:latest <registry>/...` then `docker push`.

## Honest caveats

- **Image size:** five `lg` models make a ~3 GB image. Use `MODEL_SIZE=md` for ~10× smaller with a modest accuracy drop.
- **Context words:** the predefined recognizers are replicated to every language reusing their English context words. Detection still works (patterns are language-agnostic); only the context-based score *boost* is approximate outside English. Tune `patch_conf.py` if you need native context words.
- **NER quality** varies by language and model size; keep a human in the loop for regulated data.
- **DNI vs NIF:** `EsNifRecognizer` covers the DNI/NIF number+letter (with checksum); `EsNieRecognizer` covers NIE. Both are Presidio predefined recognizers.
