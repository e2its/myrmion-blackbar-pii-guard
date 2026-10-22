# Build & publish a custom Presidio image

The default setup uses Microsoft's official analyzer image
(`mcr.microsoft.com/presidio-analyzer`). You only need your own image when you
want to **add value** — extra languages, or recognizers for your organization's
own identifiers (employee IDs, internal hostnames, customer formats). Mirroring
the official image verbatim is rarely worth it.

## When it makes sense

- **Custom recognizers / languages** (e.g. Spanish DNI/NIF, internal ID regexes) — the real reason to publish.
- **Air-gapped or pinned** environments, or a corporate policy requiring an internal registry — a controlled mirror.
- Otherwise: just use `mcr.microsoft.com/presidio-analyzer` directly.

## Build a custom analyzer

Inherit from the official image, add models and your recognizer config:

```dockerfile
# Dockerfile
FROM mcr.microsoft.com/presidio-analyzer:latest
USER root
RUN python -m spacy download es_core_news_lg
COPY default.yaml             /usr/bin/presidio-analyzer/presidio_analyzer/conf/default.yaml
COPY default_recognizers.yaml /usr/bin/presidio-analyzer/presidio_analyzer/conf/default_recognizers.yaml
USER 1001
```

Build multi-arch (Apple Silicon dev → Linux server) and push:

```bash
docker login -u e2its
docker buildx create --use            # once
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t e2its/presidio-analyzer-es:0.1.0 \
  -t e2its/presidio-analyzer-es:latest \
  --push .
```

## Public vs private

If your recognizer config encodes internal PII patterns (employee/customer ID
regexes, internal hostnames), that config is itself sensitive — use a **private**
repository. A generic mirror can be public. Docker Hub's free tier includes one
private repo; for more, consider GitHub Container Registry (`ghcr.io`), which
offers free private repos.

## Point blackbar at your image

Claude Code (`plugins/blackbar/docker-compose.yml`):

```yaml
services:
  presidio-analyzer:
    image: e2its/presidio-analyzer-es:0.1.0   # was mcr.microsoft.com/presidio-analyzer:latest
    ports:
      - "127.0.0.1:5002:3000"
```

Claude Desktop: set the **Presidio Analyzer URL** in the extension settings (it
still points at `http://localhost:5002`, you've just changed which image serves
it). For a private image, run `docker login` on the host before `docker compose up`.

Nothing else changes — both halves keep talking to `http://localhost:5002/analyze`.
