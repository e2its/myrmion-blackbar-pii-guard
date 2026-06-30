# blackbar analyzer image.
#
# Runs the SAME analyzer_service.py as the native path (this directory), so the
# Docker and no-Docker deployments detect identically. Builds on the official
# Presidio analyzer base (Python + presidio-analyzer), adds the spaCy models for
# the chosen languages, Flask, and the service.
#
#   # default: en,es,fr,de,it,pt at md (~1.3 GB)
#   docker build -t e2its/presidio-analyzer-multilang:latest .
#   # large models, higher recall:
#   docker build --build-arg MODEL_SIZE=lg -t e2its/presidio-analyzer-multilang:lg .
#   # just two languages:
#   docker build --build-arg LANGS="en,es" -t presidio-en-es .
#
# Served on container port 3000 (compose maps host 5002:3000).
FROM mcr.microsoft.com/presidio-analyzer:latest
USER root

ARG LANGS="en,es,fr,de,it,pt"
ARG MODEL_SIZE="md"

RUN set -eux; \
    for lang in $(echo "$LANGS" | tr ',' ' '); do \
      if [ "$lang" = "en" ]; then model="en_core_web_${MODEL_SIZE}"; \
      else model="${lang}_core_news_${MODEL_SIZE}"; fi; \
      python -m spacy download "$model"; \
    done

RUN pip install --no-cache-dir "flask>=3.0"

COPY analyzer_service.py /app/analyzer_service.py

# In a container the app must bind all interfaces, otherwise the host can't
# reach it through the compose port map (5002:3000). The native path keeps the
# safe 127.0.0.1 default from analyzer_service.py.
ENV BLACKBAR_LANGUAGES=$LANGS \
    BLACKBAR_MODEL_SIZE=$MODEL_SIZE \
    BLACKBAR_BIND_HOST=0.0.0.0 \
    PORT=3000

USER 1001
ENTRYPOINT []
CMD ["python", "/app/analyzer_service.py"]
