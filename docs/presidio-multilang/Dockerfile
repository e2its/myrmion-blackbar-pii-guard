# blackbar — multilingual Presidio analyzer
# Languages: English, Spanish, Portuguese, French, German, Italian (+ Spanish DNI/NIE)
#
#   docker build -t e2its/presidio-analyzer-multilang:latest .
#   # smaller/faster image (medium models, ~50 MB each instead of ~500 MB):
#   docker build --build-arg MODEL_SIZE=md -t e2its/presidio-analyzer-multilang:md .
#   docker run -d -p 5002:3000 e2its/presidio-analyzer-multilang:latest
#
FROM mcr.microsoft.com/presidio-analyzer:latest

# "lg" = best accuracy, large image. "md" = much smaller, slightly lower recall.
ARG MODEL_SIZE=lg
USER root

# English (en_core_web_lg) already ships in the base image.
# Add Spanish, Portuguese, French, German and Italian news models.
RUN set -eux; \
    for lang in es pt fr de it; do \
      python -m spacy download ${lang}_core_news_${MODEL_SIZE}; \
    done

# Rewrite the analyzer config in place: declare all six languages, extend every
# predefined recognizer to them, and add Spanish DNI (NIF) and NIE recognizers.
ENV BLACKBAR_MODEL_SIZE=${MODEL_SIZE}
COPY patch_conf.py /tmp/patch_conf.py
RUN python /tmp/patch_conf.py

# Note: this image runs the analyzer as root for simplicity. It is meant to run
# locally on your own machine; harden the user/permissions before any shared use.
