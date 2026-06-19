# Multi-language Presidio analyzer: English, Spanish, French, German, Italian, Portuguese.
# en_core_web_lg ships in the base image; the other five are added here.
FROM mcr.microsoft.com/presidio-analyzer:latest
USER root
RUN python -m spacy download es_core_news_lg \
 && python -m spacy download fr_core_news_lg \
 && python -m spacy download de_core_news_lg \
 && python -m spacy download it_core_news_lg \
 && python -m spacy download pt_core_news_lg
COPY default.yaml /app/presidio_analyzer/conf/default.yaml
USER 1001
