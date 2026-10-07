# syntax=docker/dockerfile:1
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /srv
COPY app ./app

RUN useradd --system --uid 10001 --home /srv mimeaudit \
    && chown -R mimeaudit:mimeaudit /srv
USER mimeaudit

EXPOSE 8080

# Default: run the audit service. The compose `verify` service overrides the
# command with `python -m app.verify`.
CMD ["python", "-m", "app.main"]
