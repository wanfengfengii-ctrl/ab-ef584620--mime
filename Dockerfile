# Strict MIME audit service -- dependency-free Python standard library only.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MIME_AUDIT_HOST=0.0.0.0 \
    MIME_AUDIT_PORT=8080

WORKDIR /app

# Application, tests and the one-shot verification script.
COPY mimeaudit ./mimeaudit
COPY tests ./tests
COPY scripts ./scripts

# Run as an unprivileged user.
RUN useradd --create-home --uid 10001 appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8080

# Container-level liveness probe (uses the stdlib, no extra package needed).
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 \
    CMD python -c "import json,urllib.request,sys; r=urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=3); sys.exit(0 if r.status==200 and json.load(r)['status']=='ok' else 1)"

CMD ["python", "-m", "mimeaudit"]
