# API Gateway — production image.
FROM python:3.11-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Dependencies first so the layer caches across code changes.
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY features ./features
COPY app ./app
COPY sdk ./sdk
COPY run.py ./

RUN useradd --create-home --uid 10001 apigw && \
    chown -R apigw:apigw /app
USER apigw

ENV APIGW_PORT=8000
EXPOSE 8000

# Readiness (not liveness): the orchestrator should also probe /health/live.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import os,urllib.request,sys; \
url=f\"http://127.0.0.1:{os.getenv('APIGW_PORT','8000')}/health/live\"; \
sys.exit(0 if urllib.request.urlopen(url, timeout=4).status == 200 else 1)"

# Every request here is I/O-bound (one upstream hop), so a single process with
# a large event loop goes a long way. Scale with replicas rather than workers:
# the rate limiter and usage counters are per-process unless GATEWAY_MONGO_URI
# is set, and more workers silently multiply the effective limits.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${APIGW_PORT:-8000} --workers ${APIGW_WORKERS:-1}"]
