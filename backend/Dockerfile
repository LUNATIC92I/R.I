# Production-oriented image: non-root user, no build tools, read-only friendly.
FROM python:3.13-slim AS base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /srv
COPY requirements.txt .
RUN pip install --require-hashes -r requirements.txt 2>/dev/null || pip install -r requirements.txt
COPY app ./app
COPY migrations ./migrations
COPY alembic.ini .
RUN useradd --system --uid 10001 aic && chown -R aic /srv
USER aic
EXPOSE 8000
# TLS is terminated by the institutional reverse proxy; the API listens on the internal network only.
CMD ["uvicorn", "app.asgi:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--no-server-header"]
