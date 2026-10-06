# SecureShield FastAPI - image for Railway (Dockerfile builder)
# No secrets, no .env, no Alembic auto-migrate, no --reload.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000

WORKDIR /app

# System deps commonly needed by cryptography / asyncpg wheels on slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application source only (see .dockerignore)
COPY app ./app
COPY alembic ./alembic
COPY alembic.ini .

EXPOSE 8000

# Railway injects PORT; default 8000 for local runs
# --forwarded-allow-ips mirrors the app's TRUSTED_PROXIES (FG-167): uvicorn only believes X-Forwarded-* from those
# peers (default 127.0.0.1 when unset), never from arbitrary clients.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --proxy-headers --forwarded-allow-ips \"${TRUSTED_PROXIES:-127.0.0.1}\""]
