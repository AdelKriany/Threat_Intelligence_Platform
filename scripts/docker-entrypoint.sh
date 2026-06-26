#!/usr/bin/env bash
set -euo pipefail

# Ensure working dir is project root
cd "$(dirname "$0")/.."

# Ensure virtualenv bin is on PATH (created during image build)
VENV_BIN=/app/.venv/bin
export PATH="$VENV_BIN:$PATH"

# Read settings
ENVIRONMENT=${ENVIRONMENT:-production}
DATABASE_URL=${DATABASE_URL:-}
REDIS_URL=${REDIS_URL:-}

# Helper: wait for Postgres using a small Python loop (psycopg is installed in the image)
wait_for_postgres() {
  echo "Waiting for Postgres to be available..."
  /app/.venv/bin/python - <<'PY'
import os, time
from urllib.parse import urlparse
import sys
url=os.environ.get('DATABASE_URL')
if not url:
    print('DATABASE_URL not set', file=sys.stderr); sys.exit(2)
# Expect postgresql+psycopg://user:pass@host:port/db
p=urlparse(url)
host=p.hostname or 'localhost'
port=p.port or 5432
user=p.username or 'postgres'
import psycopg
for i in range(60):
    try:
        conn=psycopg.connect(host=host, port=port, user=user, dbname=p.path.lstrip('/'), connect_timeout=2)
        conn.close()
        print('Postgres is available')
        sys.exit(0)
    except Exception as e:
        print('Postgres not ready yet:', e)
        time.sleep(1)
print('Timed out waiting for Postgres', file=sys.stderr)
sys.exit(1)
PY
}

wait_for_redis() {
  echo "Waiting for Redis to be available..."
  /app/.venv/bin/python - <<'PY'
import os, time, sys
from urllib.parse import urlparse
import redis
url=os.environ.get('REDIS_URL')
if not url:
    print('REDIS_URL not set', file=sys.stderr); sys.exit(2)
p=urlparse(url)
host=p.hostname or 'localhost'
port=p.port or 6379
for i in range(60):
    try:
        r=redis.Redis(host=host, port=port, socket_connect_timeout=2)
        if r.ping():
            print('Redis is available')
            sys.exit(0)
    except Exception as e:
        print('Redis not ready yet:', e)
    time.sleep(1)
print('Timed out waiting for Redis', file=sys.stderr)
sys.exit(1)
PY
}

# Only run waits when not using sqlite or similar, but safe to always check.
wait_for_postgres
wait_for_redis

# Run alembic migrations automatically in non-production environments
if [ "${ENVIRONMENT}" != "production" ]; then
  echo "Running Alembic migrations (ENVIRONMENT=${ENVIRONMENT})..."
  /app/.venv/bin/alembic upgrade head
fi

# Finally start the appropriate service (by delegating to uv entrypoint or passed command)
# If user passed a command, run it. Otherwise default to starting uvicorn via uv wrapper
if [ "$#" -gt 0 ]; then
  echo "Executing: $@"
  exec "$@"
else
  echo "Starting API (uvicorn)..."
  exec /app/.venv/bin/uv run uvicorn app.main:create_app --host 0.0.0.0 --port 8000 --factory
fi
