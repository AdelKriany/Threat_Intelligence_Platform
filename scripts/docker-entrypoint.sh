#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

# Export Python environment variables explicitly
export PYTHONPATH="/app/backend"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONUNBUFFERED=1

# Ensure PATH includes venv bin
export PATH="/app/.venv/bin:$PATH"

ENVIRONMENT=${ENVIRONMENT:-production}
DATABASE_URL=${DATABASE_URL:-}
REDIS_URL=${REDIS_URL:-}

wait_for_postgres() {
  echo "Waiting for Postgres to be available..."
  python - <<'PY'
import os, time
from urllib.parse import urlparse
import sys
url=os.environ.get('DATABASE_URL')
if not url:
    print('DATABASE_URL not set', file=sys.stderr); sys.exit(2)
p=urlparse(url)
host=p.hostname or 'localhost'
port=p.port or 5432
user=p.username or 'postgres'
password=p.password or ''
dbname=p.path.lstrip('/')
import psycopg
for i in range(60):
    try:
        conn=psycopg.connect(host=host, port=port, user=user, password=password, dbname=dbname, connect_timeout=2)
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
  python - <<'PY'
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

wait_for_postgres
wait_for_redis

# Change to backend directory for proper module resolution
cd /app/backend

# Run Alembic only for API (detect uvicorn in command arguments)
if [ "${ENVIRONMENT}" != "production" ]; then
  if [[ "$@" == *"uvicorn"* ]]; then
    echo "Running Alembic migrations (ENVIRONMENT=${ENVIRONMENT})..."
    cd /app && python -m alembic upgrade head || {
      echo "WARNING: Alembic migrations failed, but continuing startup..."
    }
    cd /app/backend
  fi
fi

echo "Executing: $@"
exec "$@"

