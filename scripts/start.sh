#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
  if [ -f .env.example ]; then
    cp .env.example .env
    echo "Created .env from .env.example"
  else
    echo "ERROR: .env.example not found"
    exit 1
  fi
fi

if [ ! -d .venv ]; then
  python3 -m venv .venv
  echo "Created Python virtual environment at .venv"
fi

VENV_DIR="$PWD/.venv"
PATH="$VENV_DIR/bin:$PATH"

"$VENV_DIR/bin/python" -m pip install --upgrade pip setuptools wheel
"$VENV_DIR/bin/python" -m pip install --no-cache-dir -e .

echo "Running database migrations..."
"$VENV_DIR/bin/alembic" upgrade head

echo "Starting local development server on http://0.0.0.0:8000"
exec "$VENV_DIR/bin/uvicorn" app.main:create_app --host 0.0.0.0 --port 8000 --reload --factory
