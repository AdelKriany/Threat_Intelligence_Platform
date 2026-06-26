# syntax=docker/dockerfile:1

# Builder stage: use uv image to create an isolated venv with pinned deps
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS builder
WORKDIR /app
COPY pyproject.toml ./
COPY backend backend
# Create the virtualenv and install dependencies (production: no dev extras)
RUN uv lock --force && uv sync --frozen --no-dev

# Runtime stage: small base image
FROM python:3.12-slim-bookworm AS runtime

# Create a non-root user for better security
RUN groupadd -r app && useradd -r -g app -m -d /home/app app

WORKDIR /app
# Copy the pre-built virtualenv from builder
COPY --from=builder /app/.venv /app/.venv
# Copy application code
COPY backend backend
COPY scripts scripts

# Make entrypoint executable
RUN chmod +x /app/scripts/docker-entrypoint.sh

# Ensure venv binaries are on PATH
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONPATH="/app/backend" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Fix permissions so non-root user can read files
RUN chown -R app:app /app
USER app

EXPOSE 8000

# Use the docker entrypoint script to wait for dependencies, run alembic (dev), then start
ENTRYPOINT ["/app/scripts/docker-entrypoint.sh"]
CMD []
