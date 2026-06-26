# ThreatLens

ThreatLens is a production-oriented threat intelligence platform foundation built with FastAPI, PostgreSQL, SQLAlchemy, Alembic, Redis, Celery, Docker, and pytest.

## Project overview

This repository implements Phase 1 of ThreatLens: the application foundation that can support future ingestion, enrichment, risk scoring, and reporting workflows. The focus is on clean architecture, modular packaging, environment-driven configuration, structured error handling, logging, and containerized infrastructure.

## Architecture overview

The application uses a layered structure:

- API layer: FastAPI routers and versioned endpoints
- Core layer: configuration, logging, and exception handling
- Database layer: SQLAlchemy engine/session management and Alembic migrations
- Workers layer: Celery app and example task
- Services / repositories / schemas: reserved for future domain logic

## Dependency management

This project uses a uv-compatible pyproject.toml definition. For local development, either:

- `uv sync --extra dev`
- or `python -m pip install -e .[dev]`

The dependency set favors mature production tools:

- FastAPI for the REST API layer
- SQLAlchemy and Alembic for persistence and schema evolution
- Redis and Celery for asynchronous infrastructure
- Pydantic Settings for environment-based configuration

## Folder structure

```text
ThreatLens/
  backend/
    app/
      api/
      core/
      database/
      models/
      repositories/
      schemas/
      services/
      utils/
      workers/
    tests/
  alembic/
  docs/
  scripts/
  docker-compose.yml
  Dockerfile
  pyproject.toml
  .env.example
  .pre-commit-config.yaml
```

## Installation

1. Create a virtual environment.
2. Install dependencies:
   - `python -m pip install -e .[dev]`
3. Copy the environment file:
   - `cp .env.example .env`

## Running locally

Start the API:

```bash
uvicorn app.main:create_app --host 0.0.0.0 --port 8000 --factory
```

Health endpoint:

```bash
curl http://127.0.0.1:8000/api/v1/health
```

Expected response:

```json
{"status": "ok"}
```

## Running with Docker

Build the images (optional, compose will build automatically when needed):

```bash
docker compose build
```

Start all services (development / production-like):

```bash
docker compose up --build
```

Stop and remove containers:

```bash
docker compose down
```

Developer commands

- Start (foreground):
  - `docker compose up`
- Stop: `docker compose down`
- Restart: `docker compose restart`
- Logs: `docker compose logs -f`
- API shell:
  - `docker compose exec api bash`
- PostgreSQL shell:
  - `docker compose exec postgres psql -U threatlens -d threatlens`
- Worker logs:
  - `docker compose logs -f celery-worker`
- Beat logs:
  - `docker compose logs -f celery-beat`

Services exposed (defaults):

- API: http://localhost:8000
- PostgreSQL: mapped host port 5433 -> container 5432
- Redis: mapped host port 6379 -> container 6379

Notes:
- The API container waits for Postgres and Redis to be healthy before running migrations and starting.
- In development (ENVIRONMENT=development) Alembic migrations run automatically during container startup.

## Ingestion engine

Phase 2 introduces a modular ingestion pipeline for collecting raw cybersecurity content from RSS sources and persisting it as raw articles.

### How it works

1. The feed registry defines enabled sources, URLs, polling intervals, and source types.
2. The RSS client fetches each source asynchronously with timeouts, retries, and a user agent.
3. The normalizer parses feed content and converts entries into a single internal article model.
4. The feed manager stores normalized articles in the raw article table while skipping exact duplicates via SHA-256 content hashes.
5. Celery beat schedules each enabled feed independently through the configured poll interval.

### Architecture diagram

```text
Feed Registry -> RSS Client -> Normalizer -> Feed Manager -> RawArticle table
                                \-> Logging / Errors -> Celery Beat
```

### Adding a new RSS source

Add a new feed entry to the registry with a name, URL, and poll interval, or set the INGESTION_FEEDS_JSON environment variable to a JSON array of feed definitions.

Example:

```json
[
  {
    "name": "Example Feed",
    "url": "https://example.com/feed.xml",
    "poll_interval_minutes": 15,
    "enabled": true
  }
]
```

### Data flow

- Raw feed XML/Atom content is fetched from the source.
- Each entry is normalized into a `NormalizedArticle` object.
- The object is persisted as a `RawArticle` record for future downstream phases.
- Duplicate content is skipped before storage.

## Development workflow

- Format code with `black .`
- Sort imports with `isort .`
- Lint with `ruff check .`
- Type check with `mypy backend`
- Run tests with `pytest`

## Testing

The repository includes a pytest smoke test for the health endpoint.

```bash
pytest
```
