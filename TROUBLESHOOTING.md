Troubleshooting Guide

PostgreSQL not starting
- Cause: incorrect environment variables, port collision, or corrupted data volume.
- Diagnosis: docker compose logs postgres; docker compose exec postgres psql -U threatlens -d threatlens
- Solution: ensure POSTGRES_* env vars are correct in .env, remove conflicting host port (5433), inspect postgres_data volume, restore from backup or remove volume and re-init: `docker compose down -v && docker compose up --build`.

Redis unavailable
- Cause: container crashed, network name mismatch, or wrong REDIS_URL.
- Diagnosis: docker compose logs redis; docker compose exec redis redis-cli ping
- Solution: check REDIS_URL uses host 'redis' and port 6379; restart service: `docker compose restart redis`.

Celery cannot connect
- Cause: Redis unavailable, incorrect broker URL, or worker start ordering.
- Diagnosis: docker compose logs celery-worker; inspect error traces for connection refused.
- Solution: verify REDIS_URL env (redis://redis:6379/0), ensure redis service healthy, restart worker: `docker compose restart celery-worker`.

API startup failure
- Cause: missing env vars, DB unreachable, pending alembic errors, or code errors.
- Diagnosis: docker compose logs api; docker compose exec api bash and run `/app/.venv/bin/python -m uvicorn app.main:create_app --factory` to reproduce.
- Solution: confirm DATABASE_URL points to postgres service, check alembic output in logs; run migrations manually inside container: `docker compose exec api /app/.venv/bin/alembic upgrade head`.

Alembic migration failure
- Cause: incompatible schema changes, DB permissions, or missing migrations.
- Diagnosis: check `docker compose logs api` and alembic tracebacks.
- Solution: inspect migration files in alembic/versions, run `docker compose exec api /app/.venv/bin/alembic history` and `alembic current`; fix migration script or DB state, then run `alembic upgrade head`.

RSS fetch failure
- Cause: network egress blocked, invalid feed URL, or feed parser errors.
- Diagnosis: check celery-worker and celery-beat logs for fetch errors; run `docker compose logs -f celery-worker`.
- Solution: verify network connectivity from worker container: `docker compose exec celery-worker ping -c 1 example.com`; add proxies if needed; validate feed URL manually with curl inside container.

Duplicate detection
- Cause: ingestion dedup relies on content hashing; duplicates indicate hash collision or identical content.
- Diagnosis: inspect raw_articles and hashing logic in feed manager; query database for similar hashes.
- Solution: ensure dedup uses SHA-256 and includes canonicalized content; if false positives occur, adjust normalization logic.

Environment variables missing
- Cause: .env not present or misconfigured.
- Diagnosis: check `docker compose config` to see resolved env values; `docker compose exec api env | grep DATABASE_URL`.
- Solution: copy `.env.example` to `.env` and set values. Defaults provided in .env point to service names (postgres, redis). Restart compose after changes.

General tips
- Use `docker compose logs -f` to tail all logs.
- Use `docker compose ps` to see container status and health checks.
- Use named volumes to persist DB and Redis data between restarts.
