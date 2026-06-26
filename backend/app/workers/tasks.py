from app.workers.celery_app import celery_app


@celery_app.task(name="app.workers.tasks.ping")
def ping() -> str:
    """Return a simple placeholder task result for Celery wiring."""

    return "pong"
