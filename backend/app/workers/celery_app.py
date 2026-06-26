from celery import Celery

from app.core.config import settings

celery_app = Celery(
    "threatlens",
    broker=settings.redis_url,
    backend=settings.redis_url,
)
celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
)

celery_app.autodiscover_tasks(["app"], related_name="scheduler")


def configure_beat_schedule() -> None:
    """Load the ingestion beat schedule once the Celery app is initialized."""

    from app.ingestion.scheduler import build_beat_schedule

    celery_app.conf.beat_schedule = build_beat_schedule()


configure_beat_schedule()
