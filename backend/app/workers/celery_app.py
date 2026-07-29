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
    imports=("app.ingestion.enrichment.tasks",),
)

celery_app.autodiscover_tasks(["app"], related_name="scheduler")


def configure_beat_schedule() -> None:
    """Load the ingestion beat schedule once the Celery app is initialized."""

    from app.ingestion.scheduler import build_beat_schedule

    celery_app.conf.beat_schedule = build_beat_schedule()
    if settings.enrichment_enabled:
        celery_app.conf.beat_schedule["refresh-expired-enrichments"] = {
            "task": "app.ingestion.enrichment.tasks.enrich_pending_batch_task",
            "schedule": settings.enrichment_refresh_interval_minutes * 60,
            "args": (settings.enrichment_batch_size, "nvd"),
        }
        if settings.cisa_kev_enabled:
            celery_app.conf.beat_schedule["refresh-cisa-kev"] = {
                "task": "app.ingestion.enrichment.tasks.refresh_kev_catalog_task",
                "schedule": settings.cisa_kev_refresh_interval_minutes * 60,
                "args": (settings.enrichment_batch_size, True),
            }
        if settings.epss_enabled:
            celery_app.conf.beat_schedule["refresh-epss"] = {
                "task": "app.ingestion.enrichment.tasks.refresh_epss_batch_task",
                "schedule": settings.epss_refresh_interval_minutes * 60,
                "args": (settings.enrichment_batch_size,),
            }
        celery_app.conf.beat_schedule["phase5-coverage"] = {
            "task": "app.ingestion.enrichment.tasks.phase5_coverage_task",
            "schedule": 86400,
        }


configure_beat_schedule()
