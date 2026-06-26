from __future__ import annotations

import logging
from datetime import timedelta

from celery import shared_task

from app.ingestion.registry import FeedRegistry, FeedSource
from app.ingestion.services import IngestionService

logger = logging.getLogger(__name__)


@shared_task(name="app.ingestion.scheduler.run_ingestion_task")
def run_ingestion_task(feed_name: str | None = None) -> dict[str, int]:
    """Execute the ingestion pipeline for one or all configured feeds."""

    registry = FeedRegistry.from_settings()
    service = IngestionService(registry=registry)
    if feed_name:
        registry._sources = [source for source in registry._sources if source.name == feed_name]
    return service.run_all()


def build_beat_schedule(registry: FeedRegistry | None = None) -> dict[str, dict]:
    """Create a beat schedule from the configured feed registry."""

    configured_registry = registry or FeedRegistry.from_settings()
    schedule: dict[str, dict] = {}
    for source in configured_registry.get_enabled_sources():
        schedule[f"ingest-{source.name.lower().replace(' ', '-')}"] = {
            "task": "app.ingestion.scheduler.run_ingestion_task",
            "schedule": timedelta(minutes=source.poll_interval_minutes),
            "args": (source.name,),
        }
    return schedule

