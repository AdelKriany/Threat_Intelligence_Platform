from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from app.core.config import settings
from app.services.event_scoring_backfill import EventScoreBackfillItem, EventScoreBackfillResult
from app.workers import event_scoring_tasks
from app.workers.celery_app import celery_app, configure_beat_schedule

NOW = datetime(2026, 9, 29, 12, tzinfo=UTC)


class TrackingSession:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    def __enter__(self) -> TrackingSession:
        self.events.append("session_enter")
        return self

    def __exit__(self, *args: object) -> None:
        self.events.append("session_exit")

    def commit(self) -> None:
        self.events.append("commit")

    def rollback(self) -> None:
        self.events.append("rollback")


def _result(*, has_more: bool) -> EventScoreBackfillResult:
    return EventScoreBackfillResult(
        mode="apply",
        limit=2,
        after_id=0,
        scanned=1,
        scoreable=1,
        unsupported=0,
        malformed=0,
        unscorable=0,
        first_scanned_id=1,
        last_scanned_id=1,
        next_after_id=1 if has_more else None,
        has_more=has_more,
        scores_would_create=1,
        scores_would_reuse=0,
        scores_created=1,
        scores_reused=0,
        items=(EventScoreBackfillItem(1, "cve:CVE-2026-99001", "created", score="74.50"),),
    )


def _allow_lock(monkeypatch: pytest.MonkeyPatch, events: list[str]) -> None:
    monkeypatch.setattr(
        event_scoring_tasks,
        "acquire_task_lock",
        lambda name, ttl: (object(), "token"),
    )
    monkeypatch.setattr(
        event_scoring_tasks,
        "release_task_lock",
        lambda client, name, token: events.append("release"),
    )


def test_task_commits_one_page_then_enqueues_next_cursor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    session = TrackingSession(events)
    _allow_lock(monkeypatch, events)
    monkeypatch.setattr(event_scoring_tasks, "SessionLocal", lambda: session)

    def backfill(current_session: object, **kwargs: Any) -> EventScoreBackfillResult:
        assert current_session is session
        assert kwargs == {"apply": True, "limit": 2, "after_id": 0, "as_of": NOW}
        events.append("backfill")
        return _result(has_more=True)

    monkeypatch.setattr(event_scoring_tasks, "backfill_event_scores", backfill)
    monkeypatch.setattr(
        event_scoring_tasks.score_event_page_task,
        "apply_async",
        lambda **kwargs: events.append(
            f"enqueue:{kwargs['kwargs']['after_id']}:{kwargs['kwargs']['as_of']}"
        ),
    )

    payload = event_scoring_tasks.score_event_page_task.run(
        limit=2,
        after_id=0,
        as_of=NOW.isoformat(),
    )

    assert payload["continuation_enqueued"] is True
    assert payload["scores_created"] == 1
    assert events == [
        "session_enter",
        "backfill",
        "commit",
        "session_exit",
        "release",
        f"enqueue:1:{NOW.isoformat()}",
    ]


def test_task_final_page_commits_without_enqueue(monkeypatch: pytest.MonkeyPatch) -> None:
    events: list[str] = []
    _allow_lock(monkeypatch, events)
    monkeypatch.setattr(
        event_scoring_tasks,
        "SessionLocal",
        lambda: TrackingSession(events),
    )
    monkeypatch.setattr(
        event_scoring_tasks,
        "backfill_event_scores",
        lambda *args, **kwargs: _result(has_more=False),
    )
    monkeypatch.setattr(
        event_scoring_tasks.score_event_page_task,
        "apply_async",
        lambda **kwargs: pytest.fail("final page must not enqueue another task"),
    )

    payload = event_scoring_tasks.score_event_page_task.run(as_of=NOW.isoformat())

    assert payload["continuation_enqueued"] is False
    assert events == ["session_enter", "commit", "session_exit", "release"]


def test_task_rolls_back_releases_lock_and_does_not_continue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    _allow_lock(monkeypatch, events)
    monkeypatch.setattr(
        event_scoring_tasks,
        "SessionLocal",
        lambda: TrackingSession(events),
    )

    def fail(*args: object, **kwargs: object) -> EventScoreBackfillResult:
        events.append("backfill")
        raise RuntimeError("page failed")

    monkeypatch.setattr(event_scoring_tasks, "backfill_event_scores", fail)
    monkeypatch.setattr(
        event_scoring_tasks.score_event_page_task,
        "apply_async",
        lambda **kwargs: pytest.fail("failed page must not enqueue another task"),
    )

    with pytest.raises(RuntimeError, match="page failed"):
        event_scoring_tasks.score_event_page_task.run(as_of=NOW.isoformat())

    assert events == ["session_enter", "backfill", "rollback", "session_exit", "release"]


def test_task_skips_when_another_page_owns_the_lock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        event_scoring_tasks,
        "acquire_task_lock",
        lambda name, ttl: (object(), None),
    )
    monkeypatch.setattr(
        event_scoring_tasks,
        "SessionLocal",
        lambda: pytest.fail("lock contention must not open a database session"),
    )

    payload = event_scoring_tasks.score_event_page_task.run(limit=25, after_id=100)

    assert payload == {
        "status": "skipped",
        "reason": "event_scoring_backfill_already_running",
        "limit": 25,
        "after_id": 100,
    }


def test_task_rejects_invalid_timestamp_before_acquiring_lock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        event_scoring_tasks,
        "acquire_task_lock",
        lambda *args: pytest.fail("invalid input must not acquire the task lock"),
    )

    with pytest.raises(ValueError):
        event_scoring_tasks.score_event_page_task.run(as_of="not-a-timestamp")


def test_task_is_registered_and_schedule_requires_explicit_enablement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_schedule = celery_app.conf.beat_schedule
    try:
        assert event_scoring_tasks.TASK_NAME in celery_app.tasks

        monkeypatch.setattr(settings, "event_scoring_schedule_enabled", False)
        configure_beat_schedule()
        assert "score-exact-cve-events" not in celery_app.conf.beat_schedule

        monkeypatch.setattr(settings, "event_scoring_schedule_enabled", True)
        monkeypatch.setattr(settings, "event_scoring_schedule_interval_minutes", 15)
        monkeypatch.setattr(settings, "event_scoring_page_limit", 40)
        configure_beat_schedule()

        scheduled = celery_app.conf.beat_schedule["score-exact-cve-events"]
        assert scheduled == {
            "task": event_scoring_tasks.TASK_NAME,
            "schedule": 900,
            "kwargs": {"limit": 40, "after_id": 0},
        }
    finally:
        celery_app.conf.beat_schedule = original_schedule
