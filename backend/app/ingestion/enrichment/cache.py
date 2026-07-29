from __future__ import annotations

import json
import logging
import secrets
from typing import Any, Protocol

import redis
import redis.asyncio as async_redis
from redis.exceptions import RedisError

from app.core.config import settings

logger = logging.getLogger(__name__)


class AsyncJSONCache(Protocol):
    async def get_json(self, key: str) -> dict[str, Any] | None: ...

    async def set_json(self, key: str, value: dict[str, Any], ttl_seconds: int) -> None: ...

    async def acquire_lock(self, key: str, ttl_seconds: int) -> str | None: ...

    async def release_lock(self, key: str, token: str) -> None: ...


class RedisEnrichmentCache:
    """Small fail-open Redis adapter for shared provider payloads and locks."""

    namespace = "threatlens:enrichment"

    def __init__(self, url: str = settings.redis_url) -> None:
        self.url = url

    def _client(self) -> async_redis.Redis:
        return async_redis.Redis.from_url(self.url, decode_responses=True)

    async def get_json(self, key: str) -> dict[str, Any] | None:
        client = self._client()
        try:
            value = await client.get(self._key(key))
            if value is None:
                return None
            decoded = json.loads(value)
            return decoded if isinstance(decoded, dict) else None
        except (RedisError, ValueError, TypeError):
            logger.warning("Enrichment cache read failed key=%s", key)
            return None
        finally:
            await client.aclose()

    async def set_json(self, key: str, value: dict[str, Any], ttl_seconds: int) -> None:
        client = self._client()
        try:
            encoded = json.dumps(value, separators=(",", ":"), allow_nan=False)
            await client.set(self._key(key), encoded, ex=max(1, ttl_seconds))
        except (RedisError, ValueError, TypeError):
            logger.warning("Enrichment cache write failed key=%s", key)
        finally:
            await client.aclose()

    async def acquire_lock(self, key: str, ttl_seconds: int) -> str | None:
        token = secrets.token_hex(16)
        client = self._client()
        try:
            acquired = await client.set(
                self._key(f"lock:{key}"),
                token,
                ex=max(1, ttl_seconds),
                nx=True,
            )
            return token if acquired else None
        except RedisError:
            # Cache failure must not prevent authoritative PostgreSQL updates.
            logger.warning("Enrichment cache lock unavailable key=%s", key)
            return f"redis-unavailable:{token}"
        finally:
            await client.aclose()

    async def release_lock(self, key: str, token: str) -> None:
        if token.startswith("redis-unavailable:"):
            return
        client = self._client()
        script = """
        if redis.call('get', KEYS[1]) == ARGV[1] then
            return redis.call('del', KEYS[1])
        end
        return 0
        """
        try:
            await client.eval(script, 1, self._key(f"lock:{key}"), token)
        except RedisError:
            logger.warning("Enrichment cache lock release failed key=%s", key)
        finally:
            await client.aclose()

    def _key(self, key: str) -> str:
        return f"{self.namespace}:{key}"


def acquire_task_lock(name: str, ttl_seconds: int) -> tuple[redis.Redis | None, str | None]:
    """Acquire a synchronous task lock, failing open if Redis is unavailable."""

    client = redis.Redis.from_url(settings.redis_url, decode_responses=True)
    key = f"{RedisEnrichmentCache.namespace}:lock:task:{name}"
    token = secrets.token_hex(16)
    try:
        return (
            (client, token)
            if client.set(key, token, ex=max(1, ttl_seconds), nx=True)
            else (
                client,
                None,
            )
        )
    except RedisError:
        logger.warning("Periodic task lock unavailable task=%s", name)
        return None, f"redis-unavailable:{token}"


def release_task_lock(client: redis.Redis | None, name: str, token: str | None) -> None:
    if client is None or token is None or token.startswith("redis-unavailable:"):
        return
    key = f"{RedisEnrichmentCache.namespace}:lock:task:{name}"
    try:
        if client.get(key) == token:
            client.delete(key)
    except RedisError:
        logger.warning("Periodic task lock release failed task=%s", name)
