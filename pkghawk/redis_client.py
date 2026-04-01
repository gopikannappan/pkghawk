from __future__ import annotations

import json
import logging
import time

import redis.asyncio as redis

from pkghawk.config import (
    DEDUP_TTL_SECONDS,
    MAX_EVENTS,
    REDIS_CHANNEL,
    REDIS_DEDUP_PREFIX,
    REDIS_EVENTS_KEY,
    REDIS_SOURCE_HEALTH_PREFIX,
    REDIS_URL,
)
from pkghawk.schema import PkgHawkEvent

logger = logging.getLogger(__name__)

_pool: redis.Redis | None = None


async def get_redis() -> redis.Redis:
    global _pool
    if _pool is None:
        _pool = redis.from_url(REDIS_URL, decode_responses=True)
    return _pool


async def close_redis() -> None:
    global _pool
    if _pool is not None:
        await _pool.aclose()
        _pool = None


async def publish_event(event: PkgHawkEvent) -> None:
    r = await get_redis()
    payload = event.model_dump_json()
    # Store in sorted set (score = timestamp)
    await r.zadd(REDIS_EVENTS_KEY, {payload: event.ts})
    # Trim to max events
    count = await r.zcard(REDIS_EVENTS_KEY)
    if count > MAX_EVENTS:
        await r.zremrangebyrank(REDIS_EVENTS_KEY, 0, count - MAX_EVENTS - 1)
    # Publish to subscribers
    await r.publish(REDIS_CHANNEL, payload)
    logger.info("Published event: %s %s/%s", event.id, event.ecosystem, event.package)


async def is_duplicate(event: PkgHawkEvent) -> bool:
    r = await get_redis()
    key = f"{REDIS_DEDUP_PREFIX}{event.dedup_key()}"
    existed = await r.set(key, "1", nx=True, ex=DEDUP_TTL_SECONDS)
    return existed is None  # None means key already existed


async def get_latest_events(
    n: int = 200,
    ecosystem: str | None = None,
    severity: str | None = None,
    event_type: str | None = None,
    confidence: str | None = None,
    since: int | None = None,
) -> list[dict]:
    r = await get_redis()
    min_score = since if since else "-inf"
    raw_events = await r.zrevrangebyscore(REDIS_EVENTS_KEY, "+inf", min_score)

    results: list[dict] = []
    ecosystems = set(ecosystem.split(",")) if ecosystem else None
    severities = set(severity.split(",")) if severity else None
    types = set(event_type.split(",")) if event_type else None
    confidences = set(confidence.split(",")) if confidence else None

    for raw in raw_events:
        if len(results) >= n:
            break
        evt = json.loads(raw)
        if ecosystems and evt.get("ecosystem") not in ecosystems:
            continue
        if severities and evt.get("severity") not in severities:
            continue
        if types and evt.get("type") not in types:
            continue
        if confidences and evt.get("confidence") not in confidences:
            continue
        results.append(evt)

    return results


ALL_SOURCES = ["osv.dev", "github-advisory", "pypi-rss", "socket.dev", "cisa-kev", "grok-x"]


async def set_source_health(source: str, status: str) -> None:
    r = await get_redis()
    await r.set(
        f"{REDIS_SOURCE_HEALTH_PREFIX}{source}",
        json.dumps({"status": status, "last_check": int(time.time())}),
        ex=7200,  # 2 hours — covers hourly pollers
    )


async def get_sources_health() -> dict[str, dict]:
    r = await get_redis()
    result = {}
    for source in ALL_SOURCES:
        raw = await r.get(f"{REDIS_SOURCE_HEALTH_PREFIX}{source}")
        if raw:
            result[source] = json.loads(raw)
        else:
            result[source] = {"status": "unknown", "last_check": None}
    return result


async def get_event_count_24h() -> int:
    r = await get_redis()
    since = int(time.time()) - 86400
    return await r.zcount(REDIS_EVENTS_KEY, since, "+inf")
