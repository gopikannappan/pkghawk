from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path

import redis.asyncio as aioredis
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse
from sse_starlette.sse import EventSourceResponse

from pkghawk.config import (
    GITHUB_POLL_INTERVAL,
    GROK_POLL_INTERVAL,
    LOG_LEVEL,
    OSV_POLL_INTERVAL,
    PYPI_POLL_INTERVAL,
    REDIS_CHANNEL,
    REDIS_URL,
)
from pkghawk.pollers.cisa_kev import poll_cisa_kev
from pkghawk.pollers.github_advisory import poll_github_advisory
from pkghawk.pollers.grok import poll_grok
from pkghawk.pollers.osv import poll_osv
from pkghawk.pollers.pypi_rss import poll_pypi_new_packages
from pkghawk.pollers.socket_blog import poll_socket_blog
from pkghawk.mcp_server import mcp
from pkghawk.redis_client import (
    close_redis,
    get_event_count_24h,
    get_latest_events,
    get_redis,
    get_sources_health,
)

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

VALID_ECOSYSTEMS = {"npm", "pypi", "go", "maven", "cargo", "rubygems", "nuget"}
VALID_SEVERITIES = {"critical", "high", "medium", "low", "unknown"}
VALID_TYPES = {"malicious", "vuln", "typosquat", "hijack", "suspicious"}
VALID_CONFIDENCES = {"critical", "high", "medium", "low"}


def _validate_csv(value: str | None, allowed: set[str], name: str) -> None:
    if value is None:
        return
    invalid = set(value.split(",")) - allowed
    if invalid:
        raise HTTPException(400, f"Invalid {name}: {', '.join(sorted(invalid))}. Allowed: {', '.join(sorted(allowed))}")


scheduler = AsyncIOScheduler()

# Create the MCP ASGI sub-app
mcp_app = mcp.http_app(transport="streamable-http", path="/", stateless_http=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("pkghawk starting up")
    await get_redis()

    # Start MCP server lifespan
    async with mcp_app.lifespan(mcp_app):
        # Schedule pollers
        scheduler.add_job(poll_osv, "interval", seconds=OSV_POLL_INTERVAL, id="osv")
        scheduler.add_job(
            poll_github_advisory, "interval", seconds=GITHUB_POLL_INTERVAL, id="github"
        )
        scheduler.add_job(
            poll_pypi_new_packages, "interval", seconds=PYPI_POLL_INTERVAL, id="pypi"
        )
        scheduler.add_job(poll_socket_blog, "interval", seconds=3600, id="socket")
        scheduler.add_job(poll_cisa_kev, "interval", seconds=3600, id="cisa")
        scheduler.add_job(poll_grok, "interval", seconds=GROK_POLL_INTERVAL, id="grok")
        scheduler.start()

        # Run all pollers once at startup
        asyncio.create_task(poll_osv())
        asyncio.create_task(poll_github_advisory())
        asyncio.create_task(poll_pypi_new_packages())
        asyncio.create_task(poll_socket_blog())
        asyncio.create_task(poll_cisa_kev())
        asyncio.create_task(poll_grok())

        yield

    # Shutdown
    scheduler.shutdown(wait=False)
    await close_redis()
    logger.info("pkghawk shut down")


app = FastAPI(
    title="pkghawk",
    description="Real-time package threat feed for AI agents",
    version="0.1.0",
    lifespan=lifespan,
)

# --- MCP Server ---

app.mount("/mcp", mcp_app)


# --- SSE Feed ---


async def _event_stream(
    ecosystem: str | None,
    severity: str | None,
    event_type: str | None,
    confidence: str | None,
):
    """Subscribe to Redis pub/sub and yield matching events as SSE."""
    r = aioredis.from_url(REDIS_URL, decode_responses=True)
    pubsub = r.pubsub()
    await pubsub.subscribe(REDIS_CHANNEL)

    ecosystems = set(ecosystem.split(",")) if ecosystem else None
    severities = set(severity.split(",")) if severity else None
    types = set(event_type.split(",")) if event_type else None
    confidences = set(confidence.split(",")) if confidence else None

    try:
        async for message in pubsub.listen():
            if message["type"] != "message":
                continue
            data = message["data"]
            evt = json.loads(data)
            if ecosystems and evt.get("ecosystem") not in ecosystems:
                continue
            if severities and evt.get("severity") not in severities:
                continue
            if types and evt.get("type") not in types:
                continue
            if confidences and evt.get("confidence") not in confidences:
                continue
            yield {"data": data}
    finally:
        await pubsub.unsubscribe(REDIS_CHANNEL)
        await r.aclose()


@app.get("/feed")
async def sse_feed(
    ecosystem: str | None = Query(None),
    severity: str | None = Query(None),
    type: str | None = Query(None),
    confidence: str | None = Query(None),
):
    """SSE feed of real-time package threat events."""
    _validate_csv(ecosystem, VALID_ECOSYSTEMS, "ecosystem")
    _validate_csv(severity, VALID_SEVERITIES, "severity")
    _validate_csv(type, VALID_TYPES, "type")
    _validate_csv(confidence, VALID_CONFIDENCES, "confidence")
    return EventSourceResponse(_event_stream(ecosystem, severity, type, confidence))


# --- WebSocket ---


@app.websocket("/ws")
async def websocket_feed(
    ws: WebSocket,
    ecosystem: str | None = Query(None),
    severity: str | None = Query(None),
    type: str | None = Query(None),
    confidence: str | None = Query(None),
):
    """WebSocket feed of real-time package threat events."""
    await ws.accept()

    r = aioredis.from_url(REDIS_URL, decode_responses=True)
    pubsub = r.pubsub()
    await pubsub.subscribe(REDIS_CHANNEL)

    ecosystems = set(ecosystem.split(",")) if ecosystem else None
    severities = set(severity.split(",")) if severity else None
    types = set(type.split(",")) if type else None
    confidences = set(confidence.split(",")) if confidence else None

    try:
        async for message in pubsub.listen():
            if message["type"] != "message":
                continue
            data = message["data"]
            evt = json.loads(data)
            if ecosystems and evt.get("ecosystem") not in ecosystems:
                continue
            if severities and evt.get("severity") not in severities:
                continue
            if types and evt.get("type") not in types:
                continue
            if confidences and evt.get("confidence") not in confidences:
                continue
            await ws.send_text(data)
    except WebSocketDisconnect:
        pass
    finally:
        await pubsub.unsubscribe(REDIS_CHANNEL)
        await r.aclose()


# --- REST ---


@app.get("/latest")
async def latest_events(
    n: int = Query(200, ge=1, le=500),
    ecosystem: str | None = Query(None),
    severity: str | None = Query(None),
    type: str | None = Query(None),
    confidence: str | None = Query(None),
    since: int | None = Query(None),
):
    """Get the latest N events, optionally filtered."""
    _validate_csv(ecosystem, VALID_ECOSYSTEMS, "ecosystem")
    _validate_csv(severity, VALID_SEVERITIES, "severity")
    _validate_csv(type, VALID_TYPES, "type")
    _validate_csv(confidence, VALID_CONFIDENCES, "confidence")
    return await get_latest_events(
        n=n,
        ecosystem=ecosystem,
        severity=severity,
        event_type=type,
        confidence=confidence,
        since=since,
    )


@app.get("/health")
async def health():
    """Health check with per-source status."""
    sources = await get_sources_health()
    has_error = any(s.get("status") == "error" for s in sources.values())
    return {
        "status": "degraded" if has_error else "ok",
        "sources": sources,
    }


@app.get("/stats")
async def stats():
    """Feed statistics."""
    count_24h = await get_event_count_24h()
    sources = await get_sources_health()
    active = sum(1 for s in sources.values() if s.get("status") == "ok")
    events = await get_latest_events(n=1)
    last_event_ts = events[0].get("ts_iso") if events else None
    return {
        "events_24h": count_24h,
        "sources_active": active,
        "last_event": last_event_ts,
    }


# --- Status Page ---

STATUS_DIR = Path(__file__).parent.parent / "status"


@app.get("/", response_class=HTMLResponse)
async def status_page():
    """Serve the status page."""
    index = STATUS_DIR / "index.html"
    if index.exists():
        return FileResponse(index)
    return HTMLResponse("<h1>pkghawk</h1><p>Status page not found.</p>")
