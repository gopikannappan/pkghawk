from __future__ import annotations

import json

from fastmcp import FastMCP

from pkghawk.redis_client import get_event_count_24h, get_latest_events, get_sources_health

mcp = FastMCP("pkghawk")


@mcp.tool()
async def pkghawk_latest(
    ecosystem: str | None = None,
    n: int = 20,
    severity: str | None = None,
) -> str:
    """Get the latest package threat events.

    Use at agent session start for context on recent supply chain attacks.

    Args:
        ecosystem: Filter by ecosystem (npm, pypi, go, maven, cargo, rubygems, nuget)
        n: Number of events to return (default 20, max 100)
        severity: Filter by severity (critical, high, medium, low)
    """
    n = min(n, 100)
    events = await get_latest_events(n=n, ecosystem=ecosystem, severity=severity)
    if not events:
        return json.dumps({"status": "ok", "message": "No active threats", "events": []})
    return json.dumps({"status": "alert" if events else "ok", "count": len(events), "events": events})


@mcp.tool()
async def pkghawk_check_package(
    package: str,
    ecosystem: str,
    version: str | None = None,
) -> str:
    """Check if a specific package has active security alerts.

    IMPORTANT: Call this before suggesting or installing any package.

    Args:
        package: Package name to check
        ecosystem: Package ecosystem (npm, pypi, go, maven, cargo, rubygems, nuget)
        version: Optional specific version to check
    """
    events = await get_latest_events(n=500, ecosystem=ecosystem)
    matches = [e for e in events if e.get("package", "").lower() == package.lower()]

    if version:
        version_matches = []
        for e in matches:
            affected = e.get("affected_versions", [])
            if not affected or version in str(affected):
                version_matches.append(e)
        matches = version_matches or matches

    if not matches:
        return json.dumps({"status": "clear", "package": package, "ecosystem": ecosystem, "events": []})

    return json.dumps({
        "status": "ALERT",
        "package": package,
        "ecosystem": ecosystem,
        "count": len(matches),
        "events": matches[:10],
    })


@mcp.tool()
async def pkghawk_stats() -> str:
    """Get feed health and 24h event statistics."""
    count_24h = await get_event_count_24h()
    sources = await get_sources_health()
    active = sum(1 for s in sources.values() if s.get("status") == "ok")
    return json.dumps({
        "events_24h": count_24h,
        "sources_active": active,
        "sources": sources,
    })


@mcp.tool()
async def pkghawk_subscribe(callback_url: str) -> str:
    """Register a webhook URL for push notifications of new threats.

    For persistent agent processes that want real-time alerts pushed to them.

    Args:
        callback_url: HTTPS URL that will receive POST requests with threat events
    """
    return json.dumps({
        "status": "not_available",
        "message": "Webhook subscriptions are coming in a future release. "
        "Use pkghawk_latest() to poll for recent events, "
        "or connect to the SSE feed at /feed for real-time streaming.",
    })
