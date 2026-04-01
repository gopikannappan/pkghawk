from __future__ import annotations

import logging
import re

import feedparser
import httpx

from pkghawk.processing.deduplicator import process_event
from pkghawk.redis_client import set_source_health
from pkghawk.schema import (
    Confidence,
    Ecosystem,
    EventType,
    PkgHawkEvent,
    Severity,
)

logger = logging.getLogger(__name__)

SOCKET_BLOG_RSS = "https://socket.dev/blog/rss.xml"

ECOSYSTEM_KEYWORDS: dict[str, Ecosystem] = {
    "npm": Ecosystem.NPM,
    "pypi": Ecosystem.PYPI,
    "python": Ecosystem.PYPI,
    "go": Ecosystem.GO,
    "golang": Ecosystem.GO,
    "maven": Ecosystem.MAVEN,
    "cargo": Ecosystem.CARGO,
    "crate": Ecosystem.CARGO,
    "rubygems": Ecosystem.RUBYGEMS,
    "nuget": Ecosystem.NUGET,
}


async def poll_socket_blog() -> None:
    """Poll Socket.dev blog RSS for supply chain attack writeups."""
    published = 0

    try:
        headers = {"User-Agent": "pkghawk/0.1 (https://pkghawk.dev)"}
        async with httpx.AsyncClient(timeout=30, headers=headers) as client:
            resp = await client.get(SOCKET_BLOG_RSS)
            resp.raise_for_status()

        feed = feedparser.parse(resp.text)

        for entry in feed.entries[:10]:
            title = entry.get("title", "")
            summary = entry.get("summary", "")
            link = entry.get("link", "")
            text = f"{title} {summary}".lower()

            # Only process security-relevant posts
            if not any(kw in text for kw in ["malware", "malicious", "supply chain", "hijack", "typosquat", "compromised"]):
                continue

            # Detect ecosystem
            ecosystem = Ecosystem.NPM  # default
            for kw, eco in ECOSYSTEM_KEYWORDS.items():
                if kw in text:
                    ecosystem = eco
                    break

            # Try to extract package name
            package = "unknown"
            for pattern in [r"`(\S+)`", r"'(\S+)'", r'"(\S+)"']:
                if match := re.search(pattern, title):
                    package = match.group(1)
                    break

            event = PkgHawkEvent(
                type=EventType.MALICIOUS,
                ecosystem=ecosystem,
                package=package,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                source="socket.dev",
                summary=f"{title}: {summary[:300]}",
                ref_urls=[link] if link else [],
            )
            if await process_event(event):
                published += 1

        await set_source_health("socket.dev", "ok")
        if published:
            logger.info("Socket blog: published %d new events", published)

    except Exception:
        await set_source_health("socket.dev", "error")
        logger.exception("Socket blog poller error")
