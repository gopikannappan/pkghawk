from __future__ import annotations

import logging

import feedparser
import httpx

from pkghawk.processing.deduplicator import process_event, reset_poll_counter
from pkghawk.redis_client import set_source_health
from pkghawk.schema import (
    Confidence,
    Ecosystem,
    EventType,
    PkgHawkEvent,
    Severity,
)

logger = logging.getLogger(__name__)

PYPI_NEW_PACKAGES_RSS = "https://pypi.org/rss/packages.xml"

# Well-known popular packages — new packages with similar names are suspicious
POPULAR_PACKAGES = {
    "requests", "flask", "django", "numpy", "pandas", "tensorflow",
    "torch", "boto3", "urllib3", "setuptools", "pip", "cryptography",
    "pillow", "matplotlib", "scipy", "sqlalchemy", "celery", "redis",
    "fastapi", "pydantic", "httpx", "aiohttp", "pytest", "black",
    "axios", "express", "react", "lodash", "chalk", "commander",
}


def _is_typosquat_candidate(name: str) -> bool:
    """Check if a package name looks like a typosquat of a popular package."""
    name_lower = name.lower().replace("-", "").replace("_", "")
    for popular in POPULAR_PACKAGES:
        pop_norm = popular.lower().replace("-", "").replace("_", "")
        if name_lower == pop_norm:
            continue  # exact match, not a typosquat
        # Simple Levenshtein-like: off by one char, prefix/suffix variants
        if len(name_lower) > 3 and (
            pop_norm in name_lower
            or name_lower in pop_norm
            or _edit_distance_one(name_lower, pop_norm)
        ):
            return True
    return False


def _edit_distance_one(a: str, b: str) -> bool:
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        return sum(ca != cb for ca, cb in zip(a, b)) == 1
    short, long = (a, b) if len(a) < len(b) else (b, a)
    diffs = 0
    si = li = 0
    while si < len(short) and li < len(long):
        if short[si] != long[li]:
            diffs += 1
            li += 1
        else:
            si += 1
            li += 1
    return diffs <= 1


async def poll_pypi_new_packages() -> None:
    """Poll PyPI RSS for new packages that look like typosquats."""
    reset_poll_counter("pypi-rss")
    published = 0

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(PYPI_NEW_PACKAGES_RSS)
            resp.raise_for_status()

        feed = feedparser.parse(resp.text)

        for entry in feed.entries[:40]:
            pkg_name = entry.get("title", "").strip()
            if not pkg_name or not _is_typosquat_candidate(pkg_name):
                continue

            event = PkgHawkEvent(
                type=EventType.TYPOSQUAT,
                ecosystem=Ecosystem.PYPI,
                package=pkg_name,
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                source="pypi-rss",
                summary=f"New PyPI package '{pkg_name}' resembles a popular package name — potential typosquat.",
                ref_urls=[entry.get("link", "")],
            )
            if await process_event(event):
                published += 1

        await set_source_health("pypi-rss", "ok")
        if published:
            logger.info("PyPI RSS: flagged %d potential typosquats", published)

    except Exception:
        await set_source_health("pypi-rss", "error")
        logger.exception("PyPI RSS poller error")
