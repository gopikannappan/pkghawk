from __future__ import annotations

import json
import logging

import httpx

from pkghawk.config import XAI_API_KEY
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

XAI_API_URL = "https://api.x.ai/v1/chat/completions"

ECOSYSTEM_MAP: dict[str, Ecosystem] = {
    "npm": Ecosystem.NPM,
    "pypi": Ecosystem.PYPI,
    "go": Ecosystem.GO,
    "maven": Ecosystem.MAVEN,
    "cargo": Ecosystem.CARGO,
    "rubygems": Ecosystem.RUBYGEMS,
    "nuget": Ecosystem.NUGET,
}

GROK_PROMPT = """
You are a security signal extractor monitoring X (Twitter) for package supply chain threats.

Search X for posts in the last 30 minutes mentioning any of:
- malicious npm package
- pypi malware
- compromised package maintainer
- supply chain attack
- npm hijack
- typosquatting npm OR pypi

Extract concrete threat signals only. Ignore speculation, commentary, and retweets of old news.

Return ONLY a JSON array. Each item:
{
  "package": "package name or null if unclear",
  "ecosystem": "npm | pypi | go | other | unknown",
  "signal": "one sentence description of the threat",
  "url": "tweet URL if available",
  "confidence": "high | medium | low",
  "raw_excerpt": "brief quote from post"
}

Return [] if no concrete new threats found. No prose. No markdown. Raw JSON array only.
"""


async def poll_grok() -> None:
    """Poll Grok/X for community intelligence on supply chain threats."""
    reset_poll_counter("grok-x")
    if not XAI_API_KEY:
        logger.debug("Grok poller skipped: XAI_API_KEY not set")
        return

    published = 0

    try:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                XAI_API_URL,
                headers={
                    "Authorization": f"Bearer {XAI_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": "grok-3",
                    "messages": [{"role": "user", "content": GROK_PROMPT}],
                    "max_tokens": 1000,
                },
            )
            resp.raise_for_status()

        data = resp.json()
        raw = data["choices"][0]["message"]["content"].strip()

        # Parse JSON response
        try:
            signals = json.loads(raw)
        except json.JSONDecodeError:
            logger.warning("Grok returned invalid JSON: %s", raw[:200])
            await set_source_health("grok-x", "ok")
            return

        if not isinstance(signals, list):
            logger.warning("Grok returned non-array: %s", type(signals))
            await set_source_health("grok-x", "ok")
            return

        for signal in signals:
            package = signal.get("package")
            if not package:
                continue

            ecosystem_str = signal.get("ecosystem", "unknown").lower()
            ecosystem = ECOSYSTEM_MAP.get(ecosystem_str)
            if ecosystem is None:
                continue

            signal_text = signal.get("signal", "")
            url = signal.get("url", "")

            event = PkgHawkEvent(
                type=EventType.SUSPICIOUS,
                ecosystem=ecosystem,
                package=package,
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,  # Grok-only = low until corroborated
                source="grok-x",
                summary=f"X/community signal: {signal_text}",
                ref_urls=[url] if url else [],
            )
            if await process_event(event):
                published += 1

        await set_source_health("grok-x", "ok")
        if published:
            logger.info("Grok: published %d new signals", published)

    except Exception:
        await set_source_health("grok-x", "error")
        logger.exception("Grok poller error")
