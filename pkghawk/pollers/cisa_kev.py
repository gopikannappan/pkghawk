from __future__ import annotations

import logging

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

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# CISA KEV doesn't map to specific ecosystems — we flag relevant ones
ECOSYSTEM_HINTS: dict[str, Ecosystem] = {
    "npm": Ecosystem.NPM,
    "node": Ecosystem.NPM,
    "python": Ecosystem.PYPI,
    "pip": Ecosystem.PYPI,
    "go": Ecosystem.GO,
    "java": Ecosystem.MAVEN,
    "maven": Ecosystem.MAVEN,
}


async def poll_cisa_kev() -> None:
    """Poll CISA Known Exploited Vulnerabilities feed."""
    reset_poll_counter("cisa-kev")
    published = 0

    try:
        headers = {"User-Agent": "pkghawk/0.1 (https://pkghawk.dev)"}
        async with httpx.AsyncClient(timeout=30, headers=headers, follow_redirects=True) as client:
            resp = await client.get(CISA_KEV_URL)
            if resp.status_code == 403:
                logger.debug("CISA KEV blocked (403) — likely WAF; skipping")
                await set_source_health("cisa-kev", "unavailable")
                return
            resp.raise_for_status()

        data = resp.json()
        vulns = data.get("vulnerabilities", [])

        # Process only the most recent entries (last 10)
        for vuln in vulns[-10:]:
            cve_id = vuln.get("cveID", "")
            product = vuln.get("product", "")
            vendor = vuln.get("vendorProject", "")
            description = vuln.get("shortDescription", "")

            # Try to detect ecosystem
            text = f"{product} {vendor} {description}".lower()
            ecosystem = None
            for kw, eco in ECOSYSTEM_HINTS.items():
                if kw in text:
                    ecosystem = eco
                    break

            if ecosystem is None:
                continue  # Skip non-package vulns

            event = PkgHawkEvent(
                type=EventType.VULN,
                ecosystem=ecosystem,
                package=product,
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                source="cisa-kev",
                summary=f"CISA KEV: {description[:400]}",
                cve_id=cve_id,
                ref_urls=[f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
            )
            if await process_event(event):
                published += 1

        await set_source_health("cisa-kev", "ok")
        if published:
            logger.info("CISA KEV: published %d new events", published)

    except Exception:
        await set_source_health("cisa-kev", "error")
        logger.exception("CISA KEV poller error")
