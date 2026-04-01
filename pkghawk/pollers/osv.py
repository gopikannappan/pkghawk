from __future__ import annotations

import logging

import httpx

from pkghawk.processing.deduplicator import process_event, reset_poll_counter
from pkghawk.processing.normalizer import normalize_osv
from pkghawk.redis_client import set_source_health

logger = logging.getLogger(__name__)

OSV_QUERY_API = "https://api.osv.dev/v1/query"
OSV_VULN_API = "https://api.osv.dev/v1/vulns"

# Query a set of high-value packages across ecosystems each poll cycle.
# These rotate or expand over time; the deduplicator prevents re-emission.
HIGH_VALUE_PACKAGES = [
    ("npm", "axios"),
    ("npm", "express"),
    ("npm", "lodash"),
    ("npm", "chalk"),
    ("npm", "react"),
    ("npm", "next"),
    ("npm", "@angular/core"),
    ("npm", "vue"),
    ("npm", "webpack"),
    ("npm", "typescript"),
    ("PyPI", "requests"),
    ("PyPI", "flask"),
    ("PyPI", "django"),
    ("PyPI", "numpy"),
    ("PyPI", "pandas"),
    ("PyPI", "boto3"),
    ("PyPI", "cryptography"),
    ("PyPI", "fastapi"),
    ("PyPI", "torch"),
    ("PyPI", "setuptools"),
    ("Go", "github.com/gin-gonic/gin"),
    ("Go", "github.com/gorilla/mux"),
    ("Go", "github.com/go-sql-driver/mysql"),
]

# Also fetch known malware IDs by prefix pattern (MAL-*)
MAL_ID_PREFIXES = ["MAL-2026-", "MAL-2025-"]


async def poll_osv() -> None:
    """Poll OSV.dev for vulnerabilities on high-value packages and recent malware IDs."""
    reset_poll_counter("osv.dev")
    published = 0

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            # 1. Query high-value packages
            for ecosystem, package in HIGH_VALUE_PACKAGES:
                try:
                    resp = await client.post(
                        OSV_QUERY_API,
                        json={"package": {"ecosystem": ecosystem, "name": package}},
                    )
                    resp.raise_for_status()
                    data = resp.json()

                    for vuln in data.get("vulns", []):
                        event = normalize_osv(vuln)
                        if event and await process_event(event):
                            published += 1

                except httpx.HTTPError as e:
                    logger.warning("OSV query failed for %s/%s: %s", ecosystem, package, e)

            # 2. Probe recent MAL-* IDs for new malware advisories
            for prefix in MAL_ID_PREFIXES:
                for i in range(1, 20):  # Check last 20 IDs per prefix
                    mal_id = f"{prefix}{i}"
                    try:
                        resp = await client.get(f"{OSV_VULN_API}/{mal_id}")
                        if resp.status_code == 404:
                            continue
                        resp.raise_for_status()
                        vuln = resp.json()
                        event = normalize_osv(vuln)
                        if event and await process_event(event):
                            published += 1
                    except httpx.HTTPError:
                        continue

        await set_source_health("osv.dev", "ok")
        if published:
            logger.info("OSV: published %d new events", published)

    except Exception:
        await set_source_health("osv.dev", "error")
        logger.exception("OSV poller error")