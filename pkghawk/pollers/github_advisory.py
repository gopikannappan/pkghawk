from __future__ import annotations

import logging
import re

import httpx

from pkghawk.config import GITHUB_TOKEN
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

GITHUB_ADVISORIES_API = "https://api.github.com/advisories"

ECOSYSTEM_MAP: dict[str, Ecosystem] = {
    "npm": Ecosystem.NPM,
    "pip": Ecosystem.PYPI,
    "go": Ecosystem.GO,
    "maven": Ecosystem.MAVEN,
    "cargo": Ecosystem.CARGO,  # actually "cargo" in GitHub
    "rubygems": Ecosystem.RUBYGEMS,
    "nuget": Ecosystem.NUGET,
}

SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}


async def poll_github_advisory() -> None:
    """Poll GitHub Advisory Database REST API for malware advisories."""
    published = 0

    try:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if GITHUB_TOKEN:
            headers["Authorization"] = f"token {GITHUB_TOKEN}"

        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                GITHUB_ADVISORIES_API,
                params={"type": "malware", "per_page": 30},
                headers=headers,
            )
            resp.raise_for_status()
            advisories = resp.json()

        for adv in advisories:
            ghsa_id = adv.get("ghsa_id", "")
            summary_text = adv.get("summary", "")
            description = adv.get("description", "")
            severity_raw = adv.get("severity", "unknown")
            html_url = adv.get("html_url", "")
            cve_id = adv.get("cve_id")

            # Extract ecosystem and package from vulnerabilities
            vulns = adv.get("vulnerabilities", [])
            if not vulns:
                continue

            for vuln_entry in vulns:
                pkg_info = vuln_entry.get("package", {})
                ecosystem_raw = pkg_info.get("ecosystem", "").lower()
                package_name = pkg_info.get("name", "")

                if not package_name:
                    continue

                ecosystem = ECOSYSTEM_MAP.get(ecosystem_raw)
                if ecosystem is None:
                    continue

                # Extract affected version range
                affected_versions = []
                vulnerable_range = vuln_entry.get("vulnerable_version_range", "")
                if vulnerable_range:
                    affected_versions.append(vulnerable_range)

                safe_version = vuln_entry.get("first_patched_version")

                event = PkgHawkEvent(
                    type=EventType.MALICIOUS,
                    ecosystem=ecosystem,
                    package=package_name,
                    affected_versions=affected_versions,
                    safe_version=safe_version,
                    severity=SEVERITY_MAP.get(severity_raw, Severity.UNKNOWN),
                    confidence=Confidence.HIGH,
                    source="github-advisory",
                    summary=summary_text[:500] or description[:500],
                    ref_urls=[html_url] if html_url else [],
                    cve_id=cve_id,
                    ghsa_id=ghsa_id,
                )
                if await process_event(event):
                    published += 1

        await set_source_health("github-advisory", "ok")
        if published:
            logger.info("GitHub Advisory: published %d new events", published)

    except Exception:
        await set_source_health("github-advisory", "error")
        logger.exception("GitHub Advisory poller error")
