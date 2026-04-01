from __future__ import annotations

import logging
import re

from pkghawk.schema import (
    Confidence,
    Ecosystem,
    EventType,
    PkgHawkEvent,
    Severity,
)

logger = logging.getLogger(__name__)

OSV_ECOSYSTEM_MAP: dict[str, Ecosystem] = {
    "npm": Ecosystem.NPM,
    "PyPI": Ecosystem.PYPI,
    "Go": Ecosystem.GO,
    "Maven": Ecosystem.MAVEN,
    "crates.io": Ecosystem.CARGO,
    "RubyGems": Ecosystem.RUBYGEMS,
    "NuGet": Ecosystem.NUGET,
}

SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def normalize_osv(vuln: dict) -> PkgHawkEvent | None:
    """Normalize an OSV.dev vulnerability into a PkgHawkEvent."""
    affected_list = vuln.get("affected", [])
    if not affected_list:
        return None

    affected = affected_list[0]
    pkg_info = affected.get("package", {})
    ecosystem_raw = pkg_info.get("ecosystem", "")
    ecosystem = OSV_ECOSYSTEM_MAP.get(ecosystem_raw)
    if ecosystem is None:
        return None

    package_name = pkg_info.get("name", "")
    if not package_name:
        return None

    # Determine event type
    aliases = vuln.get("aliases", [])
    summary = vuln.get("summary", "") or vuln.get("details", "")[:300]
    event_type = _classify_osv_type(vuln, summary)

    # Extract severity
    severity = Severity.UNKNOWN
    for sev in vuln.get("severity", []):
        score_str = sev.get("score", "")
        if re.search(r"CVSS:\d\.\d/AV:.*/.*", score_str):
            severity = _cvss_to_severity(score_str)
            break
    db_severity = vuln.get("database_specific", {}).get("severity")
    if severity == Severity.UNKNOWN and db_severity:
        severity = SEVERITY_MAP.get(db_severity.upper(), Severity.UNKNOWN)

    # Extract affected versions
    affected_versions: list[str] = []
    for rng in affected.get("ranges", []):
        for evt in rng.get("events", []):
            if "introduced" in evt and evt["introduced"] != "0":
                affected_versions.append(f">={evt['introduced']}")
            if "fixed" in evt:
                affected_versions.append(f"<{evt['fixed']}")

    safe_version = None
    for rng in affected.get("ranges", []):
        for evt in rng.get("events", []):
            if "fixed" in evt:
                safe_version = evt["fixed"]
                break

    # Extract IDs
    cve_id = next((a for a in aliases if a.startswith("CVE-")), None)
    ghsa_id = next((a for a in aliases if a.startswith("GHSA-")), None)

    ref_urls = [ref.get("url", "") for ref in vuln.get("references", []) if ref.get("url")]

    return PkgHawkEvent(
        type=event_type,
        ecosystem=ecosystem,
        package=package_name,
        affected_versions=affected_versions,
        safe_version=safe_version,
        severity=severity,
        confidence=Confidence.MEDIUM,
        source="osv.dev",
        summary=summary[:500],
        ref_urls=ref_urls[:5],
        cve_id=cve_id,
        ghsa_id=ghsa_id,
    )


def normalize_github_advisory(entry: dict) -> PkgHawkEvent | None:
    """Normalize a GitHub Advisory RSS entry into a PkgHawkEvent."""
    title = entry.get("title", "")
    summary = entry.get("summary", title)
    link = entry.get("link", "")

    # Try to extract package and ecosystem from title
    # Typical format: "Malicious Package: <package-name> (npm)"
    package_name = ""
    ecosystem = Ecosystem.NPM  # default
    if "npm" in title.lower():
        ecosystem = Ecosystem.NPM
    elif "pypi" in title.lower():
        ecosystem = Ecosystem.PYPI
    elif "go" in title.lower():
        ecosystem = Ecosystem.GO

    # Extract package name from title
    for pattern in [
        r"Malicious (?:Package|package)[:\s]+(\S+)",
        r"(\S+)\s+contains?\s+malware",
        r"(\S+)\s+(?:npm|pypi|go)",
    ]:
        if match := re.search(pattern, title, re.IGNORECASE):
            package_name = match.group(1).strip("()[]")
            break

    if not package_name:
        # Fall back to first significant word
        words = [w for w in title.split() if len(w) > 2 and w.lower() not in {"the", "and", "for", "malicious", "package", "contains", "malware"}]
        package_name = words[0] if words else "unknown"

    # Extract GHSA ID from link
    ghsa_id = None
    if match := re.search(r"(GHSA-[\w-]+)", link):
        ghsa_id = match.group(1)

    return PkgHawkEvent(
        type=EventType.MALICIOUS,
        ecosystem=ecosystem,
        package=package_name,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        source="github-advisory",
        summary=summary[:500],
        ref_urls=[link] if link else [],
        ghsa_id=ghsa_id,
    )


def _classify_osv_type(vuln: dict, summary: str) -> EventType:
    summary_lower = summary.lower()
    db_specific = vuln.get("database_specific", {})

    if db_specific.get("malware"):
        return EventType.MALICIOUS
    if any(kw in summary_lower for kw in ["malicious", "malware", "backdoor", "trojan", "rat "]):
        return EventType.MALICIOUS
    if any(kw in summary_lower for kw in ["typosquat", "typo-squat", "impersonat"]):
        return EventType.TYPOSQUAT
    if any(kw in summary_lower for kw in ["hijack", "compromised maintainer", "account takeover"]):
        return EventType.HIJACK
    return EventType.VULN


def _cvss_to_severity(cvss_string: str) -> Severity:
    if match := re.search(r"/(\d+\.?\d*)", cvss_string):
        score = float(match.group(1))
        if score >= 9.0:
            return Severity.CRITICAL
        if score >= 7.0:
            return Severity.HIGH
        if score >= 4.0:
            return Severity.MEDIUM
        return Severity.LOW
    return Severity.UNKNOWN
