from pkghawk.schema import (
    Confidence,
    Ecosystem,
    EventType,
    PkgHawkEvent,
    Severity,
)


def test_event_creation():
    event = PkgHawkEvent(
        type=EventType.MALICIOUS,
        ecosystem=Ecosystem.NPM,
        package="evil-pkg",
        source="osv.dev",
        summary="Malware found in evil-pkg",
    )
    assert event.id.startswith("ph-")
    assert event.type == "malicious"
    assert event.ecosystem == "npm"
    assert event.package == "evil-pkg"
    assert event.pkghawk_version == "1"


def test_event_auto_fields():
    event = PkgHawkEvent(
        type=EventType.VULN,
        ecosystem=Ecosystem.PYPI,
        package="requests",
        source="github-advisory",
        summary="CVE in requests",
    )
    assert event.ts > 0
    assert event.ts_iso.endswith("Z")
    assert event.first_seen == event.ts
    assert "github-advisory" in event.sources_confirmed


def test_event_dedup_key():
    event = PkgHawkEvent(
        type=EventType.MALICIOUS,
        ecosystem=Ecosystem.NPM,
        package="axios",
        source="osv.dev",
        summary="test",
    )
    assert event.dedup_key() == "npm:axios:malicious"


def test_event_different_sources_same_dedup():
    e1 = PkgHawkEvent(
        type=EventType.MALICIOUS,
        ecosystem=Ecosystem.NPM,
        package="axios",
        source="osv.dev",
        summary="from osv",
    )
    e2 = PkgHawkEvent(
        type=EventType.MALICIOUS,
        ecosystem=Ecosystem.NPM,
        package="axios",
        source="github-advisory",
        summary="from github",
    )
    assert e1.dedup_key() == e2.dedup_key()


def test_event_serialization():
    event = PkgHawkEvent(
        type=EventType.HIJACK,
        ecosystem=Ecosystem.GO,
        package="github.com/example/pkg",
        source="grok-x",
        summary="Maintainer hijack detected",
        severity=Severity.CRITICAL,
        confidence=Confidence.LOW,
        cve_id="CVE-2026-1234",
    )
    data = event.model_dump()
    assert data["type"] == "hijack"
    assert data["ecosystem"] == "go"
    assert data["severity"] == "critical"
    assert data["confidence"] == "low"
    assert data["cve_id"] == "CVE-2026-1234"

    json_str = event.model_dump_json()
    assert "CVE-2026-1234" in json_str
