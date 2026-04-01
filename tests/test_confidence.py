from pkghawk.processing.confidence import compute_confidence
from pkghawk.schema import Confidence, Ecosystem, EventType, PkgHawkEvent


def _make_event(source: str, sources_confirmed: list[str] | None = None) -> PkgHawkEvent:
    return PkgHawkEvent(
        type=EventType.MALICIOUS,
        ecosystem=Ecosystem.NPM,
        package="test",
        source=source,
        sources_confirmed=sources_confirmed or [],
        summary="test",
    )


def test_single_grok_source():
    event = _make_event("grok-x")
    assert compute_confidence(event) == Confidence.LOW


def test_single_structured_source():
    event = _make_event("osv.dev")
    assert compute_confidence(event) == Confidence.MEDIUM


def test_two_sources():
    event = _make_event("osv.dev", ["osv.dev", "github-advisory"])
    assert compute_confidence(event) == Confidence.HIGH


def test_three_sources():
    event = _make_event("osv.dev", ["osv.dev", "github-advisory", "grok-x"])
    assert compute_confidence(event) == Confidence.CRITICAL
