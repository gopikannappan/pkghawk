from __future__ import annotations

from pkghawk.schema import Confidence, PkgHawkEvent


def compute_confidence(event: PkgHawkEvent) -> Confidence:
    """Compute confidence based on number of confirming sources."""
    n = len(event.sources_confirmed)
    if n >= 3:
        return Confidence.CRITICAL
    if n >= 2:
        return Confidence.HIGH
    if event.source == "grok-x":
        return Confidence.LOW
    return Confidence.MEDIUM
