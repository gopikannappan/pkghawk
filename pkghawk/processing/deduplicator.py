from __future__ import annotations

import logging

from pkghawk.config import MAX_EVENTS_PER_POLL
from pkghawk.processing.sanitizer import sanitize_summary
from pkghawk.redis_client import is_duplicate, publish_event
from pkghawk.schema import PkgHawkEvent

logger = logging.getLogger(__name__)

# Track events per poll cycle to cap volume
_poll_counters: dict[str, int] = {}


def reset_poll_counter(source: str) -> None:
    """Reset event counter for a poll cycle. Call at start of each poller."""
    _poll_counters[source] = 0


async def process_event(event: PkgHawkEvent) -> bool:
    """Deduplicate, sanitize, and publish an event. Returns True if published."""
    source = event.source

    # Volume cap: if a single poll cycle emits too many events, stop
    count = _poll_counters.get(source, 0)
    if count >= MAX_EVENTS_PER_POLL:
        if count == MAX_EVENTS_PER_POLL:
            logger.warning(
                "Volume cap reached for %s: %d events in one cycle, dropping further events",
                source, count,
            )
            _poll_counters[source] = count + 1  # only warn once
        return False

    if await is_duplicate(event):
        logger.debug("Duplicate skipped: %s %s/%s", event.id, event.ecosystem, event.package)
        return False

    # Sanitize free-text fields before publishing
    event.summary = sanitize_summary(event.summary)
    await publish_event(event)
    _poll_counters[source] = count + 1
    return True
