from __future__ import annotations

import logging

from pkghawk.redis_client import is_duplicate, publish_event
from pkghawk.schema import PkgHawkEvent

logger = logging.getLogger(__name__)


async def process_event(event: PkgHawkEvent) -> bool:
    """Deduplicate and publish an event. Returns True if published."""
    if await is_duplicate(event):
        logger.debug("Duplicate skipped: %s %s/%s", event.id, event.ecosystem, event.package)
        return False
    await publish_event(event)
    return True
