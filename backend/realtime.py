from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterable

from .models import SecurityEvent


async def simulate_event_stream(
    events: Iterable[SecurityEvent],
    *,
    delay_seconds: float = 1.0,
) -> AsyncIterator[SecurityEvent]:
    """Emit supplied telemetry one event at a time to model a live collector.

    This is deliberately a simulator: it preserves the exact event payloads and
    timing order supplied by the scenario, but does not claim to be a host log
    collector. A real collector can later implement the same async stream
    contract.
    """
    delay = max(0.0, min(float(delay_seconds), 10.0))
    for event in sorted(events, key=lambda item: item.timestamp):
        if delay:
            await asyncio.sleep(delay)
        yield event
