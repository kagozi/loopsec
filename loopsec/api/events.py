"""
In-memory fan-out event bus for SSE streaming.

One asyncio.Queue per (scan_id, subscriber). Multiple SSE clients can
subscribe to the same scan and each receives all events independently.
"""

from __future__ import annotations

import asyncio
from typing import Any

# scan_id -> list of subscriber queues
_subscribers: dict[str, list[asyncio.Queue]] = {}

_SENTINEL = object()  # signals end-of-stream to SSE generators


def subscribe(scan_id: str) -> asyncio.Queue:
    """Register a new SSE subscriber for a scan. Returns the queue to read from."""
    q: asyncio.Queue = asyncio.Queue()
    _subscribers.setdefault(scan_id, []).append(q)
    return q


def unsubscribe(scan_id: str, q: asyncio.Queue) -> None:
    """Remove a subscriber queue when the SSE connection closes."""
    queues = _subscribers.get(scan_id, [])
    try:
        queues.remove(q)
    except ValueError:
        pass
    if not queues:
        _subscribers.pop(scan_id, None)


async def publish(scan_id: str, event: dict[str, Any]) -> None:
    """Push an event to all active subscribers of a scan."""
    for q in list(_subscribers.get(scan_id, [])):
        await q.put(event)


async def close(scan_id: str) -> None:
    """Send the sentinel to all subscribers, signalling end-of-stream."""
    for q in list(_subscribers.get(scan_id, [])):
        await q.put(_SENTINEL)


def is_sentinel(item: Any) -> bool:
    return item is _SENTINEL
