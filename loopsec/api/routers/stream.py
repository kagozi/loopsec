"""
SSE streaming endpoint.

GET /scans/{scan_id}/stream

- While a scan is in progress: streams live events from the in-memory event bus.
- After a scan completes: replays stored findings/patches/summary from the DB, then closes.
- Keep-alive ping every 15s prevents proxy timeouts.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Annotated, AsyncGenerator

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from loopsec.api import events
from loopsec.api.db import crud
from loopsec.api.dependencies import get_db
from loopsec.core.models import PipelineStatus

logger = logging.getLogger(__name__)

router = APIRouter()

DB = Annotated[Session, Depends(get_db)]

_TERMINAL_STATUSES = {PipelineStatus.COMPLETE.value, PipelineStatus.ERRORED.value}
_KEEP_ALIVE_INTERVAL = 15.0  # seconds


def _sse(event_type: str, data: dict) -> str:
    return f"event: {event_type}\ndata: {json.dumps(data)}\n\n"


@router.get("/scans/{scan_id}/stream")
async def stream_scan(scan_id: str, db: DB) -> StreamingResponse:
    """
    Server-Sent Events stream for a scan.
    Connect with: EventSource('/scans/{scan_id}/stream')
    """
    row = crud.get_scan(db, scan_id)
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")

    already_done = row.status in _TERMINAL_STATUSES

    return StreamingResponse(
        _generate(scan_id, already_done, db),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",       # Disable nginx buffering
            "Connection": "keep-alive",
        },
    )


async def _generate(
    scan_id: str,
    already_done: bool,
    db: Session,
) -> AsyncGenerator[str, None]:
    """
    Core SSE generator.

    If the scan is already done we replay everything from DB then close.
    If it's in progress we read from the live event queue until the sentinel arrives.
    """
    if already_done:
        async for chunk in _replay_from_db(scan_id, db):
            yield chunk
        return

    # Subscribe before reading — ensures we don't miss events published
    # between the status check above and this point.
    q = events.subscribe(scan_id)
    try:
        async for chunk in _stream_live(scan_id, q):
            yield chunk
    finally:
        events.unsubscribe(scan_id, q)


async def _replay_from_db(scan_id: str, db: Session) -> AsyncGenerator[str, None]:
    """Replay a completed scan's data from the DB."""
    row = crud.get_scan(db, scan_id)
    if row:
        yield _sse("progress", {"type": "status_change", "status": row.status})

    findings, _ = crud.get_findings(db, scan_id, limit=1000)
    for f in findings:
        yield _sse("progress", {"type": "finding_added", "finding": f})

    exploits, _ = crud.get_exploits(db, scan_id, limit=1000)
    for e in exploits:
        yield _sse("progress", {"type": "exploit_added", "exploit": e})

    patches, _ = crud.get_patches(db, scan_id, limit=1000)
    for p in patches:
        yield _sse("progress", {"type": "patch_added", "patch": p})

    if row and row.summary_json:
        import json as _json
        yield _sse("progress", {
            "type": "complete",
            "summary": _json.loads(row.summary_json),
        })


async def _stream_live(
    scan_id: str,
    q: asyncio.Queue,
) -> AsyncGenerator[str, None]:
    """Read live events from the queue until the sentinel or timeout."""
    while True:
        try:
            item = await asyncio.wait_for(q.get(), timeout=_KEEP_ALIVE_INTERVAL)
        except asyncio.TimeoutError:
            yield ": ping\n\n"  # SSE comment — keeps proxy connections alive
            continue

        if events.is_sentinel(item):
            break

        event_type = item.get("type", "progress")
        if event_type in ("complete", "error"):
            yield _sse("progress", item)
            break
        else:
            yield _sse("progress", item)
