"""
SSE streaming endpoint. Requires authentication.

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
from loopsec.api.auth.dependencies import CurrentUser
from loopsec.api.db import crud
from loopsec.api.dependencies import get_db
from loopsec.core.models import PipelineStatus

logger = logging.getLogger(__name__)

router = APIRouter()

DB = Annotated[Session, Depends(get_db)]

_TERMINAL_STATUSES = {PipelineStatus.COMPLETE.value, PipelineStatus.ERRORED.value}
_KEEP_ALIVE_INTERVAL = 15.0


def _sse(event_type: str, data: dict) -> str:
    return f"event: {event_type}\ndata: {json.dumps(data)}\n\n"


@router.get("/scans/{scan_id}/stream")
async def stream_scan(scan_id: str, user: CurrentUser, db: DB) -> StreamingResponse:
    """
    Server-Sent Events stream for a scan.
    Connect with: EventSource('/scans/{scan_id}/stream', {headers: {Authorization: 'Bearer <token>'}})
    """
    row = crud.get_scan(db, scan_id)
    if not row or row.user_id != user.id:
        raise HTTPException(status_code=404, detail="Scan not found")

    already_done = row.status in _TERMINAL_STATUSES

    return StreamingResponse(
        _generate(scan_id, already_done, db),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


async def _generate(
    scan_id: str,
    already_done: bool,
    db: Session,
) -> AsyncGenerator[str, None]:
    if already_done:
        async for chunk in _replay_from_db(scan_id, db):
            yield chunk
        return

    q = events.subscribe(scan_id)
    try:
        async for chunk in _stream_live(scan_id, q):
            yield chunk
    finally:
        events.unsubscribe(scan_id, q)


async def _replay_from_db(scan_id: str, db: Session) -> AsyncGenerator[str, None]:
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
        yield _sse("progress", {
            "type": "complete",
            "summary": json.loads(row.summary_json),
        })


async def _stream_live(
    scan_id: str,
    q: asyncio.Queue,
) -> AsyncGenerator[str, None]:
    while True:
        try:
            item = await asyncio.wait_for(q.get(), timeout=_KEEP_ALIVE_INTERVAL)
        except asyncio.TimeoutError:
            yield ": ping\n\n"
            continue

        if events.is_sentinel(item):
            break

        event_type = item.get("type", "progress")
        yield _sse("progress", item)
        if event_type in ("complete", "error"):
            break
