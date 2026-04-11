"""
Streaming endpoints — SSE and WebSocket.

GET /scans/{scan_id}/stream      — Server-Sent Events (requires Authorization header)
WS  /scans/{scan_id}/ws?token=   — WebSocket (token passed as query param since
                                   browsers cannot set WS headers)

Both tap the same in-memory event bus and replay from DB when a scan is already done.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Annotated, AsyncGenerator

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from loopsec.api import events
from loopsec.api.auth.dependencies import CurrentUser
from loopsec.api.auth.jwt import decode_token
from loopsec.api.db import crud
from loopsec.api.db.crud import get_user_by_id
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


# ---------------------------------------------------------------------------
# WebSocket endpoint
# ---------------------------------------------------------------------------

@router.websocket("/scans/{scan_id}/ws")
async def scan_websocket(
    websocket: WebSocket,
    scan_id: str,
    token: str = Query(..., description="JWT access token"),
) -> None:
    """
    WebSocket stream for a scan.

    Connect with:
        new WebSocket(`ws://host/scans/${scanId}/ws?token=${jwt}`)

    Messages are JSON objects identical to the SSE event payloads:
        {"type": "status_change", "status": "analyzing"}
        {"type": "finding_added", "finding": {...}}
        {"type": "patch_added",   "patch":   {...}}
        {"type": "exploit_added", "exploit": {...}}
        {"type": "pr_created",    "pull_request": {...}}
        {"type": "complete",      "summary": {...}}
        {"type": "error",         "message": "..."}
        {"type": "ping"}          -- keep-alive every 15 s
    """
    # ── Auth ────────────────────────────────────────────────────────────────
    user_id = decode_token(token)
    if not user_id:
        await websocket.close(code=4001, reason="Invalid or expired token")
        return

    # Use a fresh DB session for the lifetime of this connection
    from loopsec.api.db.engine import SessionLocal
    with SessionLocal() as db:
        user = get_user_by_id(db, user_id)
        if not user:
            await websocket.close(code=4001, reason="User not found")
            return

        row = crud.get_scan(db, scan_id)
        if not row or row.user_id != user.id:
            await websocket.close(code=4004, reason="Scan not found")
            return

        already_done = row.status in _TERMINAL_STATUSES

    await websocket.accept()
    logger.debug("WS connected: scan=%s user=%s", scan_id, user_id)

    try:
        if already_done:
            await _ws_replay_from_db(websocket, scan_id)
        else:
            await _ws_stream_live(websocket, scan_id)
    except WebSocketDisconnect:
        logger.debug("WS disconnected: scan=%s", scan_id)
    except Exception:
        logger.exception("WS error: scan=%s", scan_id)
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


async def _ws_send(ws: WebSocket, payload: dict) -> None:
    """Send a JSON message; silently swallow send-on-closed errors."""
    try:
        await ws.send_text(json.dumps(payload))
    except Exception:
        pass


async def _ws_replay_from_db(ws: WebSocket, scan_id: str) -> None:
    """Replay all stored results for a completed scan, then send 'complete'."""
    from loopsec.api.db.engine import SessionLocal

    with SessionLocal() as db:
        row = crud.get_scan(db, scan_id)
        if row:
            await _ws_send(ws, {"type": "status_change", "status": row.status})

        findings, _ = crud.get_findings(db, scan_id, limit=1000)
        for f in findings:
            await _ws_send(ws, {"type": "finding_added", "finding": f})

        exploits, _ = crud.get_exploits(db, scan_id, limit=1000)
        for e in exploits:
            await _ws_send(ws, {"type": "exploit_added", "exploit": e})

        patches, _ = crud.get_patches(db, scan_id, limit=1000)
        for p in patches:
            await _ws_send(ws, {"type": "patch_added", "patch": p})

        if row and row.summary_json:
            await _ws_send(ws, {
                "type": "complete",
                "summary": json.loads(row.summary_json),
            })

        # Load PRs
        prs, _ = crud.list_pull_requests(db, user_id=row.user_id or "", scan_id=scan_id)
        for pr in prs:
            await _ws_send(ws, {"type": "pr_created", "pull_request": pr})


async def _ws_stream_live(ws: WebSocket, scan_id: str) -> None:
    """Forward live events from the event bus to the WebSocket client."""
    q = events.subscribe(scan_id)
    try:
        while True:
            try:
                item = await asyncio.wait_for(q.get(), timeout=_KEEP_ALIVE_INTERVAL)
            except asyncio.TimeoutError:
                await _ws_send(ws, {"type": "ping"})
                continue

            if events.is_sentinel(item):
                break

            await _ws_send(ws, item)

            event_type = item.get("type", "")
            if event_type in ("complete", "error"):
                break
    finally:
        events.unsubscribe(scan_id, q)
