"""
Findings endpoints. All endpoints require authentication.

GET /scans/{scan_id}/findings          — list findings for a scan
GET /findings/{finding_id}             — get a single finding
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from loopsec.api.auth.dependencies import CurrentUser
from loopsec.api.db import crud
from loopsec.api.dependencies import get_db

router = APIRouter()

DB = Annotated[Session, Depends(get_db)]


@router.get("/scans/{scan_id}/findings")
def list_findings(
    scan_id: str,
    user: CurrentUser,
    db: DB,
    severity: str | None = None,
    source: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    """List findings for a scan. Filter by severity (critical/high/medium/low/info) or source (sast/dast/secret/sca)."""
    row = crud.get_scan(db, scan_id)
    if not row or row.user_id != user.id:
        raise HTTPException(status_code=404, detail="Scan not found")
    items, total = crud.get_findings(db, scan_id, severity=severity, source=source, limit=limit, offset=offset)
    return {"items": items, "total": total}


@router.get("/findings/{finding_id}")
def get_finding(finding_id: str, user: CurrentUser, db: DB) -> dict:
    """Get a single finding by ID."""
    data = crud.get_finding(db, finding_id)
    if not data:
        raise HTTPException(status_code=404, detail="Finding not found")
    # Verify the finding's scan belongs to this user
    row = crud.get_scan(db, data["scan_id"])
    if not row or row.user_id != user.id:
        raise HTTPException(status_code=404, detail="Finding not found")
    return data
