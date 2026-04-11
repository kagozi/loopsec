"""
Patches endpoints.

GET /scans/{scan_id}/patches           — list patches for a scan
GET /patches/{patch_id}                — get a single patch (includes full diff)
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from loopsec.api.db import crud
from loopsec.api.dependencies import get_db

router = APIRouter()

DB = Annotated[Session, Depends(get_db)]


@router.get("/scans/{scan_id}/patches")
def list_patches(
    scan_id: str,
    db: DB,
    status: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    """List patches for a scan. Filter by status (pending/applied/verified/failed/regressed)."""
    if not crud.get_scan(db, scan_id):
        raise HTTPException(status_code=404, detail="Scan not found")
    items, total = crud.get_patches(db, scan_id, status=status, limit=limit, offset=offset)
    return {"items": items, "total": total}


@router.get("/patches/{patch_id}")
def get_patch(patch_id: str, db: DB) -> dict:
    """Get a single patch by ID, including full diff, original and patched code."""
    data = crud.get_patch(db, patch_id)
    if not data:
        raise HTTPException(status_code=404, detail="Patch not found")
    return data
