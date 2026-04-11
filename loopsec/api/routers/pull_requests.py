"""
Pull request endpoints. All endpoints require authentication.

GET  /pull-requests                  — list all PRs for the current user
GET  /scans/{scan_id}/pull-requests  — list PRs for a specific scan
POST /scans/{scan_id}/create-pr      — manually trigger PR creation for a completed scan
"""

from __future__ import annotations

import asyncio
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from loopsec.api.auth.dependencies import CurrentUser
from loopsec.api.db import crud
from loopsec.api.dependencies import get_db
from loopsec.core.models import PipelineStatus

logger = logging.getLogger(__name__)

router = APIRouter()

DB = Annotated[Session, Depends(get_db)]


@router.get("/pull-requests")
def list_pull_requests(
    user: CurrentUser,
    db: DB,
    scan_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    """List all GitHub PRs created by LoopSec for the current user."""
    items, total = crud.list_pull_requests(
        db, user_id=user.id, scan_id=scan_id, limit=limit, offset=offset
    )
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/scans/{scan_id}/pull-requests")
def list_scan_pull_requests(scan_id: str, user: CurrentUser, db: DB) -> dict:
    """List PRs created for a specific scan."""
    row = crud.get_scan(db, scan_id)
    if not row or row.user_id != user.id:
        raise HTTPException(status_code=404, detail="Scan not found")
    items, total = crud.list_pull_requests(db, user_id=user.id, scan_id=scan_id)
    return {"items": items, "total": total}


@router.post("/scans/{scan_id}/create-pr", status_code=202)
async def create_pr_for_scan(scan_id: str, user: CurrentUser, db: DB) -> dict:
    """
    Manually trigger PR creation for a completed scan.
    Useful if the auto-PR failed or was skipped.
    """
    row = crud.get_scan(db, scan_id)
    if not row or row.user_id != user.id:
        raise HTTPException(status_code=404, detail="Scan not found")
    if row.status != PipelineStatus.COMPLETE.value:
        raise HTTPException(status_code=409, detail="Scan has not completed yet")
    if not row.github_repo:
        raise HTTPException(status_code=400, detail="Scan is not linked to a GitHub repository")
    if not user.github_access_token:
        raise HTTPException(status_code=400, detail="No GitHub token available")

    # Load patches
    patches_dicts, _ = crud.get_patches(db, scan_id)
    if not patches_dicts:
        raise HTTPException(status_code=400, detail="No patches to create a PR for")

    # Run PR creation in background thread
    from loopsec.api.background import _create_github_pr
    from loopsec.core.models import (
        Finding, FindingSource, Patch, PatchStatus, PipelineState,
        PipelineStatus as PS, ScanTarget, Severity,
    )
    from loopsec.api.db.models import FindingORM, PatchORM
    from sqlalchemy import select
    import json

    findings_orm = db.execute(select(FindingORM).where(FindingORM.scan_id == scan_id)).scalars().all()
    patches_orm  = db.execute(select(PatchORM).where(PatchORM.scan_id == scan_id)).scalars().all()

    findings = [
        Finding(
            id=f.id, source=FindingSource(f.source), severity=Severity(f.severity),
            title=f.title, description=f.description, cwe_id=f.cwe_id,
            owasp_category=f.owasp_category, file_path=f.file_path,
            line_start=f.line_start, line_end=f.line_end,
            code_snippet=f.code_snippet, endpoint=f.endpoint,
            http_method=f.http_method, tool=f.tool, rule_id=f.rule_id,
        )
        for f in findings_orm
    ]
    patches = [
        Patch(
            id=p.id, finding_id=p.finding_id, file_path=p.file_path,
            original_code=p.original_code, patched_code=p.patched_code,
            diff=p.diff, explanation=p.explanation, status=PatchStatus(p.status),
            passes_sast=p.passes_sast, passes_tests=p.passes_tests,
            exploit_mitigated=p.exploit_mitigated,
        )
        for p in patches_orm
    ]

    state = PipelineState(
        id=scan_id,
        status=PS(row.status),
        target=ScanTarget(
            repo_path=row.repo_path,
            app_url=row.app_url,
            branch=row.branch,
            languages=json.loads(row.languages or "[]"),
        ),
        findings=findings,
        patches=patches,
    )

    pr_record = await asyncio.to_thread(
        _create_github_pr,
        scan_id, user.id, row.github_repo, user.github_access_token, row.branch, state
    )
    return pr_record
