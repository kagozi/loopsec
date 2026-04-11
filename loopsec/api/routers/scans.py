"""
Scan lifecycle endpoints.

POST /scans          — trigger a new scan (returns immediately with scan_id)
GET  /scans          — list all scans with pagination
GET  /scans/{id}     — get full scan details
DELETE /scans/{id}   — delete a scan and all its data
GET  /scans/{id}/report — download markdown report
"""

from __future__ import annotations

import uuid
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from loopsec.api import background
from loopsec.api.db import crud
from loopsec.api.dependencies import get_db
from loopsec.core.models import PipelineStatus

router = APIRouter()

DB = Annotated[Session, Depends(get_db)]


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    repo_path: str
    app_url: str | None = None
    branch: str = "main"
    skip_agents: list[str] = []
    auto_deploy: bool = True


class ScanCreatedResponse(BaseModel):
    scan_id: str
    status: str
    stream_url: str


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("", status_code=202, response_model=ScanCreatedResponse)
async def create_scan(
    body: ScanRequest,
    background_tasks: BackgroundTasks,
    db: DB,
) -> ScanCreatedResponse:
    """Trigger a new scan. Returns immediately; use the stream_url for live progress."""
    # Validate repo path
    repo = Path(body.repo_path).resolve()
    if not repo.exists():
        raise HTTPException(status_code=400, detail=f"repo_path not found: {repo}")

    scan_id = uuid.uuid4().hex[:12]
    crud.create_scan(db, scan_id, str(repo), body.app_url, body.branch)

    background_tasks.add_task(
        background.run_pipeline_task,
        scan_id=scan_id,
        repo_path=str(repo),
        app_url=body.app_url,
        branch=body.branch,
        skip_agents=body.skip_agents,
        auto_deploy=body.auto_deploy,
    )

    return ScanCreatedResponse(
        scan_id=scan_id,
        status=PipelineStatus.QUEUED.value,
        stream_url=f"/scans/{scan_id}/stream",
    )


@router.get("")
def list_scans(
    db: DB,
    limit: int = 20,
    offset: int = 0,
    status: str | None = None,
) -> dict:
    """List all scans, newest first. Optionally filter by status."""
    items, total = crud.list_scans(db, limit=limit, offset=offset, status=status)
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/{scan_id}")
def get_scan(scan_id: str, db: DB) -> dict:
    """Get full details for a single scan."""
    data = crud.get_scan_dict(db, scan_id)
    if not data:
        raise HTTPException(status_code=404, detail="Scan not found")
    return data


@router.delete("/{scan_id}", status_code=204)
def delete_scan(scan_id: str, db: DB) -> None:
    """Delete a scan and all its findings, exploits, and patches."""
    row = crud.get_scan(db, scan_id)
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")

    in_progress = {
        PipelineStatus.QUEUED.value,
        PipelineStatus.ANALYZING.value,
        PipelineStatus.DEPLOYING.value,
        PipelineStatus.ATTACKING.value,
        PipelineStatus.MAPPING.value,
        PipelineStatus.FIXING.value,
        PipelineStatus.VERIFYING.value,
    }
    if row.status in in_progress:
        raise HTTPException(status_code=409, detail="Cannot delete a scan that is still running")

    crud.delete_scan(db, scan_id)


@router.get("/{scan_id}/report", response_class=PlainTextResponse)
def download_report(scan_id: str, db: DB) -> str:
    """Download the markdown report for a completed scan."""
    row = crud.get_scan(db, scan_id)
    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")
    if row.status not in (PipelineStatus.COMPLETE.value, PipelineStatus.ERRORED.value):
        raise HTTPException(status_code=409, detail="Scan has not completed yet")

    # Reconstruct PipelineState from DB and generate report
    import json
    from loopsec.core.models import (
        Exploit, Finding, FindingSource, MappedVulnerability,
        Patch, PatchStatus, PipelineState, PipelineStatus as PS,
        ScanTarget, Severity,
    )
    from loopsec.core.orchestrator import generate_report
    from loopsec.api.db.models import FindingORM, ExploitORM, PatchORM
    from sqlalchemy import select

    with db:
        findings_orm = db.execute(
            select(FindingORM).where(FindingORM.scan_id == scan_id)
        ).scalars().all()
        exploits_orm = db.execute(
            select(ExploitORM).where(ExploitORM.scan_id == scan_id)
        ).scalars().all()
        patches_orm = db.execute(
            select(PatchORM).where(PatchORM.scan_id == scan_id)
        ).scalars().all()

    findings = [
        Finding(
            id=f.id, source=FindingSource(f.source), severity=Severity(f.severity),
            title=f.title, description=f.description, cwe_id=f.cwe_id,
            owasp_category=f.owasp_category, file_path=f.file_path,
            line_start=f.line_start, line_end=f.line_end, function_name=f.function_name,
            code_snippet=f.code_snippet, endpoint=f.endpoint, http_method=f.http_method,
            parameter=f.parameter, tool=f.tool, rule_id=f.rule_id,
            raw_output=json.loads(f.raw_output) if f.raw_output else None,
            created_at=f.created_at,
        )
        for f in findings_orm
    ]
    exploits = [
        Exploit(
            id=e.id, finding_id=e.finding_id, description=e.description,
            request=e.request, response_snippet=e.response_snippet,
            steps=json.loads(e.steps or "[]"), verified=e.verified,
        )
        for e in exploits_orm
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
    mapped_vulns = [
        MappedVulnerability(**mv)
        for mv in json.loads(row.mapped_vulns_json or "[]")
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
        exploits=exploits,
        patches=patches,
        mapped_vulnerabilities=mapped_vulns,
        verified_fixes=json.loads(row.verified_fixes or "[]"),
        still_open=json.loads(row.still_open or "[]"),
        regressions=json.loads(row.regressions or "[]"),
        errors=json.loads(row.errors or "[]"),
        started_at=row.started_at,
        completed_at=row.completed_at,
        sandbox_container_id=row.sandbox_container_id,
    )

    return generate_report(state)
