"""
Scan lifecycle endpoints. All endpoints require authentication.

POST /scans          — trigger a new scan (local path or GitHub repo)
GET  /scans          — list the current user's scans
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
from pydantic import BaseModel, model_validator
from sqlalchemy.orm import Session

from loopsec.api import background
from loopsec.api.auth.dependencies import CurrentUser
from loopsec.api.db import crud
from loopsec.api.dependencies import get_db
from loopsec.core.models import PipelineStatus

router = APIRouter()

DB = Annotated[Session, Depends(get_db)]


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    # Provide exactly one of repo_path (local) or github_repo ("owner/repo")
    repo_path: str | None = None
    github_repo: str | None = None
    app_url: str | None = None
    branch: str = "main"
    skip_agents: list[str] = []
    auto_deploy: bool = True

    @model_validator(mode="after")
    def check_source(self) -> "ScanRequest":
        if not self.repo_path and not self.github_repo:
            raise ValueError("Provide either repo_path (local) or github_repo (owner/repo)")
        if self.repo_path and self.github_repo:
            raise ValueError("Provide only one of repo_path or github_repo, not both")
        return self


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
    user: CurrentUser,
    db: DB,
) -> ScanCreatedResponse:
    """
    Trigger a new scan. Returns immediately with a scan_id.
    Subscribe to stream_url for live progress via SSE.

    Supply either:
      - repo_path: absolute local path to source code, OR
      - github_repo: "owner/repo" string (will be cloned using your GitHub token)
    """
    scan_id = uuid.uuid4().hex[:12]

    if body.github_repo:
        # Placeholder path — background task will clone to a temp dir
        repo_path = f"github:{body.github_repo}"
        crud.create_scan(
            db, scan_id, repo_path, body.app_url, body.branch,
            user_id=user.id, github_repo=body.github_repo,
        )
        background_tasks.add_task(
            background.run_pipeline_task,
            scan_id=scan_id,
            repo_path=None,
            app_url=body.app_url,
            branch=body.branch,
            skip_agents=body.skip_agents,
            auto_deploy=body.auto_deploy,
            github_repo=body.github_repo,
            github_token=user.github_access_token,
            user_id=user.id,
        )
    else:
        repo = Path(body.repo_path).resolve()  # type: ignore[arg-type]
        if not repo.exists():
            raise HTTPException(status_code=400, detail=f"repo_path not found: {repo}")
        crud.create_scan(
            db, scan_id, str(repo), body.app_url, body.branch,
            user_id=user.id,
        )
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
    user: CurrentUser,
    db: DB,
    limit: int = 20,
    offset: int = 0,
    status: str | None = None,
) -> dict:
    """List the current user's scans, newest first."""
    items, total = crud.list_scans(db, user_id=user.id, limit=limit, offset=offset, status=status)
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/{scan_id}")
def get_scan(scan_id: str, user: CurrentUser, db: DB) -> dict:
    """Get full details for a single scan (must belong to the current user)."""
    data = crud.get_scan_dict(db, scan_id)
    if not data:
        raise HTTPException(status_code=404, detail="Scan not found")
    if data.get("user_id") != user.id:
        raise HTTPException(status_code=404, detail="Scan not found")
    return data


@router.delete("/{scan_id}", status_code=204)
def delete_scan(scan_id: str, user: CurrentUser, db: DB) -> None:
    """Delete a scan and all its findings, exploits, and patches."""
    row = crud.get_scan(db, scan_id)
    if not row or row.user_id != user.id:
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
def download_report(scan_id: str, user: CurrentUser, db: DB) -> str:
    """Download the markdown report for a completed scan."""
    row = crud.get_scan(db, scan_id)
    if not row or row.user_id != user.id:
        raise HTTPException(status_code=404, detail="Scan not found")
    if row.status not in (PipelineStatus.COMPLETE.value, PipelineStatus.ERRORED.value):
        raise HTTPException(status_code=409, detail="Scan has not completed yet")

    import json
    from loopsec.core.models import (
        Exploit, Finding, FindingSource, MappedVulnerability,
        Patch, PatchStatus, PipelineState, PipelineStatus as PS,
        ScanTarget, Severity,
    )
    from loopsec.core.orchestrator import generate_report
    from loopsec.api.db.models import FindingORM, ExploitORM, PatchORM
    from sqlalchemy import select

    findings_orm = db.execute(select(FindingORM).where(FindingORM.scan_id == scan_id)).scalars().all()
    exploits_orm = db.execute(select(ExploitORM).where(ExploitORM.scan_id == scan_id)).scalars().all()
    patches_orm = db.execute(select(PatchORM).where(PatchORM.scan_id == scan_id)).scalars().all()

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
