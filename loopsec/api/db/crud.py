"""
All database read/write operations. No SQL in routers — only here.
All functions are synchronous (called from threads or directly from async handlers).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from loopsec.api.db.models import ExploitORM, FindingORM, PatchORM, ScanORM
from loopsec.core.models import PipelineState, PipelineStatus


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------

def _j(v: Any) -> str:
    return json.dumps(v) if v is not None else "[]"


def _scan_to_dict(scan: ScanORM) -> dict:
    return {
        "scan_id": scan.id,
        "status": scan.status,
        "repo_path": scan.repo_path,
        "app_url": scan.app_url,
        "branch": scan.branch,
        "languages": json.loads(scan.languages or "[]"),
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "errors": json.loads(scan.errors or "[]"),
        "sandbox_container_id": scan.sandbox_container_id,
        "verified_fixes": json.loads(scan.verified_fixes or "[]"),
        "still_open": json.loads(scan.still_open or "[]"),
        "regressions": json.loads(scan.regressions or "[]"),
        "summary": json.loads(scan.summary_json) if scan.summary_json else None,
        "created_at": scan.created_at.isoformat() if scan.created_at else None,
    }


def _finding_to_dict(f: FindingORM) -> dict:
    return {
        "id": f.id,
        "scan_id": f.scan_id,
        "source": f.source,
        "severity": f.severity,
        "title": f.title,
        "description": f.description,
        "cwe_id": f.cwe_id,
        "owasp_category": f.owasp_category,
        "file_path": f.file_path,
        "line_start": f.line_start,
        "line_end": f.line_end,
        "function_name": f.function_name,
        "code_snippet": f.code_snippet,
        "endpoint": f.endpoint,
        "http_method": f.http_method,
        "parameter": f.parameter,
        "tool": f.tool,
        "rule_id": f.rule_id,
        "raw_output": json.loads(f.raw_output) if f.raw_output else None,
        "created_at": f.created_at.isoformat() if f.created_at else None,
    }


def _exploit_to_dict(e: ExploitORM) -> dict:
    return {
        "id": e.id,
        "scan_id": e.scan_id,
        "finding_id": e.finding_id,
        "description": e.description,
        "request": e.request,
        "response_snippet": e.response_snippet,
        "steps": json.loads(e.steps or "[]"),
        "verified": e.verified,
    }


def _patch_to_dict(p: PatchORM) -> dict:
    return {
        "id": p.id,
        "scan_id": p.scan_id,
        "finding_id": p.finding_id,
        "file_path": p.file_path,
        "original_code": p.original_code,
        "patched_code": p.patched_code,
        "diff": p.diff,
        "explanation": p.explanation,
        "status": p.status,
        "passes_sast": p.passes_sast,
        "passes_tests": p.passes_tests,
        "exploit_mitigated": p.exploit_mitigated,
    }


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------

def create_scan(
    db: Session,
    scan_id: str,
    repo_path: str,
    app_url: str | None,
    branch: str,
) -> ScanORM:
    now = datetime.now(timezone.utc)
    row = ScanORM(
        id=scan_id,
        status=PipelineStatus.QUEUED.value,
        repo_path=repo_path,
        app_url=app_url,
        branch=branch,
        started_at=now,
        created_at=now,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def get_scan(db: Session, scan_id: str) -> ScanORM | None:
    return db.get(ScanORM, scan_id)


def get_scan_dict(db: Session, scan_id: str) -> dict | None:
    row = get_scan(db, scan_id)
    return _scan_to_dict(row) if row else None


def list_scans(
    db: Session,
    limit: int = 20,
    offset: int = 0,
    status: str | None = None,
) -> tuple[list[dict], int]:
    stmt = select(ScanORM).order_by(ScanORM.created_at.desc())
    count_stmt = select(func.count()).select_from(ScanORM)
    if status:
        stmt = stmt.where(ScanORM.status == status)
        count_stmt = count_stmt.where(ScanORM.status == status)
    total = db.execute(count_stmt).scalar_one()
    rows = db.execute(stmt.offset(offset).limit(limit)).scalars().all()
    return [_scan_to_dict(r) for r in rows], total


def update_scan_status(db: Session, scan_id: str, status: str) -> None:
    row = db.get(ScanORM, scan_id)
    if row:
        row.status = status
        db.commit()


def save_pipeline_state(db: Session, scan_id: str, state: PipelineState) -> None:
    """Persist the full PipelineState to the DB after the pipeline finishes."""
    row = db.get(ScanORM, scan_id)
    if not row:
        return

    row.status = state.status.value
    row.completed_at = state.completed_at
    row.errors = _j(state.errors)
    row.sandbox_container_id = state.sandbox_container_id
    row.verified_fixes = _j(state.verified_fixes)
    row.still_open = _j(state.still_open)
    row.regressions = _j(state.regressions)
    row.languages = _j(state.target.languages)
    row.app_url = state.target.app_url
    row.summary_json = json.dumps(state.summary())
    row.mapped_vulns_json = json.dumps(
        [mv.model_dump() for mv in state.mapped_vulnerabilities]
    )

    # Bulk-insert findings
    for f in state.findings:
        if not db.get(FindingORM, f.id):
            db.add(FindingORM(
                id=f.id,
                scan_id=scan_id,
                source=f.source.value,
                severity=f.severity.value,
                title=f.title,
                description=f.description,
                cwe_id=f.cwe_id,
                owasp_category=f.owasp_category,
                file_path=f.file_path,
                line_start=f.line_start,
                line_end=f.line_end,
                function_name=f.function_name,
                code_snippet=f.code_snippet,
                endpoint=f.endpoint,
                http_method=f.http_method,
                parameter=f.parameter,
                tool=f.tool,
                rule_id=f.rule_id,
                raw_output=json.dumps(f.raw_output) if f.raw_output else None,
                created_at=f.created_at,
            ))

    # Bulk-insert exploits
    for e in state.exploits:
        if not db.get(ExploitORM, e.id):
            db.add(ExploitORM(
                id=e.id,
                scan_id=scan_id,
                finding_id=e.finding_id,
                description=e.description,
                request=e.request,
                response_snippet=e.response_snippet,
                steps=_j(e.steps),
                verified=e.verified,
            ))

    # Bulk-insert patches
    for p in state.patches:
        if not db.get(PatchORM, p.id):
            db.add(PatchORM(
                id=p.id,
                scan_id=scan_id,
                finding_id=p.finding_id,
                file_path=p.file_path,
                original_code=p.original_code,
                patched_code=p.patched_code,
                diff=p.diff,
                explanation=p.explanation,
                status=p.status.value,
                passes_sast=p.passes_sast,
                passes_tests=p.passes_tests,
                exploit_mitigated=p.exploit_mitigated,
            ))

    db.commit()


def delete_scan(db: Session, scan_id: str) -> bool:
    row = db.get(ScanORM, scan_id)
    if not row:
        return False
    db.delete(row)
    db.commit()
    return True


def cleanup_stale_scans(db: Session) -> int:
    """
    On startup, mark any in-progress scans as errored.
    They were running when the server last crashed/restarted.
    """
    in_progress = [
        PipelineStatus.QUEUED.value,
        PipelineStatus.ANALYZING.value,
        PipelineStatus.DEPLOYING.value,
        PipelineStatus.ATTACKING.value,
        PipelineStatus.MAPPING.value,
        PipelineStatus.FIXING.value,
        PipelineStatus.VERIFYING.value,
    ]
    rows = db.execute(
        select(ScanORM).where(ScanORM.status.in_(in_progress))
    ).scalars().all()
    for row in rows:
        row.status = PipelineStatus.ERRORED.value
        existing = json.loads(row.errors or "[]")
        existing.append("Server restarted during scan")
        row.errors = json.dumps(existing)
    if rows:
        db.commit()
    return len(rows)


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

def get_findings(
    db: Session,
    scan_id: str,
    severity: str | None = None,
    source: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[dict], int]:
    stmt = select(FindingORM).where(FindingORM.scan_id == scan_id)
    count_stmt = select(func.count()).select_from(FindingORM).where(FindingORM.scan_id == scan_id)
    if severity:
        stmt = stmt.where(FindingORM.severity == severity)
        count_stmt = count_stmt.where(FindingORM.severity == severity)
    if source:
        stmt = stmt.where(FindingORM.source == source)
        count_stmt = count_stmt.where(FindingORM.source == source)
    total = db.execute(count_stmt).scalar_one()
    rows = db.execute(stmt.offset(offset).limit(limit)).scalars().all()
    return [_finding_to_dict(r) for r in rows], total


def get_finding(db: Session, finding_id: str) -> dict | None:
    row = db.get(FindingORM, finding_id)
    return _finding_to_dict(row) if row else None


# ---------------------------------------------------------------------------
# Exploits
# ---------------------------------------------------------------------------

def get_exploits(
    db: Session,
    scan_id: str,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[dict], int]:
    stmt = select(ExploitORM).where(ExploitORM.scan_id == scan_id)
    count_stmt = select(func.count()).select_from(ExploitORM).where(ExploitORM.scan_id == scan_id)
    total = db.execute(count_stmt).scalar_one()
    rows = db.execute(stmt.offset(offset).limit(limit)).scalars().all()
    return [_exploit_to_dict(r) for r in rows], total


# ---------------------------------------------------------------------------
# Patches
# ---------------------------------------------------------------------------

def get_patches(
    db: Session,
    scan_id: str,
    status: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[dict], int]:
    stmt = select(PatchORM).where(PatchORM.scan_id == scan_id)
    count_stmt = select(func.count()).select_from(PatchORM).where(PatchORM.scan_id == scan_id)
    if status:
        stmt = stmt.where(PatchORM.status == status)
        count_stmt = count_stmt.where(PatchORM.status == status)
    total = db.execute(count_stmt).scalar_one()
    rows = db.execute(stmt.offset(offset).limit(limit)).scalars().all()
    return [_patch_to_dict(r) for r in rows], total


def get_patch(db: Session, patch_id: str) -> dict | None:
    row = db.get(PatchORM, patch_id)
    return _patch_to_dict(row) if row else None
