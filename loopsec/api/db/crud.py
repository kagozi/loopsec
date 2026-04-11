"""
All database read/write operations. No SQL in routers — only here.
All functions are synchronous (called from threads or directly from async handlers).
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from loopsec.api.db.models import ExploitORM, FindingORM, PatchORM, PullRequestORM, ScanORM, UserORM
from loopsec.core.models import PipelineState, PipelineStatus


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------

def _j(v: Any) -> str:
    return json.dumps(v) if v is not None else "[]"


def _scan_to_dict(scan: ScanORM) -> dict:
    return {
        "scan_id": scan.id,
        "user_id": scan.user_id,
        "status": scan.status,
        "repo_path": scan.repo_path,
        "github_repo": scan.github_repo,
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


def _user_to_dict(u: UserORM) -> dict:
    return {
        "id": u.id,
        "github_login": u.github_login,
        "github_name": u.github_name,
        "github_avatar_url": u.github_avatar_url,
        "github_email": u.github_email,
        "created_at": u.created_at.isoformat() if u.created_at else None,
        "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
    }


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

def upsert_user(
    db: Session,
    github_id: int,
    github_login: str,
    github_name: str | None,
    github_avatar_url: str | None,
    github_email: str | None,
    github_access_token: str,
) -> UserORM:
    """Create a new user or update their token on re-login."""
    now = datetime.now(timezone.utc)
    row = db.execute(
        select(UserORM).where(UserORM.github_id == github_id)
    ).scalar_one_or_none()

    if row:
        row.github_login = github_login
        row.github_name = github_name
        row.github_avatar_url = github_avatar_url
        row.github_email = github_email
        row.github_access_token = github_access_token
        row.last_login_at = now
    else:
        row = UserORM(
            id=uuid.uuid4().hex[:12],
            github_id=github_id,
            github_login=github_login,
            github_name=github_name,
            github_avatar_url=github_avatar_url,
            github_email=github_email,
            github_access_token=github_access_token,
            created_at=now,
            last_login_at=now,
        )
        db.add(row)

    db.commit()
    db.refresh(row)
    return row


def get_user_by_id(db: Session, user_id: str) -> UserORM | None:
    return db.get(UserORM, user_id)


def get_user_dict(db: Session, user_id: str) -> dict | None:
    row = get_user_by_id(db, user_id)
    return _user_to_dict(row) if row else None


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------

def create_scan(
    db: Session,
    scan_id: str,
    repo_path: str,
    app_url: str | None,
    branch: str,
    user_id: str | None = None,
    github_repo: str | None = None,
) -> ScanORM:
    now = datetime.now(timezone.utc)
    row = ScanORM(
        id=scan_id,
        user_id=user_id,
        status=PipelineStatus.QUEUED.value,
        repo_path=repo_path,
        github_repo=github_repo,
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
    user_id: str | None = None,
    limit: int = 20,
    offset: int = 0,
    status: str | None = None,
) -> tuple[list[dict], int]:
    stmt = select(ScanORM).order_by(ScanORM.created_at.desc())
    count_stmt = select(func.count()).select_from(ScanORM)
    if user_id:
        stmt = stmt.where(ScanORM.user_id == user_id)
        count_stmt = count_stmt.where(ScanORM.user_id == user_id)
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


# ---------------------------------------------------------------------------
# Pull Requests
# ---------------------------------------------------------------------------

def _pr_to_dict(pr: PullRequestORM) -> dict:
    return {
        "id": pr.id,
        "scan_id": pr.scan_id,
        "github_repo": pr.github_repo,
        "pr_number": pr.pr_number,
        "pr_url": pr.pr_url,
        "branch": pr.branch,
        "base_branch": pr.base_branch,
        "title": pr.title,
        "patch_count": pr.patch_count,
        "status": pr.status,
        "error": pr.error,
        "created_at": pr.created_at.isoformat() if pr.created_at else None,
    }


def create_pull_request(
    db: Session,
    *,
    scan_id: str,
    user_id: str | None,
    github_repo: str,
    pr_number: int | None,
    pr_url: str | None,
    branch: str,
    base_branch: str,
    title: str,
    patch_count: int,
    status: str = "open",
    error: str | None = None,
) -> PullRequestORM:
    pr = PullRequestORM(
        id=uuid.uuid4().hex[:12],
        scan_id=scan_id,
        user_id=user_id,
        github_repo=github_repo,
        pr_number=pr_number,
        pr_url=pr_url,
        branch=branch,
        base_branch=base_branch,
        title=title,
        patch_count=patch_count,
        status=status,
        error=error,
        created_at=datetime.now(timezone.utc),
    )
    db.add(pr)
    db.commit()
    db.refresh(pr)
    return pr


def list_pull_requests(
    db: Session,
    user_id: str,
    scan_id: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict], int]:
    stmt = (
        select(PullRequestORM)
        .join(ScanORM, PullRequestORM.scan_id == ScanORM.id)
        .where(ScanORM.user_id == user_id)
    )
    count_stmt = (
        select(func.count())
        .select_from(PullRequestORM)
        .join(ScanORM, PullRequestORM.scan_id == ScanORM.id)
        .where(ScanORM.user_id == user_id)
    )
    if scan_id:
        stmt = stmt.where(PullRequestORM.scan_id == scan_id)
        count_stmt = count_stmt.where(PullRequestORM.scan_id == scan_id)
    total = db.execute(count_stmt).scalar_one()
    rows = db.execute(stmt.order_by(PullRequestORM.created_at.desc()).offset(offset).limit(limit)).scalars().all()
    return [_pr_to_dict(r) for r in rows], total
