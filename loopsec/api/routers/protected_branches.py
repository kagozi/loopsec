"""
Branch Protection endpoints.

POST   /protected-branches              — protect a branch (registers GitHub webhook)
GET    /protected-branches              — list user's protected branches
PATCH  /protected-branches/{id}        — enable / disable
DELETE /protected-branches/{id}        — remove protection (deletes webhook if last for repo)

POST   /webhooks/github                 — GitHub push webhook (public, HMAC-verified)
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import uuid
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from loopsec.api.auth.dependencies import CurrentUser
from loopsec.api.db import crud
from loopsec.api.db.crud import (
    count_protections_for_repo,
    create_protected_branch,
    delete_protected_branch,
    get_protected_branch,
    get_protections_for_push,
    get_user_by_id,
    list_protected_branches,
    set_protected_branch_webhook,
    update_protected_branch_enabled,
)
from loopsec.api.db.engine import SessionLocal
from loopsec.api.dependencies import get_db

logger = logging.getLogger(__name__)
router = APIRouter()
DB = Annotated[Session, Depends(get_db)]

_WEBHOOK_SECRET = os.getenv("LOOPSEC_WEBHOOK_SECRET", "")
_PUBLIC_URL = os.getenv("LOOPSEC_PUBLIC_URL", "http://localhost:8000").rstrip("/")


# ─── Pydantic schemas ────────────────────────────────────────────────────────

class CreateProtectedBranch(BaseModel):
    github_repo: str   # "owner/repo"
    branch: str


class PatchProtectedBranch(BaseModel):
    enabled: bool


# ─── CRUD endpoints ──────────────────────────────────────────────────────────

@router.get("/protected-branches")
def list_branches(user: CurrentUser, db: DB) -> dict:
    items = list_protected_branches(db, user.id)
    return {"items": items, "total": len(items)}


@router.post("/protected-branches", status_code=201)
def create_branch_protection(body: CreateProtectedBranch, user: CurrentUser, db: DB) -> dict:
    """Protect a branch. Registers a GitHub push webhook if one doesn't exist for this repo."""
    # Prevent duplicates
    existing = list_protected_branches(db, user.id)
    for pb in existing:
        if pb["github_repo"] == body.github_repo and pb["branch"] == body.branch:
            raise HTTPException(status_code=409, detail="Branch already protected")

    if not _WEBHOOK_SECRET:
        raise HTTPException(
            status_code=503,
            detail="LOOPSEC_WEBHOOK_SECRET is not configured on the server",
        )

    # Create the DB record first (we need the ID)
    pb = create_protected_branch(
        db,
        user_id=user.id,
        github_repo=body.github_repo,
        branch=body.branch,
    )

    # Register GitHub webhook (or reuse existing one for the same user+repo)
    webhook_id: int | None = None
    existing_webhook_id = _find_existing_webhook_id(db, user.id, body.github_repo, pb.id)

    if existing_webhook_id:
        webhook_id = existing_webhook_id
        set_protected_branch_webhook(db, pb.id, webhook_id, _WEBHOOK_SECRET)
    else:
        # Register new webhook with GitHub
        try:
            owner, repo_name = body.github_repo.split("/", 1)
            from loopsec.integrations.github import GitHubClient
            gh = GitHubClient(token=user.github_access_token)
            webhook_url = f"{_PUBLIC_URL}/webhooks/github"
            webhook_id = gh.create_webhook(owner, repo_name, webhook_url, _WEBHOOK_SECRET)
            set_protected_branch_webhook(db, pb.id, webhook_id, _WEBHOOK_SECRET)
            logger.info("Registered webhook %s for %s", webhook_id, body.github_repo)
        except Exception as exc:
            logger.warning("Failed to register webhook for %s: %s", body.github_repo, exc)
            # Don't fail the request — protection is saved, webhook can be retried

    db.refresh(pb)
    return crud._pb_to_dict(pb)


@router.patch("/protected-branches/{pb_id}")
def toggle_protection(pb_id: str, body: PatchProtectedBranch, user: CurrentUser, db: DB) -> dict:
    pb = get_protected_branch(db, pb_id)
    if not pb or pb.user_id != user.id:
        raise HTTPException(status_code=404, detail="Not found")
    updated = update_protected_branch_enabled(db, pb_id, body.enabled)
    return crud._pb_to_dict(updated)


@router.delete("/protected-branches/{pb_id}", status_code=204)
def remove_protection(pb_id: str, user: CurrentUser, db: DB) -> None:
    pb = get_protected_branch(db, pb_id)
    if not pb or pb.user_id != user.id:
        raise HTTPException(status_code=404, detail="Not found")

    webhook_id = pb.webhook_id
    github_repo = pb.github_repo

    delete_protected_branch(db, pb_id)

    # If this was the last protection for this user+repo, delete the webhook
    remaining = count_protections_for_repo(db, user.id, github_repo)
    if remaining == 0 and webhook_id:
        try:
            owner, repo_name = github_repo.split("/", 1)
            from loopsec.integrations.github import GitHubClient
            gh = GitHubClient(token=user.github_access_token)
            gh.delete_webhook(owner, repo_name, webhook_id)
            logger.info("Deleted webhook %s for %s", webhook_id, github_repo)
        except Exception as exc:
            logger.warning("Failed to delete webhook %s: %s", webhook_id, exc)


# ─── GitHub webhook receiver ─────────────────────────────────────────────────

@router.post("/webhooks/github", status_code=202)
async def github_webhook(request: Request, background_tasks: BackgroundTasks) -> dict:
    """
    Receives GitHub push events.
    Verifies HMAC signature, matches protected branch rules,
    and triggers the security pipeline for each match.
    """
    raw_body = await request.body()

    # Verify signature
    if _WEBHOOK_SECRET:
        sig_header = request.headers.get("X-Hub-Signature-256", "")
        expected = "sha256=" + hmac.new(
            _WEBHOOK_SECRET.encode(), raw_body, hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, sig_header):
            raise HTTPException(status_code=401, detail="Invalid webhook signature")

    event = request.headers.get("X-GitHub-Event", "")
    if event == "ping":
        return {"ok": True}
    if event != "push":
        return {"ok": True, "skipped": f"event={event}"}

    import json
    payload = json.loads(raw_body)

    # Extract repo and branch
    ref = payload.get("ref", "")
    if not ref.startswith("refs/heads/"):
        return {"ok": True, "skipped": "not a branch push"}

    branch = ref[len("refs/heads/"):]
    github_repo = payload.get("repository", {}).get("full_name", "")
    if not github_repo:
        return {"ok": True, "skipped": "no repo"}

    logger.info("Webhook push: %s@%s", github_repo, branch)

    # Find matching protected branch rules
    with SessionLocal() as db:
        rules = get_protections_for_push(db, github_repo, branch)
        if not rules:
            return {"ok": True, "skipped": "no matching protection rules"}

        triggered = []
        for pb in rules:
            user = get_user_by_id(db, pb.user_id)
            if not user or not user.github_access_token:
                continue
            scan_id = uuid.uuid4().hex[:12]
            crud.create_scan(
                db,
                scan_id=scan_id,
                repo_path=f"github:{github_repo}",
                app_url=None,
                branch=branch,
                user_id=pb.user_id,
                github_repo=github_repo,
            )
            background_tasks.add_task(
                _trigger_pipeline,
                scan_id=scan_id,
                github_repo=github_repo,
                github_token=user.github_access_token,
                branch=branch,
                user_id=pb.user_id,
            )
            triggered.append(scan_id)
            logger.info("Triggered scan %s for %s@%s (user %s)", scan_id, github_repo, branch, pb.user_id)

    return {"ok": True, "triggered": triggered}


async def _trigger_pipeline(
    scan_id: str,
    github_repo: str,
    github_token: str,
    branch: str,
    user_id: str,
) -> None:
    from loopsec.api.background import run_pipeline_task
    await run_pipeline_task(
        scan_id=scan_id,
        repo_path=None,
        app_url=None,
        branch=branch,
        skip_agents=[],
        auto_deploy=False,   # skip Docker deployment for CI scans
        github_repo=github_repo,
        github_token=github_token,
        user_id=user_id,
    )


# ─── Internal helper ─────────────────────────────────────────────────────────

def _find_existing_webhook_id(db: Session, user_id: str, github_repo: str, exclude_id: str) -> int | None:
    """Find an existing webhook_id for this user+repo from other protection rules."""
    from sqlalchemy import select
    from loopsec.api.db.models import ProtectedBranchORM
    row = db.execute(
        select(ProtectedBranchORM)
        .where(
            ProtectedBranchORM.user_id == user_id,
            ProtectedBranchORM.github_repo == github_repo,
            ProtectedBranchORM.id != exclude_id,
            ProtectedBranchORM.webhook_id.isnot(None),
        )
        .limit(1)
    ).scalar_one_or_none()
    return row.webhook_id if row else None
