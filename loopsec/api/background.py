"""
Background pipeline runner.

Wraps the synchronous Orchestrator.run() in asyncio.to_thread() so it
doesn't block the FastAPI event loop. Supports both local paths and
GitHub repos (cloned on the fly using the user's GitHub token).
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import tempfile
from pathlib import Path

from loopsec.api import events
from loopsec.api.db.crud import create_pull_request, save_pipeline_state, update_scan_status
from loopsec.api.db.engine import SessionLocal
from loopsec.core.models import PipelineState, PipelineStatus, PatchStatus

logger = logging.getLogger(__name__)


async def run_pipeline_task(
    scan_id: str,
    repo_path: str | None,
    app_url: str | None,
    branch: str,
    skip_agents: list[str],
    auto_deploy: bool,
    github_repo: str | None = None,
    github_token: str | None = None,
    user_id: str | None = None,
) -> None:
    """
    Async background task. Emits SSE events at key milestones.
    Accepts either a local repo_path or a github_repo + github_token to clone.
    """
    await events.publish(scan_id, {"type": "status_change", "status": PipelineStatus.ANALYZING.value})
    with SessionLocal() as db:
        update_scan_status(db, scan_id, PipelineStatus.ANALYZING.value)

    clone_dir: str | None = None

    try:
        if github_repo and github_token:
            # Clone the repo to a temp dir
            await events.publish(scan_id, {
                "type": "status_change",
                "status": "cloning",
                "message": f"Cloning {github_repo}@{branch}...",
            })
            clone_dir = await asyncio.to_thread(
                _clone_github_repo, github_repo, branch, github_token
            )
            actual_repo_path = clone_dir
            # Update the stored repo_path to the actual clone path
            with SessionLocal() as db:
                from loopsec.api.db.models import ScanORM
                row = db.get(ScanORM, scan_id)
                if row:
                    row.repo_path = clone_dir
                    db.commit()
        else:
            actual_repo_path = repo_path  # type: ignore[assignment]

        # Build a thread-safe callback that publishes events to the async event bus
        loop = asyncio.get_running_loop()

        def _progress_callback(payload: dict) -> None:
            asyncio.run_coroutine_threadsafe(events.publish(scan_id, payload), loop)

        state: PipelineState = await asyncio.to_thread(
            _run_sync,
            actual_repo_path,
            app_url,
            branch,
            skip_agents,
            auto_deploy,
            _progress_callback,
        )

    except Exception as exc:
        logger.exception("Pipeline failed for scan %s", scan_id)
        with SessionLocal() as db:
            update_scan_status(db, scan_id, PipelineStatus.ERRORED.value)
        await events.publish(scan_id, {"type": "error", "message": str(exc)})
        await events.close(scan_id)
        return
    finally:
        if clone_dir:
            shutil.rmtree(clone_dir, ignore_errors=True)

    # Persist to DB
    with SessionLocal() as db:
        save_pipeline_state(db, scan_id, state)

    # Auto-create a GitHub PR if we scanned a GitHub repo and have patches
    if github_repo and github_token and state.patches:
        actionable = [p for p in state.patches if p.status in (PatchStatus.VERIFIED, PatchStatus.PENDING)]
        if actionable:
            await events.publish(scan_id, {"type": "status_change", "status": "creating_pr"})
            pr_record = await asyncio.to_thread(
                _create_github_pr, scan_id, user_id, github_repo, github_token, branch, state
            )
            await events.publish(scan_id, {"type": "pr_created", "pull_request": pr_record})

    # findings/exploits/patches were already streamed in real-time via progress_callback
    await events.publish(scan_id, {"type": "status_change", "status": state.status.value})
    await events.publish(scan_id, {"type": "complete", "summary": state.summary()})
    await events.close(scan_id)


def _create_github_pr(
    scan_id: str,
    user_id: str | None,
    github_repo: str,
    github_token: str,
    base_branch: str,
    state: PipelineState,
) -> dict:
    """
    Synchronous helper: builds the PR via GitHub API and records it in the DB.
    Returns the serialised PR dict.
    """
    from loopsec.integrations.github import GitHubClient
    from loopsec.integrations.github_pr import GitHubPRBuilder

    owner, repo_name = github_repo.split("/", 1)
    client = GitHubClient(token=github_token)
    pr_builder = GitHubPRBuilder(client=client, owner=owner, repo=repo_name)
    pr_data: dict | None = None
    error_msg: str | None = None

    try:
        pr_data = pr_builder.create_fix_pr(state, base_branch=base_branch)
    except Exception as exc:
        logger.warning("PR creation failed for scan %s: %s", scan_id, exc)
        error_msg = str(exc)

    actionable_count = len([
        p for p in state.patches
        if p.status in (PatchStatus.VERIFIED, PatchStatus.PENDING)
    ])

    with SessionLocal() as db:
        pr_orm = create_pull_request(
            db,
            scan_id=scan_id,
            user_id=user_id,
            github_repo=github_repo,
            pr_number=pr_data.get("number") if pr_data else None,
            pr_url=pr_data.get("html_url") if pr_data else None,
            branch=pr_data.get("head", {}).get("ref", f"loopsec/fixes-{scan_id}") if pr_data else f"loopsec/fixes-{scan_id}",
            base_branch=base_branch,
            title=pr_data.get("title", f"LoopSec: Fix {actionable_count} security vulnerabilities") if pr_data else f"LoopSec: Fix {actionable_count} security vulnerabilities",
            patch_count=actionable_count,
            status="error" if error_msg else "open",
            error=error_msg,
        )
        return {
            "id": pr_orm.id,
            "scan_id": pr_orm.scan_id,
            "github_repo": pr_orm.github_repo,
            "pr_number": pr_orm.pr_number,
            "pr_url": pr_orm.pr_url,
            "branch": pr_orm.branch,
            "base_branch": pr_orm.base_branch,
            "title": pr_orm.title,
            "patch_count": pr_orm.patch_count,
            "status": pr_orm.status,
            "error": pr_orm.error,
        }


def _clone_github_repo(repo: str, branch: str, token: str) -> str:
    """
    Clone owner/repo@branch to a temporary directory.
    Uses the HTTPS clone URL with the token embedded for auth.
    Returns the path to the cloned directory.
    """
    import subprocess

    tmp = tempfile.mkdtemp(prefix="loopsec-clone-")
    clone_url = f"https://{token}@github.com/{repo}.git"

    result = subprocess.run(
        ["git", "clone", "--depth", "1", "--branch", branch, clone_url, tmp],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        shutil.rmtree(tmp, ignore_errors=True)
        raise RuntimeError(f"git clone failed: {result.stderr.strip()}")

    return tmp


def _run_sync(
    repo_path: str,
    app_url: str | None,
    branch: str,
    skip_agents: list[str],
    auto_deploy: bool,
    progress_callback=None,
) -> PipelineState:
    """Synchronous wrapper — runs in a thread pool via asyncio.to_thread()."""
    from loopsec.core.orchestrator import Orchestrator

    orch = Orchestrator(progress_callback=progress_callback)
    return orch.run(
        repo_path=repo_path,
        app_url=app_url,
        branch=branch,
        skip_agents=skip_agents,
        auto_deploy=auto_deploy,
    )
