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
from loopsec.api.db.crud import save_pipeline_state, update_scan_status
from loopsec.api.db.engine import SessionLocal
from loopsec.core.models import PipelineState, PipelineStatus

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

        state: PipelineState = await asyncio.to_thread(
            _run_sync,
            actual_repo_path,
            app_url,
            branch,
            skip_agents,
            auto_deploy,
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

    # Emit item events as a burst
    for finding in state.findings:
        await events.publish(scan_id, {
            "type": "finding_added",
            "finding": {
                "id": finding.id,
                "severity": finding.severity.value,
                "source": finding.source.value,
                "title": finding.title,
                "file_path": finding.file_path,
                "line_start": finding.line_start,
                "endpoint": finding.endpoint,
                "tool": finding.tool,
            },
        })

    for exploit in state.exploits:
        await events.publish(scan_id, {
            "type": "exploit_added",
            "exploit": {
                "id": exploit.id,
                "finding_id": exploit.finding_id,
                "description": exploit.description,
                "verified": exploit.verified,
            },
        })

    for patch in state.patches:
        await events.publish(scan_id, {
            "type": "patch_added",
            "patch": {
                "id": patch.id,
                "finding_id": patch.finding_id,
                "file_path": patch.file_path,
                "status": patch.status.value,
            },
        })

    await events.publish(scan_id, {"type": "status_change", "status": state.status.value})
    await events.publish(scan_id, {"type": "complete", "summary": state.summary()})
    await events.close(scan_id)


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
) -> PipelineState:
    """Synchronous wrapper — runs in a thread pool via asyncio.to_thread()."""
    from loopsec.core.orchestrator import Orchestrator

    orch = Orchestrator()
    return orch.run(
        repo_path=repo_path,
        app_url=app_url,
        branch=branch,
        skip_agents=skip_agents,
        auto_deploy=auto_deploy,
    )
