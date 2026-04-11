"""
Background pipeline runner.

Wraps the synchronous Orchestrator.run() in asyncio.to_thread() so it
doesn't block the FastAPI event loop. Progress events are published to
the in-memory event bus after each logical phase.
"""

from __future__ import annotations

import asyncio
import logging

from loopsec.api import events
from loopsec.api.db.crud import save_pipeline_state, update_scan_status
from loopsec.api.db.engine import SessionLocal
from loopsec.core.models import PipelineState, PipelineStatus

logger = logging.getLogger(__name__)


async def run_pipeline_task(
    scan_id: str,
    repo_path: str,
    app_url: str | None,
    branch: str,
    skip_agents: list[str],
    auto_deploy: bool,
) -> None:
    """
    Async background task that runs the full pipeline.

    Emits SSE events at key milestones:
      - status_change  (queued → analyzing → complete / errored)
      - finding_added  (burst after pipeline finishes)
      - patch_added    (burst after pipeline finishes)
      - exploit_added  (burst after pipeline finishes)
      - complete       (terminal event with summary)
      - error          (if the pipeline raises)
    """
    await events.publish(scan_id, {"type": "status_change", "status": PipelineStatus.ANALYZING.value})

    with SessionLocal() as db:
        update_scan_status(db, scan_id, PipelineStatus.ANALYZING.value)

    try:
        state: PipelineState = await asyncio.to_thread(
            _run_sync,
            repo_path,
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

    # Persist to DB
    with SessionLocal() as db:
        save_pipeline_state(db, scan_id, state)

    # Emit individual item events as a burst so SSE clients see the full picture
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

    await events.publish(scan_id, {
        "type": "status_change",
        "status": state.status.value,
    })
    await events.publish(scan_id, {
        "type": "complete",
        "summary": state.summary(),
    })
    await events.close(scan_id)


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
