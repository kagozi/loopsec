"""
LoopSec Orchestrator

The central pipeline that coordinates all agents in sequence:
Analyze → Attack → Map → Fix → Verify

Uses a simple state machine pattern. Each agent receives the full
PipelineState and returns it with its additions.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from loopsec.agents.analyzer import AnalyzerAgent
from loopsec.agents.attacker import AttackerAgent
from loopsec.agents.fixer import FixerAgent
from loopsec.agents.mapper import MapperAgent
from loopsec.agents.verifier import VerifierAgent
from loopsec.core.config import get_config
from loopsec.core.llm import LLMClient
from loopsec.core.models import PipelineState, PipelineStatus, ScanTarget

logger = logging.getLogger(__name__)
console = Console()


class Orchestrator:
    """
    Runs the full closed-loop security pipeline.

    Usage:
        orch = Orchestrator()
        state = orch.run(repo_path="/path/to/code", app_url="http://localhost:8080")
    """

    def __init__(self, llm: LLMClient | None = None):
        self.llm = llm or LLMClient()
        self.agents = [
            AnalyzerAgent(llm=self.llm),
            AttackerAgent(llm=self.llm),
            MapperAgent(llm=self.llm),
            FixerAgent(llm=self.llm),
            VerifierAgent(llm=self.llm),
        ]

    def run(
        self,
        repo_path: str,
        app_url: str | None = None,
        branch: str = "main",
        skip_agents: list[str] | None = None,
    ) -> PipelineState:
        """
        Execute the full pipeline.

        Args:
            repo_path: Path to the source code repository
            app_url: URL of the deployed application (optional for SAST-only)
            branch: Git branch to scan
            skip_agents: List of agent names to skip (e.g., ["attacker", "verifier"])

        Returns:
            PipelineState with all findings, exploits, patches, and verification results
        """
        skip = set(skip_agents or [])

        # Initialize state
        state = PipelineState(
            target=ScanTarget(
                repo_path=str(Path(repo_path).resolve()),
                app_url=app_url,
                branch=branch,
            )
        )

        # Banner
        self._print_banner(state)

        # Run each agent in sequence
        for agent in self.agents:
            if agent.name in skip:
                console.print(f"\n[dim]⏭ Skipping {agent.name} agent[/dim]")
                continue

            # Skip DAST agents if no app URL
            if agent.name in ("attacker", "verifier") and not app_url:
                console.print(
                    f"\n[dim]⏭ Skipping {agent.name} (no app URL)[/dim]"
                )
                continue

            state = agent.execute(state)

            # Bail on critical errors
            if state.status == PipelineStatus.ERRORED:
                console.print(
                    f"\n[bold red]Pipeline stopped due to errors in {agent.name}[/bold red]"
                )
                break

        # Finalize
        state.status = PipelineStatus.COMPLETE
        state.completed_at = datetime.now(timezone.utc)

        # Print final summary
        self._print_summary(state)

        return state

    def _print_banner(self, state: PipelineState) -> None:
        banner = Text()
        banner.append("LOOPSEC", style="bold cyan")
        banner.append(" — Closed-Loop Security Agent\n", style="dim")
        banner.append(f"Target: {state.target.repo_path}\n")
        if state.target.app_url:
            banner.append(f"App URL: {state.target.app_url}\n")
        banner.append(f"Pipeline ID: {state.id}")

        console.print(Panel(banner, border_style="cyan"))

    def _print_summary(self, state: PipelineState) -> None:
        summary = state.summary()
        elapsed = ""
        if state.completed_at and state.started_at:
            delta = state.completed_at - state.started_at
            elapsed = f" in {delta.total_seconds():.1f}s"

        console.print(f"\n{'═' * 60}")
        console.print(f"[bold cyan]PIPELINE COMPLETE{elapsed}[/bold cyan]\n")

        console.print(f"  Findings:     {summary['total_findings']}")
        for sev, count in summary["by_severity"].items():
            if count > 0:
                console.print(f"    {sev:>10}: {count}")

        console.print(f"  Exploits:     {summary['exploits_generated']}")
        console.print(f"  Patches:      {summary['patches_generated']}")
        console.print(f"  [green]Verified:   {summary['verified_fixes']}[/green]")
        console.print(f"  [red]Still open: {summary['still_open']}[/red]")

        if state.errors:
            console.print(f"\n  [yellow]Errors: {len(state.errors)}[/yellow]")
            for err in state.errors:
                console.print(f"    [dim]- {err}[/dim]")

        console.print(f"{'═' * 60}\n")


def generate_report(state: PipelineState, output_path: str | None = None) -> str:
    """Generate a markdown report from the pipeline state."""
    summary = state.summary()

    report = f"""# LoopSec Security Report

**Pipeline ID:** {state.id}
**Target:** {state.target.repo_path}
**App URL:** {state.target.app_url or 'N/A'}
**Date:** {state.started_at.strftime('%Y-%m-%d %H:%M UTC')}

---

## Summary

| Metric | Count |
|--------|-------|
| Total Findings | {summary['total_findings']} |
| Critical | {summary['by_severity'].get('critical', 0)} |
| High | {summary['by_severity'].get('high', 0)} |
| Medium | {summary['by_severity'].get('medium', 0)} |
| Low | {summary['by_severity'].get('low', 0)} |
| Exploits Generated | {summary['exploits_generated']} |
| Patches Generated | {summary['patches_generated']} |
| Verified Fixes | {summary['verified_fixes']} |
| Still Open | {summary['still_open']} |

---

## Findings

"""

    for i, finding in enumerate(state.findings, 1):
        report += f"""### {i}. [{finding.severity.value.upper()}] {finding.title}

- **Source:** {finding.source.value}
- **Tool:** {finding.tool}
- **CWE:** {finding.cwe_id or 'N/A'}
- **Location:** {finding.file_path or 'N/A'}:{finding.line_start or ''}
- **Endpoint:** {finding.endpoint or 'N/A'}

{finding.description}

"""
        if finding.code_snippet:
            report += f"```\n{finding.code_snippet}\n```\n\n"

    if state.patches:
        report += "---\n\n## Patches\n\n"
        for patch in state.patches:
            status_icon = "✓" if patch.status.value == "verified" else "✗"
            report += f"""### {status_icon} Patch for: {patch.file_path}

**Status:** {patch.status.value}
**Explanation:** {patch.explanation}

```diff
{patch.diff}
```

"""

    if state.errors:
        report += "---\n\n## Errors\n\n"
        for err in state.errors:
            report += f"- {err}\n"

    if output_path:
        Path(output_path).write_text(report)
        logger.info(f"Report written to {output_path}")

    return report
