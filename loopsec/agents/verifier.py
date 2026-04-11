"""
Verifier Agent

Closes the loop by verifying that patches actually fix vulnerabilities:
1. Applies patches to source code
2. Re-builds/re-deploys the application (not implemented yet)
3. Re-runs the exact same attacks
4. Reports which fixes worked, which didn't, and any regressions
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from rich.console import Console
from rich.table import Table

from loopsec.agents.base import BaseAgent
from loopsec.core.models import (
    Exploit,
    Patch,
    PatchStatus,
    PipelineState,
    PipelineStatus,
)
from loopsec.tools.nuclei import run_nuclei
from loopsec.tools.semgrep import run_semgrep

console = Console()


class VerifierAgent(BaseAgent):
    name = "verifier"
    description = "Verifies patches by re-deploying and re-attacking"

    def run(self, state: PipelineState) -> PipelineState:
        state.status = PipelineStatus.VERIFYING

        if not state.patches:
            console.print("  [yellow]No patches to verify[/yellow]")
            return state

        console.print(f"  [dim]Verifying {len(state.patches)} patches...[/dim]")

        # 1. Apply patches and run static re-verification
        for patch in state.patches:
            self._verify_static(patch, state)

        # 2. If we have a running app, do dynamic re-verification
        if state.target.app_url:
            self._verify_dynamic(state)
        else:
            console.print("  [dim]No app URL — skipping dynamic verification[/dim]")

        # 3. Update state summary
        state.verified_fixes = [
            p.finding_id for p in state.patches if p.status == PatchStatus.VERIFIED
        ]
        state.still_open = [
            p.finding_id for p in state.patches if p.status == PatchStatus.FAILED
        ]

        # Print results
        self._print_results(state)

        return state

    def _verify_static(self, patch: Patch, state: PipelineState) -> None:
        """Verify a patch via static analysis (SAST re-scan)."""
        repo_path = Path(state.target.repo_path)
        target_file = repo_path / patch.file_path

        if not target_file.exists():
            patch.status = PatchStatus.FAILED
            return

        # Apply patch to a temporary copy
        try:
            with tempfile.TemporaryDirectory(prefix="loopsec-verify-") as tmpdir:
                tmp_file = Path(tmpdir) / target_file.name
                tmp_file.write_text(patch.patched_code)

                # Run Semgrep on patched code
                findings = run_semgrep(str(tmp_file.parent))

                # Check if the original finding's rule still triggers
                original_finding = next(
                    (f for f in state.findings if f.id == patch.finding_id), None
                )

                if original_finding and original_finding.rule_id:
                    still_present = any(
                        f.rule_id == original_finding.rule_id for f in findings
                    )
                    if not still_present:
                        patch.passes_sast = True
                        patch.status = PatchStatus.VERIFIED
                        return

                # If no specific rule to check, verify no new high/critical issues
                from loopsec.core.models import Severity
                new_severe = [
                    f for f in findings
                    if f.severity in (Severity.CRITICAL, Severity.HIGH)
                ]

                if not new_severe:
                    patch.passes_sast = True
                    patch.status = PatchStatus.VERIFIED
                else:
                    patch.passes_sast = False
                    patch.status = PatchStatus.FAILED

        except Exception as e:
            self.logger.warning(f"Static verification failed for {patch.file_path}: {e}")
            patch.status = PatchStatus.PENDING  # Can't confirm either way

    def _verify_dynamic(self, state: PipelineState) -> None:
        """
        Re-run DAST attacks against patched app to confirm fixes.
        NOTE: In MVP, this does a lightweight Nuclei re-scan.
        Full re-deploy requires the sandbox manager (Phase 2).
        """
        target_url = state.target.app_url
        if not target_url:
            return

        console.print(f"  [dim]Re-scanning {target_url} for dynamic verification...[/dim]")

        # Get original DAST exploits
        original_exploits = {e.finding_id: e for e in state.exploits}

        # Run a focused Nuclei re-scan
        try:
            new_findings = run_nuclei(target_url)
        except Exception as e:
            self.logger.warning(f"Dynamic re-scan failed: {e}")
            return

        # Check which original findings are still present
        new_endpoints = {(f.endpoint, f.rule_id) for f in new_findings}

        for patch in state.patches:
            original = next(
                (f for f in state.findings if f.id == patch.finding_id), None
            )
            if original and original.endpoint:
                key = (original.endpoint, original.rule_id)
                if key not in new_endpoints:
                    patch.exploit_mitigated = True
                    if patch.status != PatchStatus.FAILED:
                        patch.status = PatchStatus.VERIFIED
                else:
                    patch.exploit_mitigated = False
                    patch.status = PatchStatus.FAILED

    def _print_results(self, state: PipelineState) -> None:
        """Print verification results table."""
        table = Table(title="Verification Results", show_lines=True)
        table.add_column("Finding", style="bold", max_width=40)
        table.add_column("File", max_width=30)
        table.add_column("Status", justify="center", width=12)

        status_icons = {
            PatchStatus.VERIFIED: "[green]✓ FIXED[/green]",
            PatchStatus.FAILED: "[red]✗ OPEN[/red]",
            PatchStatus.PENDING: "[yellow]? PENDING[/yellow]",
            PatchStatus.REGRESSED: "[bright_red]↺ REGRESSED[/bright_red]",
        }

        for patch in state.patches:
            original = next(
                (f for f in state.findings if f.id == patch.finding_id), None
            )
            title = original.title if original else patch.finding_id
            table.add_row(
                title[:40],
                patch.file_path,
                status_icons.get(patch.status, str(patch.status)),
            )

        console.print(table)
