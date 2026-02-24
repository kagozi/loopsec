"""
Analyzer Agent

Performs static analysis on source code:
- SAST scanning (Semgrep)
- Secrets detection (Gitleaks)
- Deduplication and severity prioritization via LLM
"""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from loopsec.agents.base import BaseAgent
from loopsec.core.models import PipelineState, PipelineStatus, Severity
from loopsec.tools.gitleaks import run_gitleaks
from loopsec.tools.semgrep import run_semgrep

console = Console()


class AnalyzerAgent(BaseAgent):
    name = "analyzer"
    description = "Static analysis: SAST scanning and secrets detection"

    def run(self, state: PipelineState) -> PipelineState:
        state.status = PipelineStatus.ANALYZING
        repo_path = state.target.repo_path

        console.print(f"  [dim]Scanning: {repo_path}[/dim]")

        # 1. Run Semgrep SAST
        console.print("  [dim]Running Semgrep...[/dim]")
        sast_findings = run_semgrep(repo_path)
        console.print(f"  [dim]Semgrep: {len(sast_findings)} findings[/dim]")

        # 2. Run Gitleaks secrets scan
        console.print("  [dim]Running Gitleaks...[/dim]")
        secret_findings = run_gitleaks(repo_path)
        console.print(f"  [dim]Gitleaks: {len(secret_findings)} secrets[/dim]")

        # 3. Merge all findings
        all_findings = sast_findings + secret_findings

        # 4. Deduplicate
        all_findings = self._deduplicate(all_findings)

        # 5. LLM-assisted prioritization for ambiguous severities
        if all_findings:
            all_findings = self._prioritize(all_findings, state)

        # 6. Add to state
        for f in all_findings:
            state.add_finding(f)

        # Print summary table
        self._print_summary(all_findings)

        return state

    def _deduplicate(self, findings):
        """Remove duplicate findings based on file + line + rule."""
        seen = set()
        unique = []
        for f in findings:
            key = (f.file_path, f.line_start, f.rule_id)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def _prioritize(self, findings, state: PipelineState):
        """Use LLM to refine severity of ambiguous findings."""
        # For now, do a batch assessment of medium-severity findings
        medium = [f for f in findings if f.severity == Severity.MEDIUM]

        if not medium or len(medium) > 30:
            return findings  # Skip LLM for large batches

        prompt = (
            "You are a senior application security engineer. "
            "Review these code security findings and assess if any should be "
            "upgraded to HIGH severity or downgraded to LOW based on exploitability.\n\n"
            "For each finding, respond with the finding title and your assessment "
            "(UPGRADE, KEEP, DOWNGRADE) with a brief reason.\n\n"
            "Findings:\n"
        )
        for i, f in enumerate(medium[:15]):
            prompt += (
                f"\n{i+1}. [{f.rule_id}] {f.title}\n"
                f"   File: {f.file_path}:{f.line_start}\n"
                f"   Code: {(f.code_snippet or 'N/A')[:150]}\n"
            )

        try:
            response = self.llm.chat(prompt)
            # Parse simple keywords from response
            for i, f in enumerate(medium[:15]):
                marker = f"{i+1}."
                idx = response.find(marker)
                if idx != -1:
                    section = response[idx : idx + 200].upper()
                    if "UPGRADE" in section:
                        f.severity = Severity.HIGH
                    elif "DOWNGRADE" in section:
                        f.severity = Severity.LOW
        except Exception as e:
            self.logger.warning(f"LLM prioritization failed (non-fatal): {e}")

        return findings

    def _print_summary(self, findings):
        """Display a nice summary table."""
        if not findings:
            console.print("  [yellow]No findings detected.[/yellow]")
            return

        table = Table(title="Analyzer Results", show_lines=False)
        table.add_column("Severity", style="bold", width=10)
        table.add_column("Count", justify="right", width=6)

        counts = {}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        colors = {
            Severity.CRITICAL: "red",
            Severity.HIGH: "bright_red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "cyan",
            Severity.INFO: "dim",
        }

        for sev in Severity:
            if sev in counts:
                table.add_row(
                    f"[{colors[sev]}]{sev.value.upper()}[/{colors[sev]}]",
                    str(counts[sev]),
                )

        console.print(table)
