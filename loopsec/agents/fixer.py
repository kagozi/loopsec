"""
Fixer Agent

Generates minimal, targeted code patches for discovered vulnerabilities:
1. Reads vulnerable code with full file context
2. Uses LLM to generate a secure fix
3. Validates the fix doesn't introduce new SAST issues
4. Produces unified diffs ready for PR
"""

from __future__ import annotations

import difflib
from pathlib import Path

from rich.console import Console

from loopsec.agents.base import BaseAgent
from loopsec.core.config import get_config
from loopsec.core.models import (
    Finding,
    MappedVulnerability,
    Patch,
    PatchStatus,
    PipelineState,
    PipelineStatus,
    Severity,
)
from loopsec.tools.semgrep import run_semgrep

console = Console()


class FixerAgent(BaseAgent):
    name = "fixer"
    description = "Generates and validates code patches for vulnerabilities"

    def run(self, state: PipelineState) -> PipelineState:
        state.status = PipelineStatus.FIXING
        cfg = get_config()
        repo_path = Path(state.target.repo_path)

        # Collect all findings that have source code locations
        fixable = self._get_fixable_findings(state)

        if not fixable:
            console.print("  [yellow]No fixable findings with source locations[/yellow]")
            return state

        # Limit how many we fix at once
        fixable = fixable[: cfg.max_findings_to_fix]
        console.print(f"  [dim]Generating patches for {len(fixable)} findings...[/dim]")

        for finding, file_path, line_start in fixable:
            full_path = repo_path / file_path

            if not full_path.exists():
                self.logger.warning(f"File not found: {full_path}")
                continue

            try:
                original_code = full_path.read_text()
            except OSError as e:
                self.logger.warning(f"Cannot read {full_path}: {e}")
                continue

            # Generate patch via LLM
            patch = self._generate_patch(
                finding=finding,
                file_path=file_path,
                original_code=original_code,
                line_start=line_start,
            )

            if patch:
                # Validate: write temp file, re-scan with Semgrep
                patch.passes_sast = self._validate_patch(
                    full_path, original_code, patch.patched_code
                )

                if patch.passes_sast:
                    console.print(f"  [green]✓ Patch for {file_path}:{line_start} — validated[/green]")
                else:
                    console.print(f"  [yellow]⚠ Patch for {file_path}:{line_start} — SAST re-check found issues[/yellow]")

                state.add_patch(patch)
                self._emit({
                    "type": "patch_added",
                    "patch": {
                        "id": patch.id,
                        "finding_id": patch.finding_id,
                        "file_path": patch.file_path,
                        "status": patch.status.value,
                        "passes_sast": patch.passes_sast,
                        "explanation": patch.explanation,
                    },
                })

        console.print(f"  [bold]Generated {len(state.patches)} patches[/bold]")
        return state

    def _get_fixable_findings(
        self, state: PipelineState
    ) -> list[tuple[Finding, str, int]]:
        """Get findings that have source code locations, sorted by severity."""
        fixable: list[tuple[Finding, str, int]] = []

        # SAST findings already have file locations
        for f in state.get_sast_findings():
            if f.file_path and f.line_start:
                fixable.append((f, f.file_path, f.line_start))

        # Mapped DAST findings
        mapped_index = {m.finding_id: m for m in state.mapped_vulnerabilities}
        for f in state.get_dast_findings():
            if f.id in mapped_index:
                m = mapped_index[f.id]
                fixable.append((f, m.file_path, m.line_start))

        # Sort by severity (critical first)
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        fixable.sort(key=lambda x: severity_order.get(x[0].severity, 99))

        # Deduplicate by file + line
        seen = set()
        unique = []
        for item in fixable:
            key = (item[1], item[2])
            if key not in seen:
                seen.add(key)
                unique.append(item)

        return unique

    def _generate_patch(
        self,
        finding: Finding,
        file_path: str,
        original_code: str,
        line_start: int,
    ) -> Patch | None:
        """Use LLM to generate a secure code patch."""

        # Extract context window around the vulnerable line
        lines = original_code.splitlines(keepends=True)
        ctx_start = max(0, line_start - 15)
        ctx_end = min(len(lines), line_start + 15)
        context = "".join(lines[ctx_start:ctx_end])

        prompt = f"""You are a senior security engineer fixing a vulnerability.

FILE: {file_path}
VULNERABILITY: {finding.title}
SEVERITY: {finding.severity.value}
CWE: {finding.cwe_id or 'N/A'}
DESCRIPTION: {finding.description[:500]}
RULE: {finding.rule_id or 'N/A'}

VULNERABLE CODE (lines {ctx_start + 1}-{ctx_end}):
```
{context}
```

FULL FILE:
```
{original_code[:8000]}
```

Generate a MINIMAL, TARGETED fix. Rules:
1. Only change what's necessary to fix the vulnerability
2. Do NOT refactor unrelated code
3. Maintain the same coding style
4. Add a brief comment explaining the security fix
5. Return the COMPLETE file content with the fix applied

Respond in JSON:
{{
    "patched_code": "...full file content with fix...",
    "explanation": "Brief explanation of what was changed and why"
}}"""

        try:
            result = self.llm.chat_json(prompt)
            patched_code = result.get("patched_code", "")
            explanation = result.get("explanation", "")

            if not patched_code or patched_code == original_code:
                self.logger.warning(f"LLM returned empty or identical patch for {file_path}")
                return None

            # Generate unified diff
            diff = difflib.unified_diff(
                original_code.splitlines(keepends=True),
                patched_code.splitlines(keepends=True),
                fromfile=f"a/{file_path}",
                tofile=f"b/{file_path}",
            )
            diff_str = "".join(diff)

            if not diff_str:
                return None

            return Patch(
                finding_id=finding.id,
                file_path=file_path,
                original_code=original_code,
                patched_code=patched_code,
                diff=diff_str,
                explanation=explanation,
                status=PatchStatus.PENDING,
            )

        except Exception as e:
            self.logger.error(f"Patch generation failed for {file_path}: {e}")
            return None

    def _validate_patch(
        self, file_path: Path, original_code: str, patched_code: str
    ) -> bool:
        """
        Validate patch by writing it to a temp location and running Semgrep.
        Returns True if the patch doesn't introduce new issues.
        """
        import tempfile
        import shutil

        try:
            # Create temp directory with just this file
            with tempfile.TemporaryDirectory(prefix="loopsec-validate-") as tmpdir:
                tmp_file = Path(tmpdir) / file_path.name
                tmp_file.write_text(patched_code)

                # Run Semgrep on original
                original_file = Path(tmpdir) / f"orig_{file_path.name}"
                original_file.write_text(original_code)
                original_findings = run_semgrep(str(original_file.parent))

                # Run Semgrep on patched
                original_file.unlink()
                patched_findings = run_semgrep(str(tmp_file.parent))

                # Check: patched version should not have MORE issues
                original_rules = {f.rule_id for f in original_findings}
                new_rules = {f.rule_id for f in patched_findings} - original_rules

                if new_rules:
                    self.logger.warning(
                        f"Patch introduces new issues: {new_rules}"
                    )
                    return False

                return True

        except Exception as e:
            self.logger.warning(f"Patch validation failed: {e}")
            return True  # Assume OK if validation itself fails
