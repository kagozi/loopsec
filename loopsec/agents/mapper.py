"""
Mapper Agent

The 'secret sauce' — maps DAST (runtime) findings back to source code locations.
Uses multiple strategies:
1. Route → Handler mapping (framework-aware)
2. SAST ↔ DAST correlation (same CWE at related locations)
3. LLM reasoning over code + exploit context
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from rich.console import Console

from loopsec.agents.base import BaseAgent
from loopsec.core.models import (
    Finding,
    FindingSource,
    MappedVulnerability,
    PipelineState,
    PipelineStatus,
)

console = Console()

# Common framework route patterns
ROUTE_PATTERNS = {
    "python": [
        # Flask/FastAPI
        r'@(?:app|router|blueprint)\.\w+\(\s*["\']([^"\']+)',
        # Django urls.py
        r'path\(\s*["\']([^"\']+)',
    ],
    "javascript": [
        # Express
        r'(?:app|router)\.\w+\(\s*["\']([^"\']+)',
        # Next.js (file-based routing)
        r'pages/(.+?)\.\w+$',
    ],
}


class MapperAgent(BaseAgent):
    name = "mapper"
    description = "Maps runtime DAST findings to source code locations"

    def run(self, state: PipelineState) -> PipelineState:
        state.status = PipelineStatus.MAPPING

        dast_findings = state.get_dast_findings()
        sast_findings = state.get_sast_findings()

        if not dast_findings:
            console.print("  [yellow]No DAST findings to map[/yellow]")
            return state

        console.print(f"  [dim]Mapping {len(dast_findings)} DAST findings to source...[/dim]")

        # 1. Build route → file index from source code
        route_index = self._build_route_index(state.target.repo_path)
        console.print(f"  [dim]Route index: {len(route_index)} routes found[/dim]")

        # 2. Map each DAST finding
        for finding in dast_findings:
            mapped = self._map_finding(finding, sast_findings, route_index, state)
            if mapped:
                state.mapped_vulnerabilities.append(mapped)

        console.print(
            f"  [bold]Mapped {len(state.mapped_vulnerabilities)}/{len(dast_findings)} "
            f"DAST findings to source code[/bold]"
        )

        return state

    def _build_route_index(self, repo_path: str) -> dict[str, str]:
        """
        Scan source code for route definitions and build endpoint → file mapping.
        Returns: {"GET /api/users": "src/routes/users.py:15", ...}
        """
        index: dict[str, str] = {}
        repo = Path(repo_path)

        # Determine language patterns to use
        extensions = {".py": "python", ".js": "javascript", ".ts": "javascript"}

        for ext, lang in extensions.items():
            for filepath in repo.rglob(f"*{ext}"):
                # Skip common non-route files
                if any(skip in str(filepath) for skip in [
                    "node_modules", "__pycache__", ".git", "test", "venv", "migrations"
                ]):
                    continue

                try:
                    content = filepath.read_text(errors="ignore")
                except OSError:
                    continue

                for pattern in ROUTE_PATTERNS.get(lang, []):
                    for match in re.finditer(pattern, content):
                        route = match.group(1)
                        # Find the line number
                        line_num = content[: match.start()].count("\n") + 1
                        rel_path = str(filepath.relative_to(repo))
                        index[route] = f"{rel_path}:{line_num}"

        return index

    def _map_finding(
        self,
        finding: Finding,
        sast_findings: list[Finding],
        route_index: dict[str, str],
        state: PipelineState,
    ) -> MappedVulnerability | None:
        """Try multiple strategies to map a DAST finding to source code."""

        # Strategy 1: Direct route matching
        if finding.endpoint:
            mapped = self._match_by_route(finding, route_index)
            if mapped:
                return mapped

        # Strategy 2: SAST correlation (same CWE on related code)
        if finding.cwe_id:
            mapped = self._match_by_cwe(finding, sast_findings)
            if mapped:
                return mapped

        # Strategy 3: LLM reasoning
        mapped = self._match_by_llm(finding, state)
        return mapped

    def _match_by_route(
        self, finding: Finding, route_index: dict[str, str]
    ) -> MappedVulnerability | None:
        """Match DAST endpoint to a route handler in source code."""
        endpoint = finding.endpoint or ""
        # Normalize: strip query params, trailing slashes
        endpoint = endpoint.split("?")[0].rstrip("/")

        # Try exact match first
        for route, location in route_index.items():
            normalized_route = route.rstrip("/")
            if normalized_route == endpoint or endpoint.endswith(normalized_route):
                file_path, line = location.rsplit(":", 1)
                return MappedVulnerability(
                    finding_id=finding.id,
                    file_path=file_path,
                    line_start=int(line),
                    confidence=0.8,
                    reasoning=f"Route '{route}' matches DAST endpoint '{endpoint}'",
                )

        # Try partial/fuzzy match
        for route, location in route_index.items():
            # Match path segments
            route_parts = set(route.strip("/").split("/"))
            endpoint_parts = set(endpoint.strip("/").split("/"))
            if route_parts and route_parts.issubset(endpoint_parts):
                file_path, line = location.rsplit(":", 1)
                return MappedVulnerability(
                    finding_id=finding.id,
                    file_path=file_path,
                    line_start=int(line),
                    confidence=0.5,
                    reasoning=f"Partial route match: '{route}' ⊂ '{endpoint}'",
                )

        return None

    def _match_by_cwe(
        self, finding: Finding, sast_findings: list[Finding]
    ) -> MappedVulnerability | None:
        """Find SAST findings with the same CWE as this DAST finding."""
        if not finding.cwe_id:
            return None

        matches = [
            f for f in sast_findings
            if f.cwe_id == finding.cwe_id and f.file_path
        ]

        if matches:
            # Pick the highest severity match
            best = max(matches, key=lambda f: list(reversed(list(
                __import__("loopsec.core.models", fromlist=["Severity"]).Severity
            ))).index(f.severity) if f.severity else 0)
            return MappedVulnerability(
                finding_id=finding.id,
                file_path=best.file_path or "",
                line_start=best.line_start or 0,
                line_end=best.line_end,
                function_name=best.function_name,
                confidence=0.6,
                reasoning=(
                    f"CWE correlation: DAST {finding.cwe_id} matches "
                    f"SAST finding in {best.file_path}:{best.line_start}"
                ),
            )

        return None

    def _match_by_llm(
        self, finding: Finding, state: PipelineState
    ) -> MappedVulnerability | None:
        """Use LLM to reason about where this vulnerability lives in source code."""
        # Get list of source files for context
        repo = Path(state.target.repo_path)
        source_files = []
        for ext in (".py", ".js", ".ts", ".java", ".go", ".rb", ".php"):
            for f in repo.rglob(f"*{ext}"):
                if not any(skip in str(f) for skip in [
                    "node_modules", "__pycache__", ".git", "venv"
                ]):
                    rel = str(f.relative_to(repo))
                    source_files.append(rel)

        if not source_files:
            return None

        # Limit file list
        file_list = "\n".join(source_files[:50])

        prompt = f"""You are a security engineer mapping a runtime vulnerability to source code.

DAST Finding:
- Title: {finding.title}
- Endpoint: {finding.endpoint or 'N/A'}
- HTTP Method: {finding.http_method or 'N/A'}
- Parameter: {finding.parameter or 'N/A'}
- CWE: {finding.cwe_id or 'N/A'}
- Description: {finding.description[:300]}

Source files in the project:
{file_list}

Which source file most likely contains the vulnerable code? Respond in JSON:
{{
    "file_path": "path/to/file.py",
    "line_start": 0,
    "confidence": 0.5,
    "reasoning": "Brief explanation"
}}

If you cannot determine the file with any confidence, set confidence to 0."""

        try:
            result = self.llm.chat_json(prompt)
            confidence = float(result.get("confidence", 0))
            if confidence > 0.3 and result.get("file_path"):
                return MappedVulnerability(
                    finding_id=finding.id,
                    file_path=result["file_path"],
                    line_start=int(result.get("line_start", 0)),
                    confidence=confidence,
                    reasoning=result.get("reasoning", "LLM inference"),
                )
        except Exception as e:
            self.logger.warning(f"LLM mapping failed: {e}")

        return None
