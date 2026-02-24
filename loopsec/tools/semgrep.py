"""
Semgrep Tool Wrapper

Runs Semgrep SAST scans and converts results to LoopSec Finding objects.
"""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

from loopsec.core.config import get_config
from loopsec.core.models import Finding, FindingSource, Severity

logger = logging.getLogger(__name__)

# Map Semgrep severity → LoopSec severity
SEVERITY_MAP = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
    "INVENTORY": Severity.INFO,
}


def run_semgrep(target_path: str | Path, rules: str | None = None) -> list[Finding]:
    """
    Run Semgrep against a target directory and return findings.

    Args:
        target_path: Path to the source code directory
        rules: Semgrep rules config (e.g., "auto", "p/security-audit", path to rules)

    Returns:
        List of Finding objects
    """
    cfg = get_config()
    rules = rules or cfg.tools.semgrep_rules
    target_path = Path(target_path).resolve()

    if not target_path.exists():
        logger.error(f"Target path does not exist: {target_path}")
        return []

    cmd = [
        "semgrep",
        "scan",
        "--json",
        "--config", rules,
        "--no-git-ignore",         # Scan everything
        "--timeout", "60",         # Per-rule timeout
        "--max-target-bytes", "1000000",
        str(target_path),
    ]

    logger.info(f"Running: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except FileNotFoundError:
        logger.error("Semgrep not found. Install with: pip install semgrep")
        return []
    except subprocess.TimeoutExpired:
        logger.error("Semgrep timed out after 300s")
        return []

    if result.returncode not in (0, 1):  # 1 = findings found, which is fine
        logger.error(f"Semgrep failed (exit {result.returncode}): {result.stderr[:500]}")

    try:
        output = json.loads(result.stdout)
    except json.JSONDecodeError:
        logger.error(f"Failed to parse Semgrep JSON output: {result.stdout[:500]}")
        return []

    return _parse_results(output, target_path)


def _parse_results(output: dict, target_path: Path) -> list[Finding]:
    """Convert Semgrep JSON output to Finding objects."""
    findings: list[Finding] = []

    for result in output.get("results", []):
        extra = result.get("extra", {})
        severity_str = extra.get("severity", "WARNING")

        # Build relative file path
        abs_path = result.get("path", "")
        try:
            rel_path = str(Path(abs_path).relative_to(target_path))
        except ValueError:
            rel_path = abs_path

        # Extract code snippet
        lines = extra.get("lines", "").strip()

        # Extract CWE if present
        metadata = extra.get("metadata", {})
        cwe_list = metadata.get("cwe", [])
        cwe_id = cwe_list[0] if cwe_list else None
        if isinstance(cwe_id, str) and ":" in cwe_id:
            cwe_id = cwe_id.split(":")[0].strip()

        # OWASP category
        owasp = metadata.get("owasp", [])
        owasp_cat = owasp[0] if owasp else None

        finding = Finding(
            source=FindingSource.SAST,
            severity=SEVERITY_MAP.get(severity_str, Severity.MEDIUM),
            title=result.get("check_id", "unknown").split(".")[-1].replace("-", " ").title(),
            description=extra.get("message", "No description"),
            cwe_id=cwe_id,
            owasp_category=owasp_cat,
            file_path=rel_path,
            line_start=result.get("start", {}).get("line"),
            line_end=result.get("end", {}).get("line"),
            code_snippet=lines[:500] if lines else None,
            tool="semgrep",
            rule_id=result.get("check_id"),
            raw_output=result,
        )
        findings.append(finding)

    logger.info(f"Semgrep found {len(findings)} issues")
    return findings
