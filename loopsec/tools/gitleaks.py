"""
Gitleaks Tool Wrapper

Detects hardcoded secrets (API keys, passwords, tokens) in source code.
"""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

from loopsec.core.models import Finding, FindingSource, Severity

logger = logging.getLogger(__name__)


def run_gitleaks(target_path: str | Path) -> list[Finding]:
    """
    Run Gitleaks against a target directory.

    Args:
        target_path: Path to the source code directory

    Returns:
        List of Finding objects for detected secrets
    """
    target_path = Path(target_path).resolve()
    report_path = target_path / ".gitleaks-report.json"

    cmd = [
        "gitleaks",
        "detect",
        "--source", str(target_path),
        "--report-path", str(report_path),
        "--report-format", "json",
        "--no-git",
        "--exit-code", "0",       # Don't fail on findings
    ]

    logger.info(f"Running: {' '.join(cmd)}")

    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except FileNotFoundError:
        logger.warning("Gitleaks not found. Skipping secrets scan.")
        return []
    except subprocess.TimeoutExpired:
        logger.error("Gitleaks timed out")
        return []

    if not report_path.exists():
        logger.info("No Gitleaks report generated (no findings or error)")
        return []

    try:
        with open(report_path) as f:
            results = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.error(f"Failed to read Gitleaks report: {e}")
        return []
    finally:
        report_path.unlink(missing_ok=True)

    return _parse_results(results, target_path)


def _parse_results(results: list[dict], target_path: Path) -> list[Finding]:
    """Convert Gitleaks JSON to Finding objects."""
    findings: list[Finding] = []

    for leak in results:
        try:
            rel_path = str(Path(leak.get("File", "")).relative_to(target_path))
        except ValueError:
            rel_path = leak.get("File", "unknown")

        # Mask the actual secret in the snippet
        secret = leak.get("Secret", "")
        match = leak.get("Match", "")
        masked = match.replace(secret, secret[:4] + "****") if secret else match

        finding = Finding(
            source=FindingSource.SECRET,
            severity=Severity.HIGH,
            title=f"Hardcoded Secret: {leak.get('RuleID', 'unknown')}",
            description=(
                f"Potential hardcoded secret detected ({leak.get('RuleID', 'unknown')}). "
                f"Secret type: {leak.get('Description', 'Unknown')}. "
                f"This should be moved to environment variables or a secrets manager."
            ),
            cwe_id="CWE-798",
            file_path=rel_path,
            line_start=leak.get("StartLine"),
            line_end=leak.get("EndLine"),
            code_snippet=masked[:300],
            tool="gitleaks",
            rule_id=leak.get("RuleID"),
            raw_output=leak,
        )
        findings.append(finding)

    logger.info(f"Gitleaks found {len(findings)} secrets")
    return findings
