"""
Nuclei Tool Wrapper

Runs ProjectDiscovery Nuclei for template-based vulnerability scanning
against deployed applications.
"""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

from loopsec.core.models import Finding, FindingSource, Severity

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def run_nuclei(
    target_url: str,
    templates: str | None = None,
    extra_args: list[str] | None = None,
) -> list[Finding]:
    """
    Run Nuclei against a target URL.

    Args:
        target_url: The URL to scan
        templates: Path to templates or template tag (e.g., "cves", "owasp-top-10")
        extra_args: Additional CLI arguments

    Returns:
        List of Finding objects
    """
    cmd = [
        "nuclei",
        "-u", target_url,
        "-jsonl",
        "-silent",
        "-severity", "info,low,medium,high,critical",
        "-timeout", "10",
        "-retries", "1",
        "-bulk-size", "25",
        "-concurrency", "10",
    ]

    if templates:
        cmd.extend(["-t", templates])
    else:
        # Default: use built-in security-focused templates
        cmd.extend(["-tags", "owasp,cve,security,misconfig"])

    if extra_args:
        cmd.extend(extra_args)

    logger.info(f"Running Nuclei against {target_url}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
        )
    except FileNotFoundError:
        logger.warning("Nuclei not found. Skipping template-based scan.")
        return []
    except subprocess.TimeoutExpired:
        logger.error("Nuclei timed out after 600s")
        return []

    return _parse_jsonl(result.stdout)


def _parse_jsonl(output: str) -> list[Finding]:
    """Parse Nuclei JSONL output into Findings."""
    findings: list[Finding] = []

    for line in output.strip().splitlines():
        if not line.strip():
            continue
        try:
            result = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = result.get("info", {})
        severity_str = info.get("severity", "info").lower()

        # Extract matched endpoint
        matched_at = result.get("matched-at", "")
        host = result.get("host", "")
        endpoint = matched_at.replace(host, "") if host else matched_at

        # Classification
        classification = info.get("classification", {})
        cwe_ids = classification.get("cwe-id", [])
        cwe_id = f"CWE-{cwe_ids[0]}" if cwe_ids else None

        # Extract request/response for PoC
        request = result.get("request", "")
        response = result.get("response", "")

        finding = Finding(
            source=FindingSource.DAST,
            severity=SEVERITY_MAP.get(severity_str, Severity.INFO),
            title=info.get("name", "Unknown Nuclei Finding"),
            description=info.get("description", "")
            or f"Nuclei template {result.get('template-id', 'unknown')} matched.",
            cwe_id=cwe_id,
            endpoint=endpoint or matched_at,
            http_method=result.get("type", "http").upper(),
            tool="nuclei",
            rule_id=result.get("template-id"),
            raw_output={
                "request": request[:2000],
                "response": response[:2000],
                "matched_at": matched_at,
                "matcher_name": result.get("matcher-name", ""),
                "extracted_results": result.get("extracted-results", []),
            },
        )
        findings.append(finding)

    logger.info(f"Nuclei found {len(findings)} issues")
    return findings
