"""
GitHub PR Builder

Takes LoopSec pipeline results and:
1. Creates a fix branch with all patches applied
2. Opens a PR with a security summary
3. Posts a detailed comment with findings
4. Sets commit status checks
"""

from __future__ import annotations

import base64
import logging
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from loopsec.core.models import (
    Finding,
    Patch,
    PatchStatus,
    PipelineState,
    Severity,
)
from loopsec.integrations.github import GitHubClient

logger = logging.getLogger(__name__)

SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


class GitHubPRBuilder:
    """Creates GitHub PRs from LoopSec scan results."""

    def __init__(self, client: GitHubClient, owner: str, repo: str):
        self.gh = client
        self.owner = owner
        self.repo = repo

    def create_fix_pr(
        self,
        state: PipelineState,
        base_branch: str = "main",
        source_dir: str | None = None,
    ) -> dict | None:
        """
        Create a PR with security fixes applied.

        Args:
            state: Completed pipeline state with patches
            base_branch: Branch to open PR against
            source_dir: Local clone directory (used to push patches)

        Returns:
            PR data dict, or None if no patches to apply
        """
        verified_patches = [
            p for p in state.patches if p.status == PatchStatus.VERIFIED
        ]
        pending_patches = [
            p for p in state.patches if p.status == PatchStatus.PENDING
        ]
        all_patches = verified_patches + pending_patches

        if not all_patches:
            logger.info("No patches to create PR for")
            return None

        # Create branch name
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        branch_name = f"loopsec/security-fixes-{timestamp}"

        # Get the base branch SHA
        ref_data = self.gh.get_ref(self.owner, self.repo, base_branch)
        base_sha = ref_data["object"]["sha"]

        # Create the fix branch
        self.gh.create_branch(self.owner, self.repo, branch_name, base_sha)

        # Apply patches via the GitHub API (commit each file change)
        applied_count = 0
        for patch in all_patches:
            try:
                self._apply_patch_via_api(patch, branch_name)
                applied_count += 1
            except Exception as e:
                logger.error(f"Failed to apply patch for {patch.file_path}: {e}")

        if applied_count == 0:
            logger.warning("No patches could be applied")
            return None

        # Build PR body
        pr_body = self._build_pr_body(state, all_patches)

        # Create the PR
        pr = self.gh.create_pull_request(
            owner=self.owner,
            repo=self.repo,
            title=f"🔒 LoopSec: Fix {applied_count} security vulnerabilities",
            body=pr_body,
            head=branch_name,
            base=base_branch,
        )

        pr_number = pr["number"]
        logger.info(f"Created PR #{pr_number}: {pr['html_url']}")

        # Add a detailed findings comment
        comment_body = self._build_findings_comment(state)
        self.gh.add_pr_comment(self.owner, self.repo, pr_number, comment_body)

        return pr

    def _apply_patch_via_api(self, patch: Patch, branch: str) -> None:
        """Apply a single patch by updating the file via GitHub API."""
        # Get current file content and SHA
        file_data = self.gh.get_file_content(
            self.owner, self.repo, patch.file_path, ref=branch
        )
        file_sha = file_data["sha"]

        # Encode patched content
        content_b64 = base64.b64encode(patch.patched_code.encode()).decode()

        status_label = "✓ verified" if patch.status == PatchStatus.VERIFIED else "pending review"

        self.gh.update_file(
            owner=self.owner,
            repo=self.repo,
            path=patch.file_path,
            content_b64=content_b64,
            message=f"fix: {patch.explanation[:72]} ({status_label})\n\nLoopSec auto-fix for finding: {patch.finding_id}",
            branch=branch,
            file_sha=file_sha,
        )
        logger.info(f"Applied patch to {patch.file_path} on branch {branch}")

    def post_scan_comment(
        self, state: PipelineState, pr_number: int
    ) -> dict:
        """Post a security scan summary on an existing PR."""
        body = self._build_findings_comment(state)
        return self.gh.add_pr_comment(self.owner, self.repo, pr_number, body)

    def set_status(
        self,
        sha: str,
        state: PipelineState,
        target_url: str | None = None,
    ) -> dict:
        """Set a commit status based on scan results."""
        summary = state.summary()
        critical_high = (
            summary["by_severity"].get("critical", 0)
            + summary["by_severity"].get("high", 0)
        )
        unfixed_critical = len([
            f for f in state.get_unfixed_findings()
            if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ])

        if unfixed_critical > 0:
            status_state = "failure"
            description = f"Found {unfixed_critical} unfixed critical/high vulnerabilities"
        elif summary["total_findings"] > 0:
            status_state = "success"
            description = (
                f"Found {summary['total_findings']} issues, "
                f"{summary['verified_fixes']} auto-fixed"
            )
        else:
            status_state = "success"
            description = "No security issues found"

        return self.gh.set_commit_status(
            owner=self.owner,
            repo=self.repo,
            sha=sha,
            state=status_state,
            description=description,
            target_url=target_url,
        )

    # ─── Markdown Builders ────────────────────────────────

    def _build_pr_body(self, state: PipelineState, patches: list[Patch]) -> str:
        """Build the PR description markdown."""
        summary = state.summary()
        verified = len([p for p in patches if p.status == PatchStatus.VERIFIED])
        pending = len(patches) - verified

        body = f"""## 🔒 LoopSec Security Fixes

This PR was automatically generated by [LoopSec](https://github.com/yourorg/loopsec) to fix security vulnerabilities found during automated scanning.

### Summary

| Metric | Count |
|--------|-------|
| Total findings | {summary['total_findings']} |
| Critical | {summary['by_severity'].get('critical', 0)} |
| High | {summary['by_severity'].get('high', 0)} |
| Medium | {summary['by_severity'].get('medium', 0)} |
| Patches in this PR | {len(patches)} |
| ✅ Verified fixes | {verified} |
| ⏳ Pending review | {pending} |

### Changes

"""
        for patch in patches:
            finding = next(
                (f for f in state.findings if f.id == patch.finding_id), None
            )
            title = finding.title if finding else patch.finding_id
            severity = finding.severity.value if finding else "unknown"
            emoji = SEVERITY_EMOJI.get(finding.severity, "⚪") if finding else "⚪"
            status = "✅ Verified" if patch.status == PatchStatus.VERIFIED else "⏳ Needs review"

            body += f"""#### {emoji} {title} (`{patch.file_path}`)
- **Severity:** {severity}
- **Status:** {status}
- **Fix:** {patch.explanation}

"""

        body += """### ⚠️ Review Checklist

- [ ] Verify patches don't break existing functionality
- [ ] Run your test suite against these changes
- [ ] Review any "pending review" patches carefully
- [ ] Merge when satisfied

---
*Generated by LoopSec — Closed-Loop AI Security Agent*
"""
        return body

    def _build_findings_comment(self, state: PipelineState) -> str:
        """Build the detailed findings comment."""
        summary = state.summary()

        comment = f"""## 🔍 LoopSec Security Scan Results

**Scan ID:** `{state.id}`
**Scanned:** {state.started_at.strftime('%Y-%m-%d %H:%M UTC')}

### Overview

| | Count |
|---|---|
| 🔴 Critical | {summary['by_severity'].get('critical', 0)} |
| 🟠 High | {summary['by_severity'].get('high', 0)} |
| 🟡 Medium | {summary['by_severity'].get('medium', 0)} |
| 🔵 Low | {summary['by_severity'].get('low', 0)} |
| **Total** | **{summary['total_findings']}** |
| ✅ Auto-fixed | {summary['verified_fixes']} |
| ❌ Still open | {summary['still_open']} |

### Findings

"""
        # Group by severity
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            findings = state.get_findings_by_severity(severity)
            if not findings:
                continue

            emoji = SEVERITY_EMOJI[severity]
            comment += f"#### {emoji} {severity.value.upper()} ({len(findings)})\n\n"

            for f in findings[:10]:  # Cap at 10 per severity
                # Check if this finding has a patch
                patch = next(
                    (p for p in state.patches if p.finding_id == f.id), None
                )
                fix_status = ""
                if patch:
                    if patch.status == PatchStatus.VERIFIED:
                        fix_status = " ✅ *auto-fixed*"
                    else:
                        fix_status = " 🔧 *patch pending*"

                location = ""
                if f.file_path:
                    location = f" — `{f.file_path}"
                    if f.line_start:
                        location += f":{f.line_start}"
                    location += "`"

                comment += f"- **{f.title}**{location}{fix_status}\n"
                if f.cwe_id:
                    comment += f"  {f.cwe_id}"
                    if f.endpoint:
                        comment += f" | Endpoint: `{f.endpoint}`"
                    comment += "\n"

            if len(findings) > 10:
                comment += f"\n  *...and {len(findings) - 10} more*\n"

            comment += "\n"

        if state.errors:
            comment += "### ⚠️ Scan Errors\n\n"
            for err in state.errors:
                comment += f"- {err}\n"
            comment += "\n"

        comment += "---\n*Generated by LoopSec — Closed-Loop AI Security Agent*\n"
        return comment
