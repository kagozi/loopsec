"""Tests for core models and pipeline state."""

import pytest

from loopsec.core.models import (
    Exploit,
    Finding,
    FindingSource,
    MappedVulnerability,
    Patch,
    PatchStatus,
    PipelineState,
    ScanTarget,
    Severity,
)


class TestFinding:
    def test_create_sast_finding(self):
        f = Finding(
            source=FindingSource.SAST,
            severity=Severity.HIGH,
            title="SQL Injection",
            description="User input concatenated into SQL query",
            cwe_id="CWE-89",
            file_path="app/db.py",
            line_start=42,
            tool="semgrep",
            rule_id="python.lang.security.audit.formatted-sql-query",
        )
        assert f.id  # Auto-generated
        assert f.source == FindingSource.SAST
        assert f.severity == Severity.HIGH
        assert f.file_path == "app/db.py"

    def test_create_dast_finding(self):
        f = Finding(
            source=FindingSource.DAST,
            severity=Severity.CRITICAL,
            title="Reflected XSS",
            description="XSS via search parameter",
            cwe_id="CWE-79",
            endpoint="/api/search",
            http_method="GET",
            parameter="q",
            tool="zap",
        )
        assert f.endpoint == "/api/search"
        assert f.parameter == "q"


class TestPipelineState:
    def test_empty_state(self):
        state = PipelineState(
            target=ScanTarget(repo_path="/tmp/test-repo")
        )
        assert state.target.repo_path == "/tmp/test-repo"
        assert len(state.findings) == 0
        assert state.summary()["total_findings"] == 0

    def test_add_findings(self):
        state = PipelineState(
            target=ScanTarget(repo_path="/tmp/test-repo")
        )

        state.add_finding(Finding(
            source=FindingSource.SAST,
            severity=Severity.HIGH,
            title="SQLi",
            description="test",
        ))
        state.add_finding(Finding(
            source=FindingSource.DAST,
            severity=Severity.MEDIUM,
            title="XSS",
            description="test",
        ))

        assert len(state.findings) == 2
        assert len(state.get_sast_findings()) == 1
        assert len(state.get_dast_findings()) == 1
        assert state.summary()["by_severity"]["high"] == 1

    def test_get_unfixed_findings(self):
        state = PipelineState(
            target=ScanTarget(repo_path="/tmp/test-repo")
        )

        f1 = Finding(source=FindingSource.SAST, severity=Severity.HIGH,
                      title="Bug1", description="test")
        f2 = Finding(source=FindingSource.SAST, severity=Severity.MEDIUM,
                      title="Bug2", description="test")

        state.add_finding(f1)
        state.add_finding(f2)

        # Patch f1 and mark as verified
        state.add_patch(Patch(
            finding_id=f1.id,
            file_path="test.py",
            original_code="bad",
            patched_code="good",
            diff="--- a\n+++ b",
            explanation="Fixed",
            status=PatchStatus.VERIFIED,
        ))

        unfixed = state.get_unfixed_findings()
        assert len(unfixed) == 1
        assert unfixed[0].id == f2.id

    def test_severity_filter(self):
        state = PipelineState(
            target=ScanTarget(repo_path="/tmp/test-repo")
        )

        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.HIGH, Severity.LOW]:
            state.add_finding(Finding(
                source=FindingSource.SAST,
                severity=sev,
                title=f"Finding-{sev.value}",
                description="test",
            ))

        assert len(state.get_findings_by_severity(Severity.HIGH)) == 2
        assert len(state.get_findings_by_severity(Severity.CRITICAL)) == 1


class TestExploit:
    def test_create_exploit(self):
        e = Exploit(
            finding_id="abc123",
            description="SQLi PoC",
            request="GET /api/users?id=1' OR 1=1--",
            steps=["Send request", "Observe data leak"],
        )
        assert e.finding_id == "abc123"
        assert not e.verified


class TestPatch:
    def test_create_patch(self):
        p = Patch(
            finding_id="abc123",
            file_path="app/db.py",
            original_code="query = f'SELECT * FROM users WHERE id={user_id}'",
            patched_code="query = 'SELECT * FROM users WHERE id=%s'",
            diff="--- a/app/db.py\n+++ b/app/db.py",
            explanation="Use parameterized query",
        )
        assert p.status == PatchStatus.PENDING
        assert p.passes_sast is None
