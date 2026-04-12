"""
SQLAlchemy ORM models. Each table maps directly to the corresponding
Pydantic model in loopsec.core.models.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from loopsec.api.db.engine import Base


class UserORM(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(12), primary_key=True)
    github_id: Mapped[int] = mapped_column(Integer, unique=True, index=True, nullable=False)
    github_login: Mapped[str] = mapped_column(String(255), nullable=False)
    github_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    github_avatar_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    github_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    # Stored plaintext for now — encrypt with a KMS in production
    github_access_token: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
    last_login_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    scans: Mapped[list[ScanORM]] = relationship(
        back_populates="user", lazy="select"
    )


class ScanORM(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(12), primary_key=True)
    user_id: Mapped[str | None] = mapped_column(
        String(12), ForeignKey("users.id"), nullable=True, index=True
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="queued", index=True)
    repo_path: Mapped[str] = mapped_column(Text, nullable=False)
    github_repo: Mapped[str | None] = mapped_column(String(255), nullable=True)  # "owner/repo"
    app_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    branch: Mapped[str] = mapped_column(String(255), nullable=False, default="main")
    languages: Mapped[str] = mapped_column(Text, nullable=False, default="[]")       # JSON list[str]
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    errors: Mapped[str] = mapped_column(Text, nullable=False, default="[]")           # JSON list[str]
    sandbox_container_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    verified_fixes: Mapped[str] = mapped_column(Text, nullable=False, default="[]")  # JSON list[str]
    still_open: Mapped[str] = mapped_column(Text, nullable=False, default="[]")      # JSON list[str]
    regressions: Mapped[str] = mapped_column(Text, nullable=False, default="[]")     # JSON list[str]
    summary_json: Mapped[str | None] = mapped_column(Text, nullable=True)             # JSON summary dict
    mapped_vulns_json: Mapped[str | None] = mapped_column(Text, nullable=True)        # JSON list[MappedVulnerability]
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )

    user: Mapped[UserORM | None] = relationship(back_populates="scans")
    findings: Mapped[list[FindingORM]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", lazy="select"
    )
    exploits: Mapped[list[ExploitORM]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", lazy="select"
    )
    patches: Mapped[list[PatchORM]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", lazy="select"
    )


class FindingORM(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(12), primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        String(12), ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=False
    )
    source: Mapped[str] = mapped_column(String(20), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    cwe_id: Mapped[str | None] = mapped_column(String(50), nullable=True)
    owasp_category: Mapped[str | None] = mapped_column(String(100), nullable=True)
    file_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    line_start: Mapped[int | None] = mapped_column(Integer, nullable=True)
    line_end: Mapped[int | None] = mapped_column(Integer, nullable=True)
    function_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    code_snippet: Mapped[str | None] = mapped_column(Text, nullable=True)
    endpoint: Mapped[str | None] = mapped_column(Text, nullable=True)
    http_method: Mapped[str | None] = mapped_column(String(10), nullable=True)
    parameter: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tool: Mapped[str | None] = mapped_column(String(100), nullable=True)
    rule_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    raw_output: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON dict
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    scan: Mapped[ScanORM] = relationship(back_populates="findings")


class ExploitORM(Base):
    __tablename__ = "exploits"

    id: Mapped[str] = mapped_column(String(12), primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        String(12), ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=False
    )
    finding_id: Mapped[str] = mapped_column(String(12), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    request: Mapped[str] = mapped_column(Text, nullable=False)
    response_snippet: Mapped[str | None] = mapped_column(Text, nullable=True)
    steps: Mapped[str] = mapped_column(Text, nullable=False, default="[]")  # JSON list[str]
    verified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    scan: Mapped[ScanORM] = relationship(back_populates="exploits")


class PatchORM(Base):
    __tablename__ = "patches"

    id: Mapped[str] = mapped_column(String(12), primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        String(12), ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=False
    )
    finding_id: Mapped[str] = mapped_column(String(12), nullable=False, index=True)
    file_path: Mapped[str] = mapped_column(Text, nullable=False)
    original_code: Mapped[str] = mapped_column(Text, nullable=False)
    patched_code: Mapped[str] = mapped_column(Text, nullable=False)
    diff: Mapped[str] = mapped_column(Text, nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    passes_sast: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    passes_tests: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    exploit_mitigated: Mapped[bool | None] = mapped_column(Boolean, nullable=True)

    scan: Mapped[ScanORM] = relationship(back_populates="patches")


class PullRequestORM(Base):
    __tablename__ = "pull_requests"

    id: Mapped[str] = mapped_column(String(12), primary_key=True)
    scan_id: Mapped[str] = mapped_column(
        String(12), ForeignKey("scans.id", ondelete="CASCADE"), index=True, nullable=False
    )
    user_id: Mapped[str | None] = mapped_column(String(12), ForeignKey("users.id"), nullable=True)
    github_repo: Mapped[str] = mapped_column(String(255), nullable=False)   # "owner/repo"
    pr_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    pr_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    branch: Mapped[str] = mapped_column(String(255), nullable=False)        # fix branch
    base_branch: Mapped[str] = mapped_column(String(255), nullable=False, default="main")
    title: Mapped[str] = mapped_column(Text, nullable=False)
    patch_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="open")  # open/merged/closed/error
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )


class ProtectedBranchORM(Base):
    __tablename__ = "protected_branches"

    id: Mapped[str] = mapped_column(String(12), primary_key=True)
    user_id: Mapped[str] = mapped_column(
        String(12), ForeignKey("users.id"), nullable=False, index=True
    )
    github_repo: Mapped[str] = mapped_column(String(255), nullable=False)   # "owner/repo"
    branch: Mapped[str] = mapped_column(String(255), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    webhook_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    webhook_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: datetime.now(timezone.utc),
    )
