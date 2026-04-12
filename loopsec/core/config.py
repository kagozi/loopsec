"""
LoopSec Configuration

Centralized settings loaded from environment variables and/or config file.
"""

from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, Field


class LLMConfig(BaseModel):
    provider: str = "openai"
    model: str = "gpt-4o"
    api_key: str = Field(default_factory=lambda: os.getenv("OPENAI_API_KEY", ""))
    temperature: float = 0.1
    max_tokens: int = 4096
    timeout: int = 120


class SandboxConfig(BaseModel):
    docker_network: str = "loopsec-net"
    default_timeout: int = 300          # 5 min per container operation
    max_containers: int = 5
    cleanup_on_finish: bool = True


class ToolsConfig(BaseModel):
    semgrep_rules: str = "auto"         # "auto", "p/security-audit", or path
    nuclei_templates: str = ""          # Path to custom templates (empty = defaults)
    zap_api_key: str = Field(default_factory=lambda: os.getenv("ZAP_API_KEY", ""))
    zap_host: str = "http://localhost:8080"
    sqlmap_level: int = 3
    sqlmap_risk: int = 2


class Config(BaseModel):
    """Master configuration object."""

    llm: LLMConfig = Field(default_factory=LLMConfig)
    sandbox: SandboxConfig = Field(default_factory=SandboxConfig)
    tools: ToolsConfig = Field(default_factory=ToolsConfig)

    # General
    work_dir: Path = Field(default_factory=lambda: Path(os.getenv("LOOPSEC_WORK_DIR", str(Path.home() / ".loopsec"))))
    log_level: str = "INFO"
    max_findings_to_fix: int = 20       # Don't try to fix everything at once
    auto_apply_patches: bool = False    # Safety: require confirmation by default

    @classmethod
    def from_env(cls) -> Config:
        """Build config from environment variables."""
        return cls(
            llm=LLMConfig(
                provider=os.getenv("LOOPSEC_LLM_PROVIDER", "openai"),
                model=os.getenv("LOOPSEC_LLM_MODEL", "gpt-4o"),
                api_key=os.getenv("OPENAI_API_KEY", ""),
            ),
            tools=ToolsConfig(
                semgrep_rules=os.getenv("LOOPSEC_SEMGREP_RULES", "auto"),
                zap_host=os.getenv("ZAP_HOST", "http://localhost:8080"),
            ),
            work_dir=Path(os.getenv("LOOPSEC_WORK_DIR", str(Path.home() / ".loopsec"))),
            log_level=os.getenv("LOOPSEC_LOG_LEVEL", "INFO"),
        )


# Singleton
_config: Config | None = None


def get_config() -> Config:
    global _config
    if _config is None:
        _config = Config.from_env()
    return _config


def set_config(config: Config) -> None:
    global _config
    _config = config
