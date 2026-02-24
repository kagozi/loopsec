"""
Base Agent

Abstract base class for all LoopSec agents.
Each agent receives the full PipelineState, does its work, and returns it modified.
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod

from rich.console import Console

from loopsec.core.llm import LLMClient, get_llm
from loopsec.core.models import PipelineState

console = Console()


class BaseAgent(ABC):
    """Base class for all pipeline agents."""

    name: str = "base"
    description: str = ""

    def __init__(self, llm: LLMClient | None = None):
        self.llm = llm or get_llm()
        self.logger = logging.getLogger(f"loopsec.agents.{self.name}")

    @abstractmethod
    def run(self, state: PipelineState) -> PipelineState:
        """Execute the agent's task and return updated state."""
        ...

    def execute(self, state: PipelineState) -> PipelineState:
        """Wrapper that handles logging, timing, and error handling."""
        console.print(f"\n[bold cyan]▶ Running {self.name} agent...[/bold cyan]")
        self.logger.info(f"Agent '{self.name}' starting")
        start = time.time()

        try:
            state = self.run(state)
            elapsed = time.time() - start
            console.print(
                f"[bold green]✓ {self.name} agent completed[/bold green] "
                f"({elapsed:.1f}s)"
            )
            self.logger.info(f"Agent '{self.name}' completed in {elapsed:.1f}s")
        except Exception as e:
            elapsed = time.time() - start
            error_msg = f"Agent '{self.name}' failed after {elapsed:.1f}s: {e}"
            self.logger.error(error_msg, exc_info=True)
            state.errors.append(error_msg)
            console.print(f"[bold red]✗ {self.name} agent failed: {e}[/bold red]")

        return state
