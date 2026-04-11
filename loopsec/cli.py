"""
LoopSec CLI

Usage:
    loopsec scan --repo ./my-app --url http://localhost:8080
    loopsec scan --repo ./my-app                              # SAST only
    loopsec scan --repo ./my-app --skip attacker verifier     # Skip DAST
    loopsec report --input results.json --output report.md
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

app = typer.Typer(
    name="loopsec",
    help="LoopSec — Closed-Loop AI Security Agent",
    add_completion=False,
)
console = Console()


def setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    # Quiet noisy libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("litellm").setLevel(logging.WARNING)
    logging.getLogger("openai").setLevel(logging.WARNING)


@app.command()
def scan(
    repo: str = typer.Option(..., "--repo", "-r", help="Path to source code repository"),
    url: Optional[str] = typer.Option(None, "--url", "-u", help="URL of deployed application"),
    branch: str = typer.Option("main", "--branch", "-b", help="Git branch to scan"),
    skip: Optional[list[str]] = typer.Option(None, "--skip", "-s", help="Agents to skip"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output report path"),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="LLM model override"),
    no_deploy: bool = typer.Option(False, "--no-deploy", help="Disable auto-deploy via Docker sandbox"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging"),
) -> None:
    """Run the full security scan pipeline."""
    setup_logging("DEBUG" if verbose else "INFO")

    # Validate repo path
    repo_path = Path(repo).resolve()
    if not repo_path.exists():
        console.print(f"[red]Error: Repository path not found: {repo_path}[/red]")
        raise typer.Exit(1)

    # Override model if specified
    if model:
        from loopsec.core.config import get_config
        get_config().llm.model = model

    # Run pipeline
    from loopsec.core.orchestrator import Orchestrator, generate_report

    orch = Orchestrator()
    state = orch.run(
        repo_path=str(repo_path),
        app_url=url,
        branch=branch,
        skip_agents=skip or [],
        auto_deploy=not no_deploy,
    )

    # Generate report
    report_path = output or f"loopsec-report-{state.id}.md"
    generate_report(state, report_path)
    console.print(f"\n[bold]Report saved: {report_path}[/bold]")

    # Save raw JSON results
    json_path = report_path.replace(".md", ".json")
    Path(json_path).write_text(state.model_dump_json(indent=2))
    console.print(f"[dim]Raw results: {json_path}[/dim]")

    # Exit with non-zero if critical/high findings remain unfixed
    unfixed = state.get_unfixed_findings()
    from loopsec.core.models import Severity
    critical_unfixed = [
        f for f in unfixed if f.severity in (Severity.CRITICAL, Severity.HIGH)
    ]
    if critical_unfixed:
        console.print(
            f"\n[bold red]{len(critical_unfixed)} critical/high findings remain unfixed[/bold red]"
        )
        raise typer.Exit(1)


@app.command()
def analyze(
    repo: str = typer.Option(..., "--repo", "-r", help="Path to source code"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Run only the static analysis (SAST) agent."""
    setup_logging("DEBUG" if verbose else "INFO")

    from loopsec.agents.analyzer import AnalyzerAgent
    from loopsec.core.models import PipelineState, ScanTarget

    state = PipelineState(target=ScanTarget(repo_path=str(Path(repo).resolve())))
    agent = AnalyzerAgent()
    state = agent.execute(state)

    console.print(f"\n[bold]Found {len(state.findings)} issues[/bold]")


@app.command()
def version() -> None:
    """Show LoopSec version."""
    console.print("[bold cyan]LoopSec[/bold cyan] v0.1.0")


@app.command()
def webhook(
    port: int = typer.Option(9000, "--port", "-p", help="Port to listen on"),
    host: str = typer.Option("0.0.0.0", "--host", help="Host to bind to"),
    github_token: Optional[str] = typer.Option(
        None, "--github-token", envvar="GITHUB_TOKEN", help="GitHub token"
    ),
    webhook_secret: Optional[str] = typer.Option(
        None, "--webhook-secret", envvar="LOOPSEC_WEBHOOK_SECRET", help="Webhook secret"
    ),
    app_url: Optional[str] = typer.Option(
        None, "--app-url", help="Target app URL for DAST scanning"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Start the GitHub webhook server."""
    setup_logging("DEBUG" if verbose else "INFO")

    if not github_token:
        console.print("[red]Error: --github-token or GITHUB_TOKEN env var required[/red]")
        raise typer.Exit(1)

    from loopsec.integrations.webhook import create_webhook_app

    flask_app = create_webhook_app(
        github_token=github_token,
        webhook_secret=webhook_secret or "",
        app_url=app_url,
    )

    console.print(f"[bold cyan]LoopSec Webhook Server[/bold cyan]")
    console.print(f"  Listening on: http://{host}:{port}")
    console.print(f"  Webhook URL:  http://<your-domain>:{port}/webhook")
    console.print(f"  Health check: http://{host}:{port}/health")
    console.print(f"  DAST target:  {app_url or 'disabled'}")
    console.print(f"\n  [dim]Configure this URL in your GitHub repo → Settings → Webhooks[/dim]")
    console.print(f"  [dim]Events to subscribe: push, pull_request[/dim]\n")

    flask_app.run(host=host, port=port, debug=verbose)


@app.command()
def github_scan(
    repo_slug: str = typer.Argument(help="GitHub repo (owner/repo)"),
    branch: Optional[str] = typer.Option(None, "--branch", "-b", help="Branch to scan"),
    pr_number: Optional[int] = typer.Option(None, "--pr", help="PR number to scan and comment on"),
    app_url: Optional[str] = typer.Option(None, "--url", "-u", help="App URL for DAST"),
    github_token: Optional[str] = typer.Option(
        None, "--github-token", envvar="GITHUB_TOKEN", help="GitHub token"
    ),
    create_pr: bool = typer.Option(False, "--create-pr", help="Create fix PR with patches"),
    model: Optional[str] = typer.Option(None, "--model", "-m", help="LLM model override"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Scan a GitHub repo directly and optionally create a fix PR.

    Examples:
        loopsec github-scan myorg/myapp
        loopsec github-scan myorg/myapp --pr 42
        loopsec github-scan myorg/myapp --create-pr
        loopsec github-scan myorg/myapp --branch develop --url http://localhost:5001
    """
    setup_logging("DEBUG" if verbose else "INFO")

    if not github_token:
        console.print("[red]Error: --github-token or GITHUB_TOKEN env var required[/red]")
        raise typer.Exit(1)

    # Parse owner/repo
    parts = repo_slug.split("/")
    if len(parts) != 2:
        console.print(f"[red]Error: repo must be in 'owner/repo' format, got: {repo_slug}[/red]")
        raise typer.Exit(1)
    owner, repo = parts

    if model:
        from loopsec.core.config import get_config
        get_config().llm.model = model

    import shutil
    from loopsec.integrations.github import GitHubClient
    from loopsec.integrations.github_pr import GitHubPRBuilder
    from loopsec.core.orchestrator import Orchestrator, generate_report

    gh = GitHubClient(github_token)

    # Determine branch
    if not branch:
        branch = gh.get_default_branch(owner, repo)
        console.print(f"[dim]Using default branch: {branch}[/dim]")

    # If scanning a PR, get its branch
    head_sha = None
    if pr_number:
        pr_data = gh.get_pull_request(owner, repo, pr_number)
        branch = pr_data["head"]["ref"]
        head_sha = pr_data["head"]["sha"]
        console.print(f"[dim]Scanning PR #{pr_number} branch: {branch}[/dim]")

    # Clone
    console.print(f"[dim]Cloning {owner}/{repo}@{branch}...[/dim]")
    clone_dir = gh.clone_repo(owner, repo, branch)

    try:
        # Set pending status if we have a SHA
        if head_sha:
            gh.set_commit_status(
                owner, repo, head_sha,
                state="pending",
                description="LoopSec security scan in progress...",
            )

        # Run pipeline
        skip = []
        if pr_number and not create_pr:
            skip = ["fixer", "verifier"]  # Just scan for PRs

        orch = Orchestrator()
        state = orch.run(
            repo_path=clone_dir,
            app_url=app_url,
            branch=branch,
            skip_agents=skip,
        )

        # Generate report
        report_path = f"loopsec-report-{owner}-{repo}-{state.id}.md"
        generate_report(state, report_path)
        console.print(f"\n[bold]Report saved: {report_path}[/bold]")

        pr_builder = GitHubPRBuilder(gh, owner, repo)

        # Post comment on PR
        if pr_number:
            pr_builder.post_scan_comment(state, pr_number)
            console.print(f"[green]Posted scan results on PR #{pr_number}[/green]")

        # Set commit status
        if head_sha:
            pr_builder.set_status(head_sha, state)

        # Create fix PR
        if create_pr and state.patches:
            pr = pr_builder.create_fix_pr(state, base_branch=branch)
            if pr:
                console.print(f"[bold green]Fix PR created: {pr['html_url']}[/bold green]")
            else:
                console.print("[yellow]No patches to create PR for[/yellow]")

    finally:
        shutil.rmtree(clone_dir, ignore_errors=True)


@app.command()
def api(
    port: int = typer.Option(8000, "--port", "-p", help="Port to listen on"),
    host: str = typer.Option("127.0.0.1", "--host", help="Host to bind to"),
    reload: bool = typer.Option(False, "--reload", help="Enable auto-reload (dev mode)"),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    """Start the LoopSec REST API server."""
    setup_logging("DEBUG" if verbose else "INFO")

    try:
        import uvicorn
    except ImportError:
        console.print("[red]Error: uvicorn is required. Install with: pip install 'loopsec[api]'[/red]")
        raise typer.Exit(1)

    console.print(f"[bold cyan]LoopSec API Server[/bold cyan]")
    console.print(f"  Listening on: http://{host}:{port}")
    console.print(f"  Docs:         http://{host}:{port}/docs")
    console.print(f"  Health:       http://{host}:{port}/health\n")

    uvicorn.run(
        "loopsec.api.main:app",
        host=host,
        port=port,
        reload=reload,
        log_level="debug" if verbose else "info",
    )


def main() -> None:
    app()


if __name__ == "__main__":
    main()
