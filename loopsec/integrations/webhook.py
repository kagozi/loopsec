"""
GitHub Webhook Server

Listens for GitHub webhook events and triggers LoopSec scans:
- push events → scan the branch, create fix PR if issues found
- pull_request events → scan the PR, post comment with results, set status check

Run with:
    loopsec webhook --port 9000
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import shutil
import tempfile
import threading
from typing import Any

from flask import Flask, Request, request, jsonify

from loopsec.core.config import get_config
from loopsec.core.llm import LLMClient
from loopsec.core.models import PipelineState
from loopsec.core.orchestrator import Orchestrator, generate_report
from loopsec.integrations.github import GitHubClient
from loopsec.integrations.github_pr import GitHubPRBuilder

logger = logging.getLogger(__name__)

webhook_app = Flask("loopsec-webhook")

# Configured at startup
_github_token: str = ""
_webhook_secret: str = ""
_app_url: str | None = None  # Optional: URL of deployed app for DAST


def create_webhook_app(
    github_token: str,
    webhook_secret: str = "",
    app_url: str | None = None,
) -> Flask:
    """Create and configure the webhook Flask app."""
    global _github_token, _webhook_secret, _app_url
    _github_token = github_token
    _webhook_secret = webhook_secret
    _app_url = app_url
    return webhook_app


def _verify_signature(request: Request) -> bool:
    """Verify the GitHub webhook signature."""
    if not _webhook_secret:
        return True  # No secret configured, skip verification

    signature = request.headers.get("X-Hub-Signature-256", "")
    if not signature:
        return False

    expected = "sha256=" + hmac.new(
        _webhook_secret.encode(),
        request.get_data(),
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(signature, expected)


@webhook_app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "loopsec-webhook"})


@webhook_app.route("/webhook", methods=["POST"])
def webhook():
    """Main webhook endpoint — receives GitHub events."""
    if not _verify_signature(request):
        logger.warning("Invalid webhook signature")
        return jsonify({"error": "Invalid signature"}), 401

    event = request.headers.get("X-GitHub-Event", "")
    payload = request.get_json()

    if not payload:
        return jsonify({"error": "No payload"}), 400

    logger.info(f"Received GitHub event: {event}")

    if event == "push":
        # Run async to not block the webhook response
        thread = threading.Thread(
            target=_handle_push, args=(payload,), daemon=True
        )
        thread.start()
        return jsonify({"status": "accepted", "event": "push"}), 202

    elif event == "pull_request":
        action = payload.get("action", "")
        if action in ("opened", "synchronize", "reopened"):
            thread = threading.Thread(
                target=_handle_pull_request, args=(payload,), daemon=True
            )
            thread.start()
            return jsonify({"status": "accepted", "event": "pull_request"}), 202

    elif event == "ping":
        return jsonify({"status": "pong"}), 200

    return jsonify({"status": "ignored", "event": event}), 200


def _handle_push(payload: dict[str, Any]) -> None:
    """Handle a push event — scan the branch and create a fix PR."""
    repo_data = payload.get("repository", {})
    owner = repo_data.get("owner", {}).get("login", "")
    repo = repo_data.get("name", "")
    ref = payload.get("ref", "")
    head_sha = payload.get("after", "")

    # Only scan default branch pushes
    default_branch = repo_data.get("default_branch", "main")
    branch = ref.replace("refs/heads/", "")
    if branch != default_branch:
        logger.info(f"Skipping non-default branch push: {branch}")
        return

    logger.info(f"Processing push to {owner}/{repo}@{branch} ({head_sha[:8]})")

    gh = GitHubClient(_github_token)
    clone_dir = None

    try:
        # Set status to pending
        gh.set_commit_status(
            owner, repo, head_sha,
            state="pending",
            description="LoopSec security scan in progress...",
        )

        # Clone the repo
        clone_dir = gh.clone_repo(owner, repo, branch)

        # Run the pipeline
        orch = Orchestrator()
        state = orch.run(
            repo_path=clone_dir,
            app_url=_app_url,
            branch=branch,
        )

        # Save report
        report_path = os.path.join(clone_dir, f"loopsec-report-{state.id}.md")
        generate_report(state, report_path)

        # Create fix PR if there are patches
        pr_builder = GitHubPRBuilder(gh, owner, repo)

        if state.patches:
            pr = pr_builder.create_fix_pr(state, base_branch=branch)
            if pr:
                logger.info(f"Created fix PR: {pr['html_url']}")

        # Set final commit status
        pr_builder.set_status(head_sha, state)

    except Exception as e:
        logger.error(f"Push handler failed: {e}", exc_info=True)
        try:
            gh.set_commit_status(
                owner, repo, head_sha,
                state="error",
                description=f"LoopSec scan failed: {str(e)[:100]}",
            )
        except Exception:
            pass
    finally:
        if clone_dir:
            shutil.rmtree(clone_dir, ignore_errors=True)


def _handle_pull_request(payload: dict[str, Any]) -> None:
    """Handle a PR event — scan the PR branch, post comment, set status."""
    pr_data = payload.get("pull_request", {})
    repo_data = payload.get("repository", {})
    owner = repo_data.get("owner", {}).get("login", "")
    repo = repo_data.get("name", "")
    pr_number = pr_data.get("number", 0)
    head_sha = pr_data.get("head", {}).get("sha", "")
    head_branch = pr_data.get("head", {}).get("ref", "")
    base_branch = pr_data.get("base", {}).get("ref", "main")

    logger.info(f"Processing PR #{pr_number} on {owner}/{repo} ({head_sha[:8]})")

    gh = GitHubClient(_github_token)
    clone_dir = None

    try:
        # Set status to pending
        gh.set_commit_status(
            owner, repo, head_sha,
            state="pending",
            description="LoopSec security scan in progress...",
        )

        # Clone the PR branch
        clone_dir = gh.clone_repo(owner, repo, head_branch)

        # Run pipeline (skip fixer and verifier for PRs — just scan and report)
        orch = Orchestrator()
        state = orch.run(
            repo_path=clone_dir,
            app_url=_app_url,
            branch=head_branch,
            skip_agents=["fixer", "verifier"],
        )

        # Post findings comment on the PR
        pr_builder = GitHubPRBuilder(gh, owner, repo)
        pr_builder.post_scan_comment(state, pr_number)

        # Set commit status
        pr_builder.set_status(head_sha, state)

        logger.info(f"PR #{pr_number} scan complete: {state.summary()}")

    except Exception as e:
        logger.error(f"PR handler failed: {e}", exc_info=True)
        try:
            gh.set_commit_status(
                owner, repo, head_sha,
                state="error",
                description=f"LoopSec scan failed: {str(e)[:100]}",
            )
        except Exception:
            pass
    finally:
        if clone_dir:
            shutil.rmtree(clone_dir, ignore_errors=True)