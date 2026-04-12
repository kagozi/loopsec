"""
GitHub API Client

Handles all GitHub interactions:
- Clone repos
- Create branches and PRs with fix patches
- Post summary comments on PRs
- Set commit status checks (pass/fail)
"""

from __future__ import annotations

import logging
import subprocess
import tempfile
from pathlib import Path

import httpx

logger = logging.getLogger(__name__)


class GitHubClient:
    """Client for the GitHub REST API."""

    BASE_URL = "https://api.github.com"

    def __init__(self, token: str, app_mode: bool = False):
        """
        Args:
            token: GitHub personal access token or installation token
            app_mode: If True, uses 'Bearer' auth (GitHub App). Otherwise 'token'.
        """
        self.token = token
        auth_prefix = "Bearer" if app_mode else "token"
        self.headers = {
            "Authorization": f"{auth_prefix} {token}",
            "Accept": "application/vnd.github.v3+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        self.client = httpx.Client(
            base_url=self.BASE_URL,
            headers=self.headers,
            timeout=30,
        )

    def _get(self, path: str, params: dict | None = None) -> dict | list:
        resp = self.client.get(path, params=params)
        resp.raise_for_status()
        return resp.json()

    def _post(self, path: str, json: dict | None = None) -> dict:
        resp = self.client.post(path, json=json)
        resp.raise_for_status()
        return resp.json()

    def _patch(self, path: str, json: dict | None = None) -> dict:
        resp = self.client.patch(path, json=json)
        resp.raise_for_status()
        return resp.json()

    # ─── Repository Operations ────────────────────────────

    def get_repo(self, owner: str, repo: str) -> dict:
        return self._get(f"/repos/{owner}/{repo}")

    def clone_repo(
        self,
        owner: str,
        repo: str,
        branch: str = "main",
        dest: str | None = None,
    ) -> str:
        """Clone a repo to a local directory. Returns the path."""
        dest = dest or tempfile.mkdtemp(prefix=f"loopsec-{repo}-")
        clone_url = f"https://x-access-token:{self.token}@github.com/{owner}/{repo}.git"

        logger.info(f"Cloning {owner}/{repo}@{branch} to {dest}")
        subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", branch, clone_url, dest],
            capture_output=True,
            text=True,
            check=True,
        )
        return dest

    def get_default_branch(self, owner: str, repo: str) -> str:
        info = self.get_repo(owner, repo)
        return info.get("default_branch", "main")

    # ─── Branch Operations ────────────────────────────────

    def get_ref(self, owner: str, repo: str, ref: str) -> dict:
        return self._get(f"/repos/{owner}/{repo}/git/ref/heads/{ref}")

    def create_branch(
        self, owner: str, repo: str, branch_name: str, from_sha: str
    ) -> dict:
        """Create a new branch from a commit SHA."""
        logger.info(f"Creating branch {branch_name} from {from_sha[:8]}")
        return self._post(
            f"/repos/{owner}/{repo}/git/refs",
            json={"ref": f"refs/heads/{branch_name}", "sha": from_sha},
        )

    # ─── File Operations ──────────────────────────────────

    def get_file_content(self, owner: str, repo: str, path: str, ref: str = "main") -> dict:
        """Get file content and its SHA (needed for updates)."""
        return self._get(f"/repos/{owner}/{repo}/contents/{path}", params={"ref": ref})

    def update_file(
        self,
        owner: str,
        repo: str,
        path: str,
        content_b64: str,
        message: str,
        branch: str,
        file_sha: str,
    ) -> dict:
        """Update a file on a branch."""
        return self.client.put(
            f"{self.BASE_URL}/repos/{owner}/{repo}/contents/{path}",
            json={
                "message": message,
                "content": content_b64,
                "sha": file_sha,
                "branch": branch,
            },
        ).json()

    # ─── Pull Request Operations ──────────────────────────

    def create_pull_request(
        self,
        owner: str,
        repo: str,
        title: str,
        body: str,
        head: str,
        base: str = "main",
    ) -> dict:
        """Create a pull request."""
        logger.info(f"Creating PR: {title} ({head} → {base})")
        return self._post(
            f"/repos/{owner}/{repo}/pulls",
            json={
                "title": title,
                "body": body,
                "head": head,
                "base": base,
            },
        )

    def add_pr_comment(self, owner: str, repo: str, pr_number: int, body: str) -> dict:
        """Post a comment on a PR."""
        return self._post(
            f"/repos/{owner}/{repo}/issues/{pr_number}/comments",
            json={"body": body},
        )

    def get_pull_request(self, owner: str, repo: str, pr_number: int) -> dict:
        return self._get(f"/repos/{owner}/{repo}/pulls/{pr_number}")

    def list_pull_request_files(self, owner: str, repo: str, pr_number: int) -> list:
        return self._get(f"/repos/{owner}/{repo}/pulls/{pr_number}/files")

    # ─── Commit Status Checks ─────────────────────────────

    def set_commit_status(
        self,
        owner: str,
        repo: str,
        sha: str,
        state: str,
        description: str,
        context: str = "loopsec/security-scan",
        target_url: str | None = None,
    ) -> dict:
        """
        Set a commit status check.

        Args:
            state: "pending", "success", "failure", or "error"
            description: Short description shown in GitHub UI
            context: Name of the status check
            target_url: Link to full report
        """
        payload = {
            "state": state,
            "description": description[:140],  # GitHub limit
            "context": context,
        }
        if target_url:
            payload["target_url"] = target_url

        return self._post(
            f"/repos/{owner}/{repo}/statuses/{sha}",
            json=payload,
        )

    # ─── Check Runs (GitHub Apps) ─────────────────────────

    def create_check_run(
        self,
        owner: str,
        repo: str,
        name: str,
        head_sha: str,
        status: str = "in_progress",
        conclusion: str | None = None,
        title: str = "",
        summary: str = "",
        text: str = "",
    ) -> dict:
        """Create a check run (requires GitHub App permissions)."""
        payload: dict = {
            "name": name,
            "head_sha": head_sha,
            "status": status,
        }
        if conclusion:
            payload["conclusion"] = conclusion
        if title or summary:
            payload["output"] = {
                "title": title or name,
                "summary": summary,
                "text": text,
            }
        return self._post(f"/repos/{owner}/{repo}/check-runs", json=payload)

    def update_check_run(
        self,
        owner: str,
        repo: str,
        check_run_id: int,
        status: str = "completed",
        conclusion: str = "success",
        title: str = "",
        summary: str = "",
        text: str = "",
    ) -> dict:
        """Update an existing check run."""
        payload: dict = {
            "status": status,
            "conclusion": conclusion,
        }
        if title or summary:
            payload["output"] = {
                "title": title,
                "summary": summary,
                "text": text,
            }
        return self._patch(
            f"/repos/{owner}/{repo}/check-runs/{check_run_id}",
            json=payload,
        )

    def create_webhook(
        self,
        owner: str,
        repo: str,
        url: str,
        secret: str,
        events: list[str] | None = None,
    ) -> int:
        """Register a webhook on owner/repo. Returns the webhook ID."""
        data = self._post(f"/repos/{owner}/{repo}/hooks", json={
            "name": "web",
            "active": True,
            "events": events or ["push"],
            "config": {
                "url": url,
                "content_type": "json",
                "secret": secret,
                "insecure_ssl": "0",
            },
        })
        return data["id"]

    def delete_webhook(self, owner: str, repo: str, webhook_id: int) -> bool:
        """Delete a webhook. Returns True on success."""
        try:
            resp = self.client.delete(f"/repos/{owner}/{repo}/hooks/{webhook_id}")
            return resp.status_code == 204
        except Exception:
            return False
