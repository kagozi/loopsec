"""
GitHub repository browser endpoints.

All calls are proxied through our API using the user's stored GitHub access token,
so the frontend never handles GitHub tokens directly.

GET /github/repos                       — list user's repos (own + org)
GET /github/repos/{owner}/{repo}        — get repo details
GET /github/repos/{owner}/{repo}/branches — list branches
GET /github/repos/{owner}/{repo}/languages — language breakdown
"""

from __future__ import annotations

import logging

import httpx
from fastapi import APIRouter, HTTPException, Query

from loopsec.api.auth.dependencies import CurrentUser

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/github", tags=["github"])

_GH_API = "https://api.github.com"
_TIMEOUT = 15


def _gh_headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


async def _gh_get(token: str, path: str, params: dict | None = None) -> dict | list:
    url = f"{_GH_API}{path}"
    async with httpx.AsyncClient() as client:
        resp = await client.get(url, headers=_gh_headers(token), params=params, timeout=_TIMEOUT)
    if resp.status_code == 404:
        raise HTTPException(status_code=404, detail="GitHub resource not found")
    if resp.status_code == 403:
        raise HTTPException(status_code=403, detail="GitHub API rate limit or permission denied")
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/repos")
async def list_repos(
    user: CurrentUser,
    page: int = Query(1, ge=1),
    per_page: int = Query(30, ge=1, le=100),
    sort: str = Query("updated", pattern="^(updated|pushed|full_name|created)$"),
    type: str = Query("all", pattern="^(all|owner|member|public|private)$"),
    visibility: str = Query("all", pattern="^(all|public|private)$"),
) -> dict:
    """
    List repositories the authenticated user has access to.
    Includes owned repos and org repos.
    """
    data = await _gh_get(
        user.github_access_token,
        "/user/repos",
        params={
            "page": page,
            "per_page": per_page,
            "sort": sort,
            "type": type,
            "visibility": visibility,
        },
    )
    repos = [_slim_repo(r) for r in data]  # type: ignore[arg-type]
    return {"repos": repos, "page": page, "per_page": per_page}


@router.get("/repos/{owner}/{repo}")
async def get_repo(owner: str, repo: str, user: CurrentUser) -> dict:
    """Get details for a single repository."""
    data = await _gh_get(user.github_access_token, f"/repos/{owner}/{repo}")
    return _slim_repo(data)  # type: ignore[arg-type]


@router.get("/repos/{owner}/{repo}/branches")
async def list_branches(
    owner: str,
    repo: str,
    user: CurrentUser,
    per_page: int = Query(50, ge=1, le=100),
) -> dict:
    """List branches for a repository."""
    data = await _gh_get(
        user.github_access_token,
        f"/repos/{owner}/{repo}/branches",
        params={"per_page": per_page},
    )
    branches = [
        {"name": b["name"], "sha": b["commit"]["sha"], "protected": b.get("protected", False)}
        for b in data  # type: ignore[union-attr]
    ]
    return {"branches": branches}


@router.get("/repos/{owner}/{repo}/languages")
async def get_languages(owner: str, repo: str, user: CurrentUser) -> dict:
    """Return the language breakdown for a repository (bytes per language)."""
    data = await _gh_get(user.github_access_token, f"/repos/{owner}/{repo}/languages")
    return {"languages": data}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _slim_repo(r: dict) -> dict:
    """Return only the fields the frontend needs."""
    return {
        "id": r["id"],
        "full_name": r["full_name"],
        "name": r["name"],
        "owner": r["owner"]["login"],
        "owner_avatar_url": r["owner"]["avatar_url"],
        "description": r.get("description"),
        "private": r["private"],
        "default_branch": r.get("default_branch", "main"),
        "language": r.get("language"),
        "stargazers_count": r.get("stargazers_count", 0),
        "updated_at": r.get("updated_at"),
        "pushed_at": r.get("pushed_at"),
        "html_url": r["html_url"],
        "clone_url": r["clone_url"],
        "topics": r.get("topics", []),
    }
