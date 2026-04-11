"""
GitHub OAuth 2.0 authentication endpoints.

Flow:
  1. Frontend redirects user to GET /auth/github/login?redirect_uri=<frontend-callback>
  2. We redirect to GitHub with client_id + scope + state (encodes redirect_uri)
  3. GitHub redirects back to GET /auth/github/callback?code=...&state=...
  4. We exchange the code for an access token, fetch the GitHub user, upsert in DB
  5. Issue a JWT and redirect to {redirect_uri}?token=<jwt>
  6. Frontend stores the JWT and uses it as: Authorization: Bearer <token>

Required env vars:
  GITHUB_CLIENT_ID
  GITHUB_CLIENT_SECRET
  LOOPSEC_JWT_SECRET
"""

from __future__ import annotations

import base64
import json
import logging
import os
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from loopsec.api.auth.dependencies import CurrentUser
from loopsec.api.auth.jwt import create_token
from loopsec.api.db import crud
from loopsec.api.dependencies import get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

_GITHUB_AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
_GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
_GITHUB_USER_URL = "https://api.github.com/user"
_GITHUB_EMAILS_URL = "https://api.github.com/user/emails"

DB = Annotated[Session, Depends(get_db)]


def _client_id() -> str:
    v = os.getenv("GITHUB_CLIENT_ID", "")
    if not v:
        raise HTTPException(status_code=500, detail="GITHUB_CLIENT_ID not configured")
    return v


def _client_secret() -> str:
    v = os.getenv("GITHUB_CLIENT_SECRET", "")
    if not v:
        raise HTTPException(status_code=500, detail="GITHUB_CLIENT_SECRET not configured")
    return v


def _encode_state(redirect_uri: str) -> str:
    return base64.urlsafe_b64encode(json.dumps({"r": redirect_uri}).encode()).decode()


def _decode_state(state: str) -> str | None:
    try:
        data = json.loads(base64.urlsafe_b64decode(state.encode()))
        return data.get("r")
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/github/login")
def github_login(
    redirect_uri: str = Query(..., description="Frontend URL to redirect to after auth"),
) -> RedirectResponse:
    """
    Start the GitHub OAuth flow. Redirect the user here to begin login.
    After auth, GitHub will call /auth/github/callback and we'll forward
    to redirect_uri?token=<jwt>.
    """
    state = _encode_state(redirect_uri)
    params = {
        "client_id": _client_id(),
        "scope": "repo read:user user:email",
        "state": state,
    }
    url = _GITHUB_AUTHORIZE_URL + "?" + "&".join(f"{k}={v}" for k, v in params.items())
    return RedirectResponse(url=url)


@router.get("/github/callback")
async def github_callback(
    code: str = Query(...),
    state: str = Query(...),
    db: DB = None,
) -> RedirectResponse:
    """
    GitHub redirects here after the user authorizes. We exchange the code
    for a token, fetch the user profile, issue a JWT, and redirect to the frontend.
    """
    redirect_uri = _decode_state(state)
    if not redirect_uri:
        raise HTTPException(status_code=400, detail="Invalid state parameter")

    async with httpx.AsyncClient() as client:
        # Exchange code for access token
        token_resp = await client.post(
            _GITHUB_TOKEN_URL,
            json={
                "client_id": _client_id(),
                "client_secret": _client_secret(),
                "code": code,
            },
            headers={"Accept": "application/json"},
            timeout=15,
        )
        token_resp.raise_for_status()
        token_data = token_resp.json()
        access_token = token_data.get("access_token")
        if not access_token:
            # Avoid logging sensitive information
            logger.error("GitHub token exchange failed: No access token returned")
            raise HTTPException(status_code=400, detail="GitHub OAuth failed — no access token returned")

        # Fetch user profile
        gh_headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
        }
        user_resp = await client.get(_GITHUB_USER_URL, headers=gh_headers, timeout=10)
        user_resp.raise_for_status()
        gh_user = user_resp.json()

        # Fetch primary email if not public
        email = gh_user.get("email")
        if not email:
            try:
                emails_resp = await client.get(_GITHUB_EMAILS_URL, headers=gh_headers, timeout=10)
                emails_resp.raise_for_status()
                for e in emails_resp.json():
                    if e.get("primary") and e.get("verified"):
                        email = e["email"]
                        break
            except Exception:
                pass  # Email is optional

    # Upsert user in DB and issue JWT
    user = crud.upsert_user(
        db,
        github_id=gh_user["id"],
        github_login=gh_user["login"],
        github_name=gh_user.get("name"),
        github_avatar_url=gh_user.get("avatar_url"),
        github_email=email,
        github_access_token=access_token,
    )

    jwt_token = create_token(user.id)
    sep = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(url=f"{redirect_uri}{sep}token={jwt_token}")


@router.get("/me")
def get_me(user: CurrentUser) -> dict:
    """Return the currently authenticated user's profile."""
    return {
        "id": user.id,
        "github_login": user.github_login,
        "github_name": user.github_name,
        "github_avatar_url": user.github_avatar_url,
        "github_email": user.github_email,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
    }


@router.post("/logout", status_code=204)
def logout(user: CurrentUser) -> None:
    """
    Stateless logout — the client simply discards the JWT.
    This endpoint exists for completeness (e.g., to revoke the GitHub token in future).
    """
    # TODO: maintain a token denylist (Redis) for immediate invalidation
    pass

