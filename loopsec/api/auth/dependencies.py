"""
FastAPI dependencies for authentication.

Usage in a router:
    CurrentUser = Annotated[UserORM, Depends(get_current_user)]

    @router.get("/something")
    def handler(user: CurrentUser, db: DB):
        ...
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from loopsec.api.auth.jwt import decode_token
from loopsec.api.db.crud import get_user_by_id
from loopsec.api.db.models import UserORM
from loopsec.api.dependencies import get_db

_bearer = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    db: Annotated[Session, Depends(get_db)],
) -> UserORM:
    """
    Extract and validate the Bearer JWT. Raises 401 on any failure.
    Returns the authenticated UserORM.
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = decode_token(credentials.credentials)
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


# Convenience type alias — use this in all routers
CurrentUser = Annotated[UserORM, Depends(get_current_user)]
