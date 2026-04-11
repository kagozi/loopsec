"""
JWT creation and validation for LoopSec API sessions.

Tokens are HS256-signed JWTs with a configurable expiry.
The secret key is read from LOOPSEC_JWT_SECRET at startup.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import jwt

_SECRET = os.getenv("LOOPSEC_JWT_SECRET", "change-me-in-production-use-a-long-random-string")
_ALGORITHM = "HS256"
_EXPIRY_DAYS = int(os.getenv("LOOPSEC_JWT_EXPIRY_DAYS", "30"))


def create_token(user_id: str) -> str:
    """Issue a signed JWT for the given user_id."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user_id,
        "iat": now,
        "exp": now + timedelta(days=_EXPIRY_DAYS),
    }
    return jwt.encode(payload, _SECRET, algorithm=_ALGORITHM)


def decode_token(token: str) -> str | None:
    """
    Validate and decode a JWT. Returns the user_id (sub) or None if invalid/expired.
    """
    try:
        payload = jwt.decode(token, _SECRET, algorithms=[_ALGORITHM])
        return payload["sub"]
    except jwt.PyJWTError:
        return None
