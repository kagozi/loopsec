"""FastAPI dependency providers."""

from __future__ import annotations

from collections.abc import Generator

from sqlalchemy.orm import Session

from loopsec.api.db.engine import SessionLocal


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
