"""
SQLAlchemy engine, session factory, and table creation.
SQLite with WAL mode for safe concurrent access from background threads.
"""

from __future__ import annotations

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from loopsec.core.config import get_config


class Base(DeclarativeBase):
    pass


def _configure_sqlite(dbapi_conn, _connection_record) -> None:
    """Enable WAL mode and NORMAL sync for concurrent read/write safety."""
    dbapi_conn.execute("PRAGMA journal_mode=WAL")
    dbapi_conn.execute("PRAGMA synchronous=NORMAL")
    dbapi_conn.execute("PRAGMA foreign_keys=ON")


def _build_engine():
    work_dir = get_config().work_dir
    work_dir.mkdir(parents=True, exist_ok=True)
    db_url = f"sqlite:///{work_dir}/loopsec.db"
    eng = create_engine(
        db_url,
        connect_args={"check_same_thread": False},
        echo=False,
    )
    event.listen(eng, "connect", _configure_sqlite)
    return eng


engine = _build_engine()
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)


def create_tables() -> None:
    """Idempotent — safe to call on every startup."""
    Base.metadata.create_all(engine)
