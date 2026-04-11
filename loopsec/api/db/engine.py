"""
SQLAlchemy engine, session factory, and table creation.
SQLite with WAL mode for safe concurrent access from background threads.
"""

from __future__ import annotations

from sqlalchemy import create_engine, event, text
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


def run_migrations() -> None:
    """
    Add columns introduced after the initial schema, idempotently.
    Called on startup after create_tables().
    """
    with engine.connect() as conn:
        # scans: user_id (added with auth)
        cols = {row[1] for row in conn.execute(text("PRAGMA table_info(scans)"))}
        if "user_id" not in cols:
            conn.execute(text("ALTER TABLE scans ADD COLUMN user_id VARCHAR(12)"))
            conn.commit()
        if "github_repo" not in cols:
            conn.execute(text("ALTER TABLE scans ADD COLUMN github_repo VARCHAR(255)"))
            conn.commit()

        # pull_requests table (added with auto-PR feature)
        tables = {row[0] for row in conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))}
        if "pull_requests" not in tables:
            conn.execute(text("""
                CREATE TABLE pull_requests (
                    id VARCHAR(12) PRIMARY KEY,
                    scan_id VARCHAR(12) NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                    user_id VARCHAR(12) REFERENCES users(id),
                    github_repo VARCHAR(255) NOT NULL,
                    pr_number INTEGER,
                    pr_url TEXT,
                    branch VARCHAR(255) NOT NULL,
                    base_branch VARCHAR(255) NOT NULL DEFAULT 'main',
                    title TEXT NOT NULL,
                    patch_count INTEGER NOT NULL DEFAULT 0,
                    status VARCHAR(20) NOT NULL DEFAULT 'open',
                    error TEXT,
                    created_at DATETIME NOT NULL
                )
            """))
            conn.commit()
