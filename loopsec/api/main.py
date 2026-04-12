"""
LoopSec FastAPI application.

Start with:
    loopsec api --port 8000
    uvicorn loopsec.api.main:app --reload   # for development
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from loopsec.api.db.crud import cleanup_stale_scans
from loopsec.api.db.engine import SessionLocal, create_tables, run_migrations
from loopsec.api.routers import exploits, findings, patches, pull_requests, scans, stream
from loopsec.api.routers.auth import router as auth_router
from loopsec.api.routers.github_repos import router as github_router
from loopsec.api.routers.protected_branches import router as protected_branches_router

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    create_tables()
    run_migrations()
    with SessionLocal() as db:
        stale = cleanup_stale_scans(db)
        if stale:
            logger.warning("Marked %d stale in-progress scan(s) as errored on startup", stale)
    yield
    # Shutdown — nothing to clean up


app = FastAPI(
    title="LoopSec API",
    description="Closed-loop AI security agent — trigger scans, stream progress, retrieve results.",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # tighten to your frontend domain before production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Routers ---
app.include_router(auth_router)                               # /auth/*
app.include_router(github_router)                             # /github/*
app.include_router(scans.router, prefix="/scans", tags=["scans"])
app.include_router(stream.router, tags=["stream"])
app.include_router(findings.router, tags=["findings"])
app.include_router(patches.router, tags=["patches"])
app.include_router(exploits.router, tags=["exploits"])
app.include_router(pull_requests.router, tags=["pull-requests"])
app.include_router(protected_branches_router, tags=["branch-protection"])


@app.get("/health", tags=["meta"])
def health() -> dict:
    """Health check — confirms the API and DB are up."""
    try:
        with SessionLocal() as db:
            db.execute(__import__("sqlalchemy").text("SELECT 1"))
        db_status = "connected"
    except Exception:
        db_status = "error"

    return {"status": "ok", "version": "0.1.0", "db": db_status}
