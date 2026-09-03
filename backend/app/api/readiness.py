"""Non-secret component readiness for the local prototype UI."""

from __future__ import annotations

import os
import shutil
from typing import Dict, Generator, Optional

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.db.session import get_session_factory


router = APIRouter(prefix="/api", tags=["readiness"])


def get_optional_readiness_db() -> Generator[Optional[Session], None, None]:
    """Yield no session when configuration is absent instead of leaking details."""
    try:
        session = get_session_factory()()
    except Exception:
        yield None
        return
    try:
        yield session
    finally:
        session.close()


def _database_status(session: Optional[Session]) -> str:
    if session is None:
        return "unavailable"
    try:
        session.execute(text("SELECT 1"))
    except Exception:
        session.rollback()
        return "unavailable"
    return "ready"


def _scanner_status(environment_name: str) -> str:
    configured = os.getenv(environment_name, "").strip()
    if not configured:
        return "not_configured"
    return "ready" if shutil.which(configured) else "unavailable"


@router.get("/readiness")
def readiness(
    session: Optional[Session] = Depends(get_optional_readiness_db),
) -> Dict[str, object]:
    components = {
        "backend": {"status": "ready"},
        "postgresql": {"status": _database_status(session)},
        "nmap": {"status": _scanner_status("RECON_NMAP_PATH")},
        "nuclei": {"status": _scanner_status("RECON_NUCLEI_PATH")},
    }
    overall = (
        "ready"
        if all(component["status"] == "ready" for component in components.values())
        else "degraded"
    )
    return {"status": overall, "components": components}
