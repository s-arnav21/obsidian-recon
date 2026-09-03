"""Authorized synchronous reconnaissance entry point for local development."""

from __future__ import annotations

import os
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from pydantic import AnyHttpUrl, BaseModel, ConfigDict, StrictBool
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.scanning.nmap import NmapScanner
from app.scanning.nuclei import NucleiScanner
from app.scanning.scope import ReconAuthorizationError, ReconScopeError
from app.scanning.tool_runner import ScannerToolError
from app.services.recon_pipeline import ReconPipeline


router = APIRouter(prefix="/api/scans", tags=["reconnaissance"])


class ReconScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_url: AnyHttpUrl
    authorized: StrictBool


def _configured_pipeline() -> ReconPipeline:
    allowed_origins = tuple(filter(None, (
        value.strip()
        for value in os.getenv("RECON_ALLOWED_ORIGINS", "").split(",")
    )))
    nmap_path = os.getenv("RECON_NMAP_PATH")
    nuclei_path = os.getenv("RECON_NUCLEI_PATH")
    return ReconPipeline(
        nmap_scanner=NmapScanner(nmap_path) if nmap_path else None,
        nuclei_scanner=NucleiScanner(nuclei_path) if nuclei_path else None,
        allowed_origins=allowed_origins,
    )


@router.post("/run")
def run_recon_scan(
    request: ReconScanRequest,
    session: Session = Depends(get_db),
    pipeline: ReconPipeline = Depends(_configured_pipeline),
) -> Dict[str, Any]:
    try:
        return pipeline.run(
            target_url=str(request.target_url),
            authorized=request.authorized,
            session=session,
        ).to_dict()
    except ReconAuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except ReconScopeError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ScannerToolError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except ConnectionError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
