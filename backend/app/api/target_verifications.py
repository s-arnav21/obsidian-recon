"""API for persisted DNS TXT proof-of-control challenges."""

from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.scanning.scope import ReconScopeError
from app.services.target_verification import (
    TargetVerificationNotFoundError,
    TargetVerificationService,
)


router = APIRouter(
    prefix="/api/target-verifications",
    tags=["target-verifications"],
)


class TargetVerificationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target_url: str = Field(min_length=1, max_length=2048)


def _verification_service() -> TargetVerificationService:
    return TargetVerificationService()


def _not_found(exc: TargetVerificationNotFoundError) -> HTTPException:
    return HTTPException(status_code=404, detail=str(exc))


@router.post("")
def create_target_verification(
    request: TargetVerificationRequest,
    session: Session = Depends(get_db),
    service: TargetVerificationService = Depends(_verification_service),
) -> Dict[str, Any]:
    try:
        result = service.create_challenge(
            session,
            target_url=request.target_url,
        )
        session.commit()
        return result.to_dict()
    except ReconScopeError as exc:
        session.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception:
        session.rollback()
        raise


@router.post("/{verification_id}/verify")
def verify_target_verification(
    verification_id: str,
    session: Session = Depends(get_db),
    service: TargetVerificationService = Depends(_verification_service),
) -> Dict[str, Any]:
    try:
        result = service.verify_challenge(session, verification_id)
        session.commit()
        return result.to_dict()
    except TargetVerificationNotFoundError as exc:
        session.rollback()
        raise _not_found(exc) from exc
    except Exception:
        session.rollback()
        raise


@router.get("/{verification_id}")
def get_target_verification(
    verification_id: str,
    session: Session = Depends(get_db),
    service: TargetVerificationService = Depends(_verification_service),
) -> Dict[str, Any]:
    try:
        result = service.get_challenge(session, verification_id)
        session.commit()
        return result.to_dict()
    except TargetVerificationNotFoundError as exc:
        session.rollback()
        raise _not_found(exc) from exc
    except Exception:
        session.rollback()
        raise
