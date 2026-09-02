"""HTTP boundary for the temporary local test harness."""

from __future__ import annotations

from functools import lru_cache
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, StrictBool
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.integrations.labs.dvwa import (
    DVWALabConfigurationError,
    DVWALabConnectionError,
    DVWALabSetupError,
)
from app.services.generic_local_web_validation import LocalTargetConnectionError
from app.services.test_harness import (
    AuthorizationRequiredError,
    HarnessConfigurationError,
    InvalidTargetError,
    TargetNotAllowedError,
    TestHarnessPipeline,
    UnsupportedScenarioError,
)


router = APIRouter(prefix="/api/test-harness", tags=["test-harness"])


class TestHarnessRequest(BaseModel):
    """Only the three fields accepted by the local fixture endpoint."""

    model_config = ConfigDict(extra="forbid")

    target_url: str
    scenario: str
    authorized: StrictBool


@lru_cache
def get_test_harness_pipeline() -> TestHarnessPipeline:
    return TestHarnessPipeline()


@router.post("/run")
def run_test_harness(
    request: TestHarnessRequest,
    pipeline: TestHarnessPipeline = Depends(get_test_harness_pipeline),
    session: Session = Depends(get_db),
) -> Dict[str, Any]:
    try:
        return pipeline.run(
            target_url=request.target_url,
            scenario=request.scenario,
            authorized=request.authorized,
            persistence_session=session,
        )
    except AuthorizationRequiredError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except TargetNotAllowedError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except UnsupportedScenarioError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except InvalidTargetError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except (HarnessConfigurationError, DVWALabConfigurationError) as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except (DVWALabConnectionError, DVWALabSetupError) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except LocalTargetConnectionError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
