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
from app.presentation import decorate_pipeline_response
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
    """Strict request accepted by the controlled test-harness endpoint."""

    model_config = ConfigDict(extra="forbid")

    target_url: str
    scenario: str
    authorized: StrictBool
    skip_dns_verification: StrictBool = False


@lru_cache
def get_test_harness_pipeline() -> TestHarnessPipeline:
    return TestHarnessPipeline()


@router.get("/config")
def get_test_harness_config(
    pipeline: TestHarnessPipeline = Depends(get_test_harness_pipeline),
) -> Dict[str, bool]:
    return {
        "development_dns_bypass_enabled": pipeline.dev_dns_bypass_enabled,
    }


@router.post("/run")
def run_test_harness(
    request: TestHarnessRequest,
    pipeline: TestHarnessPipeline = Depends(get_test_harness_pipeline),
    session: Session = Depends(get_db),
) -> Dict[str, Any]:
    try:
        result = pipeline.run(
            target_url=request.target_url,
            scenario=request.scenario,
            authorized=request.authorized,
            persistence_session=session,
            skip_dns_verification=request.skip_dns_verification,
        )
        return decorate_pipeline_response(result, controlled_lab=True)
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
