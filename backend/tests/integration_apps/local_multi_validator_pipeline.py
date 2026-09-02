"""Compatibility imports for the Step 7 integration-test contract."""

from app.services.generic_local_web_validation import (
    ScopedLoopbackHttpClient,
    TargetScopeError,
    run_local_multi_validator_pipeline,
)


__all__ = [
    "ScopedLoopbackHttpClient",
    "TargetScopeError",
    "run_local_multi_validator_pipeline",
]
