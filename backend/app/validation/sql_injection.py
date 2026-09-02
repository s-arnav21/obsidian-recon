"""Conservative differential validation for normalized HTTP SQLi findings."""

from __future__ import annotations

from dataclasses import dataclass
from difflib import SequenceMatcher
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urljoin, urlsplit

from app.models.finding import Finding, STATUS_WEIGHT, ValidationStatus
from app.models.validation import ValidationResult


VALIDATOR_ID = "generic-http-sqli"
VALIDATOR_NAME = "generic_http_sqli"
VALIDATION_METHOD = "boolean-response-differential SQLi"

SUPPORTED_METHODS = frozenset({"GET", "POST"})
SUPPORTED_PARAMETER_LOCATIONS = frozenset({"query", "form"})

# These fixed probes are deliberately internal. Findings and callers cannot
# supply or override validation payloads.
_CONTROL_VALUE = "1"
_TRUE_PROBE_VALUE = "1 AND 1=1"
_FALSE_PROBE_VALUE = "1 AND 1=2"

_CONFIRMED_BASELINE_TRUE_MIN = 0.90
_CONFIRMED_BASELINE_FALSE_MAX = 0.70
_CONFIRMED_SIMILARITY_DELTA_MIN = 0.20
_CONFIRMED_TRUE_FALSE_MAX = 0.75

_REJECTED_TRUE_FALSE_MIN = 0.95
_REJECTED_DELTA_MAX = 0.05

# Bound SequenceMatcher work on unexpectedly large responses.
_COMPARISON_CHARACTER_LIMIT = 100_000


@dataclass(frozen=True)
class _ResponseObservation:
    status: int
    text: str


def _context_evidence(finding: Finding) -> Dict[str, Any]:
    return {
        "endpoint": finding.endpoint,
        "http_method": finding.http_method,
        "parameter_name": finding.parameter_name,
        "parameter_location": finding.parameter_location,
    }


def _manual_review(
    finding: Finding,
    reason: str,
    *,
    evidence: Optional[Dict[str, Any]] = None,
    error: Optional[str] = None,
) -> ValidationResult:
    return ValidationResult(
        status=ValidationStatus.MANUAL_REVIEW,
        confidence=STATUS_WEIGHT[ValidationStatus.MANUAL_REVIEW],
        validator=VALIDATOR_NAME,
        method=VALIDATION_METHOD,
        evidence={
            **_context_evidence(finding),
            **(evidence or {}),
            "decision": "inconclusive",
            "reason": reason,
        },
        error=error,
    )


def _resolve_endpoint_url(finding: Finding) -> str:
    endpoint = (finding.endpoint or "").strip()
    if not endpoint:
        raise ValueError("missing_endpoint")

    endpoint_parts = urlsplit(endpoint)
    if endpoint_parts.scheme or endpoint_parts.netloc:
        target_parts = urlsplit(finding.target)
        endpoint_origin = (
            endpoint_parts.scheme.lower(),
            endpoint_parts.hostname,
            endpoint_parts.port,
        )
        target_origin = (
            target_parts.scheme.lower(),
            target_parts.hostname,
            target_parts.port,
        )
        if endpoint_origin != target_origin:
            raise ValueError("endpoint_origin_mismatch")
        return endpoint

    return urljoin(f"{finding.target.rstrip('/')}/", endpoint.lstrip("/"))


def _validate_context(finding: Finding, session: Any) -> Optional[str]:
    if not finding.endpoint or not finding.endpoint.strip():
        return "missing_endpoint"
    if not finding.http_method:
        return "missing_http_method"
    if not finding.parameter_name or not finding.parameter_name.strip():
        return "missing_parameter_name"
    if not finding.parameter_location:
        return "missing_parameter_location"
    if finding.http_method not in SUPPORTED_METHODS:
        return "unsupported_http_method"
    if finding.parameter_location not in SUPPORTED_PARAMETER_LOCATIONS:
        return "unsupported_parameter_location"
    if session is None:
        return "missing_scoped_http_session"
    return None


def _observe_response(response: Any) -> _ResponseObservation:
    status = getattr(response, "status_code", None)
    text = getattr(response, "text", None)
    if isinstance(status, bool) or not isinstance(status, int):
        raise TypeError("HTTP response status_code must be an integer")
    if not isinstance(text, str):
        raise TypeError("HTTP response text must be a string")
    return _ResponseObservation(status=status, text=text)


def _send_probe(
    session: Any,
    *,
    method: str,
    location: str,
    url: str,
    parameter_name: str,
    value: str,
) -> _ResponseObservation:
    parameters = {parameter_name: value}
    if method == "GET" and location == "query":
        return _observe_response(session.get(url, params=parameters))
    if method == "POST" and location == "form":
        return _observe_response(session.post(url, data=parameters))
    raise ValueError("unsupported_request_shape")


def _similarity(left: str, right: str) -> float:
    return SequenceMatcher(
        None,
        left[:_COMPARISON_CHARACTER_LIMIT],
        right[:_COMPARISON_CHARACTER_LIMIT],
    ).ratio()


def _comparison_evidence(
    finding: Finding,
    baseline: _ResponseObservation,
    true_probe: _ResponseObservation,
    false_probe: _ResponseObservation,
) -> Tuple[Dict[str, Any], float, float, float, float]:
    baseline_true = _similarity(baseline.text, true_probe.text)
    baseline_false = _similarity(baseline.text, false_probe.text)
    true_false = _similarity(true_probe.text, false_probe.text)
    similarity_delta = baseline_true - baseline_false

    evidence = {
        **_context_evidence(finding),
        "baseline_status": baseline.status,
        "true_probe_status": true_probe.status,
        "false_probe_status": false_probe.status,
        "baseline_length": len(baseline.text),
        "true_probe_length": len(true_probe.text),
        "false_probe_length": len(false_probe.text),
        "baseline_true_similarity": round(baseline_true, 6),
        "baseline_false_similarity": round(baseline_false, 6),
        "true_false_similarity": round(true_false, 6),
        "similarity_delta": round(similarity_delta, 6),
        "comparison_character_limit": _COMPARISON_CHARACTER_LIMIT,
        "thresholds": {
            "confirmed_baseline_true_min": _CONFIRMED_BASELINE_TRUE_MIN,
            "confirmed_baseline_false_max": _CONFIRMED_BASELINE_FALSE_MAX,
            "confirmed_similarity_delta_min": _CONFIRMED_SIMILARITY_DELTA_MIN,
            "confirmed_true_false_max": _CONFIRMED_TRUE_FALSE_MAX,
            "rejected_true_false_min": _REJECTED_TRUE_FALSE_MIN,
            "rejected_delta_max": _REJECTED_DELTA_MAX,
        },
    }
    return (
        evidence,
        baseline_true,
        baseline_false,
        true_false,
        similarity_delta,
    )


def validate_generic_http_sqli(
    finding: Finding,
    session: Any,
) -> ValidationResult:
    """Validate a normalized SQLi finding with a pre-approved HTTP client."""
    context_error = _validate_context(finding, session)
    if context_error is not None:
        return _manual_review(finding, context_error)

    try:
        url = _resolve_endpoint_url(finding)
        request_shape = {
            "method": finding.http_method,
            "location": finding.parameter_location,
            "url": url,
            "parameter_name": finding.parameter_name,
        }
        baseline = _send_probe(
            session,
            **request_shape,
            value=_CONTROL_VALUE,
        )
        true_probe = _send_probe(
            session,
            **request_shape,
            value=_TRUE_PROBE_VALUE,
        )
        false_probe = _send_probe(
            session,
            **request_shape,
            value=_FALSE_PROBE_VALUE,
        )
    except Exception as exc:
        return _manual_review(
            finding,
            "http_request_failed",
            error=f"{type(exc).__name__}: {exc}",
        )

    (
        evidence,
        baseline_true,
        baseline_false,
        true_false,
        similarity_delta,
    ) = _comparison_evidence(
        finding,
        baseline,
        true_probe,
        false_probe,
    )

    statuses = {
        baseline.status,
        true_probe.status,
        false_probe.status,
    }
    requests_succeeded = all(200 <= status < 300 for status in statuses)
    if not requests_succeeded:
        return _manual_review(
            finding,
            "non_success_http_status",
            evidence=evidence,
        )
    if len(statuses) != 1:
        return _manual_review(
            finding,
            "inconsistent_http_status",
            evidence=evidence,
        )

    confirmed = (
        baseline_true >= _CONFIRMED_BASELINE_TRUE_MIN
        and baseline_false <= _CONFIRMED_BASELINE_FALSE_MAX
        and similarity_delta >= _CONFIRMED_SIMILARITY_DELTA_MIN
        and true_false <= _CONFIRMED_TRUE_FALSE_MAX
    )
    if confirmed:
        return ValidationResult(
            status=ValidationStatus.CONFIRMED,
            confidence=0.9,
            validator=VALIDATOR_NAME,
            method=VALIDATION_METHOD,
            evidence={
                **evidence,
                "decision": "confirmed",
                "reason": "stable_boolean_response_differential",
            },
        )

    rejected = (
        true_false >= _REJECTED_TRUE_FALSE_MIN
        and abs(similarity_delta) <= _REJECTED_DELTA_MAX
    )
    if rejected:
        return ValidationResult(
            status=ValidationStatus.REJECTED,
            confidence=0.9,
            validator=VALIDATOR_NAME,
            method=VALIDATION_METHOD,
            evidence={
                **evidence,
                "decision": "rejected",
                "reason": "true_and_false_responses_equivalent",
            },
        )

    return _manual_review(
        finding,
        "ambiguous_response_differential",
        evidence=evidence,
    )
