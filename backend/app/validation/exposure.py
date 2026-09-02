"""Safe retrieval validation for scanner-discovered exposed resources."""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlsplit

from app.models.finding import Finding, STATUS_WEIGHT, ValidationStatus
from app.models.validation import ValidationResult


VALIDATOR_ID = "generic-http-exposed-resource"
VALIDATOR_NAME = "generic_http_exposed_resource"
VALIDATION_METHOD = "safe-http-resource-verification"

_CLASSIFICATION_CHARACTER_LIMIT = 100_000
_ENV_ASSIGNMENT = re.compile(
    r"(?m)^[A-Z][A-Z0-9_]{2,}\s*=\s*\S+\s*$"
)
_SENSITIVE_JSON_KEY = re.compile(
    r'(?i)["\'](?:api[_-]?key|password|secret|token)["\']\s*:'
)


def _context_evidence(finding: Finding) -> Dict[str, Any]:
    return {
        "endpoint": finding.endpoint,
        "http_method": finding.http_method,
    }


def _result(
    finding: Finding,
    *,
    status: str,
    confidence: float,
    decision: str,
    reason: str,
    evidence: Optional[Dict[str, Any]] = None,
    error: Optional[str] = None,
) -> ValidationResult:
    return ValidationResult(
        status=status,
        confidence=confidence,
        validator=VALIDATOR_NAME,
        method=VALIDATION_METHOD,
        evidence={
            **_context_evidence(finding),
            **(evidence or {}),
            "decision": decision,
            "reason": reason,
        },
        error=error,
    )


def _manual_review(
    finding: Finding,
    reason: str,
    *,
    evidence: Optional[Dict[str, Any]] = None,
    error: Optional[str] = None,
) -> ValidationResult:
    return _result(
        finding,
        status=ValidationStatus.MANUAL_REVIEW,
        confidence=STATUS_WEIGHT[ValidationStatus.MANUAL_REVIEW],
        decision="inconclusive",
        reason=reason,
        evidence=evidence,
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


def _content_type(response: Any) -> str:
    headers = getattr(response, "headers", {})
    value = ""
    if hasattr(headers, "get"):
        value = headers.get("content-type", "") or headers.get(
            "Content-Type",
            "",
        )
    return value.lower() if isinstance(value, str) else str(value).lower()


def _classification_signals(text: str) -> List[str]:
    sample = text[:_CLASSIFICATION_CHARACTER_LIMIT]
    lowered = sample.lower()
    signals = []
    if "-----begin private key-----" in lowered:
        signals.append("private_key_material")
    if len(_ENV_ASSIGNMENT.findall(sample)) >= 2:
        signals.append("environment_assignment_set")
    if len(set(_SENSITIVE_JSON_KEY.findall(sample))) >= 2:
        signals.append("sensitive_configuration_keys")
    if (
        "traceback (most recent call last)" in lowered
        or "stack trace:" in lowered
        or "exception in thread" in lowered
    ):
        signals.append("debug_stack_trace")
    if "<title>index of /" in lowered or "<h1>index of /" in lowered:
        signals.append("directory_listing")
    return signals


def _observe_response(response: Any) -> Tuple[int, str, str]:
    status = getattr(response, "status_code", None)
    text = getattr(response, "text", None)
    if isinstance(status, bool) or not isinstance(status, int):
        raise TypeError("HTTP response status_code must be an integer")
    if not isinstance(text, str):
        raise TypeError("HTTP response text must be a string")
    return status, text, _content_type(response)


def validate_generic_exposed_resource(
    finding: Finding,
    session: Any,
) -> ValidationResult:
    """Verify only the supplied resource endpoint with a scoped HTTP client."""
    if not finding.endpoint or not finding.endpoint.strip():
        return _manual_review(finding, "missing_endpoint")
    if finding.http_method != "GET":
        return _manual_review(finding, "unsupported_http_method")
    if session is None:
        return _manual_review(finding, "missing_scoped_http_session")

    try:
        url = _resolve_endpoint_url(finding)
        status, text, content_type = _observe_response(session.get(url))
    except Exception as exc:
        reason = (
            "endpoint_origin_mismatch"
            if str(exc) == "endpoint_origin_mismatch"
            else "http_request_failed"
        )
        return _manual_review(
            finding,
            reason,
            error=f"{type(exc).__name__}: {exc}",
        )

    signals = _classification_signals(text)
    evidence = {
        "response_status": status,
        "response_content_type": content_type,
        "response_size": len(text.encode("utf-8")),
        "classification_signals": signals,
        "classification_character_limit": _CLASSIFICATION_CHARACTER_LIMIT,
    }

    if status in {401, 403, 404, 410}:
        return _result(
            finding,
            status=ValidationStatus.REJECTED,
            confidence=0.95,
            decision="rejected",
            reason="resource_not_publicly_accessible",
            evidence=evidence,
        )
    if not 200 <= status < 300:
        return _manual_review(
            finding,
            "non_success_http_status",
            evidence=evidence,
        )
    if signals:
        return _result(
            finding,
            status=ValidationStatus.CONFIRMED,
            confidence=0.9,
            decision="confirmed",
            reason="strong_sensitive_resource_signal",
            evidence=evidence,
        )
    return _manual_review(
        finding,
        "accessible_resource_without_strong_sensitive_signal",
        evidence=evidence,
    )
