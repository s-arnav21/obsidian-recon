"""Conservative reflected-input validation for normalized HTTP findings."""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple
from urllib.parse import urljoin, urlsplit

from app.models.finding import Finding, STATUS_WEIGHT, ValidationStatus
from app.models.validation import ValidationResult


VALIDATOR_ID = "generic-http-reflected-xss"
VALIDATOR_NAME = "generic_http_reflected_xss"
VALIDATION_METHOD = "inert-html-reflection"

SUPPORTED_REQUEST_SHAPES = frozenset({
    ("GET", "query"),
    ("POST", "form"),
})

_CONTROL_VALUE = "obsidian-recon-reflection-control"
_MARKER_TOKEN = "obsidian-recon-reflection-7f3a1"
_INERT_HTML_PROBE = (
    f'<or-reflection data-marker="{_MARKER_TOKEN}"></or-reflection>'
)


def _context_evidence(finding: Finding) -> Dict[str, Any]:
    return {
        "endpoint": finding.endpoint,
        "http_method": finding.http_method,
        "parameter_name": finding.parameter_name,
        "parameter_location": finding.parameter_location,
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


def _validate_context(finding: Finding, session: Any) -> Optional[str]:
    if not finding.endpoint or not finding.endpoint.strip():
        return "missing_endpoint"
    if not finding.http_method:
        return "missing_http_method"
    if not finding.parameter_name or not finding.parameter_name.strip():
        return "missing_parameter_name"
    if not finding.parameter_location:
        return "missing_parameter_location"
    if (
        finding.http_method,
        finding.parameter_location,
    ) not in SUPPORTED_REQUEST_SHAPES:
        return "unsupported_request_shape"
    if session is None:
        return "missing_scoped_http_session"
    return None


def _send_value(
    session: Any,
    finding: Finding,
    url: str,
    value: str,
) -> Any:
    parameters = {finding.parameter_name: value}
    if finding.http_method == "GET":
        return session.get(url, params=parameters)
    return session.post(url, data=parameters)


def _observe_response(response: Any) -> Tuple[int, str, str]:
    status = getattr(response, "status_code", None)
    text = getattr(response, "text", None)
    headers = getattr(response, "headers", {})
    if isinstance(status, bool) or not isinstance(status, int):
        raise TypeError("HTTP response status_code must be an integer")
    if not isinstance(text, str):
        raise TypeError("HTTP response text must be a string")
    content_type = ""
    if hasattr(headers, "get"):
        content_type = headers.get("content-type", "") or headers.get(
            "Content-Type",
            "",
        )
    if not isinstance(content_type, str):
        content_type = str(content_type)
    return status, text, content_type.lower()


def validate_generic_reflected_xss(
    finding: Finding,
    session: Any,
) -> ValidationResult:
    """Verify conservative inert HTML reflection with a scoped HTTP client."""
    context_error = _validate_context(finding, session)
    if context_error is not None:
        return _manual_review(finding, context_error)

    try:
        url = _resolve_endpoint_url(finding)
        baseline_status, baseline_text, _ = _observe_response(
            _send_value(session, finding, url, _CONTROL_VALUE)
        )
        response_status, response_text, content_type = _observe_response(
            _send_value(session, finding, url, _INERT_HTML_PROBE)
        )
    except Exception as exc:
        return _manual_review(
            finding,
            "http_request_failed",
            error=f"{type(exc).__name__}: {exc}",
        )

    marker_reflected = _MARKER_TOKEN in response_text
    raw_probe_reflected = _INERT_HTML_PROBE in response_text
    marker_present_in_baseline = _MARKER_TOKEN in baseline_text
    evidence = {
        "baseline_status": baseline_status,
        "response_status": response_status,
        "response_content_type": content_type,
        "response_size": len(response_text.encode("utf-8")),
        "marker_reflected": marker_reflected,
        "raw_probe_reflected": raw_probe_reflected,
        "marker_present_in_baseline": marker_present_in_baseline,
        "response_context": (
            "raw_html_element"
            if raw_probe_reflected and "text/html" in content_type
            else "reflected_but_context_unresolved"
            if marker_reflected
            else "not_reflected"
        ),
    }

    if not (
        200 <= baseline_status < 300
        and 200 <= response_status < 300
        and baseline_status == response_status
    ):
        return _manual_review(
            finding,
            "non_success_or_inconsistent_http_status",
            evidence=evidence,
        )
    if marker_present_in_baseline:
        return _manual_review(
            finding,
            "marker_preexisting_in_baseline",
            evidence=evidence,
        )
    if raw_probe_reflected and "text/html" in content_type:
        return _result(
            finding,
            status=ValidationStatus.CONFIRMED,
            confidence=0.85,
            decision="confirmed",
            reason="inert_html_element_reflected_without_encoding",
            evidence=evidence,
        )
    if marker_reflected:
        return _manual_review(
            finding,
            "reflection_context_requires_browser_review",
            evidence=evidence,
        )
    return _result(
        finding,
        status=ValidationStatus.REJECTED,
        confidence=0.9,
        decision="rejected",
        reason="marker_not_reflected",
        evidence=evidence,
    )
