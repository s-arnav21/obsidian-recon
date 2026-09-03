"""Deterministic same-origin controlled-canary SSRF validation."""

from __future__ import annotations

import hashlib
import html
import re
import time
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import quote, urlencode, urljoin, urlsplit

import httpx

from app.models.finding import Finding, STATUS_WEIGHT, ValidationStatus
from app.models.validation import ValidationResult
from app.validation.http_policy import header_mutation_error


VALIDATOR_ID = "generic-http-ssrf"
VALIDATOR_NAME = "generic_http_ssrf"
VALIDATION_METHOD = "controlled same-origin canary retrieval"

SUPPORTED_METHODS = frozenset({"GET", "POST", "PUT", "PATCH"})
SUPPORTED_PARAMETER_LOCATIONS = frozenset({
    "query", "form", "json", "cookie", "header",
})
SUPPORTED_REQUEST_SHAPES = frozenset(
    (method, location)
    for method in SUPPORTED_METHODS
    for location in SUPPORTED_PARAMETER_LOCATIONS
)

CONTROLLED_CANARY_PATH = "/__obsidian_ssrf/canary"
CONTROLLED_CONTROL_PATH = "/__obsidian_ssrf/control"

_REQUEST_TIMEOUT_SECONDS = 5.0
_MAX_REQUEST_ATTEMPTS = 3
_RETRY_BACKOFF_SECONDS = 0.05
_ANALYSIS_CHARACTER_LIMIT = 100_000
_WAF_STATUS_CODES = frozenset({403, 406, 429})
_WAF_TEXT_PATTERNS = (
    re.compile(r"web application firewall", re.I),
    re.compile(r"request (?:was )?blocked", re.I),
    re.compile(r"blocked by (?:a )?security (?:rule|policy)", re.I),
    re.compile(r"mod_security|modsecurity", re.I),
    re.compile(r"temporarily rate[ -]?limited", re.I),
)


@dataclass(frozen=True)
class _ResponseObservation:
    status: int
    text: str
    content_type: str
    attempts: int


@dataclass(frozen=True)
class _CanaryPlan:
    baseline_url: str
    baseline_identifier: str
    baseline_content_marker: str
    canary_url: str
    canary_identifier: str
    canary_content_marker: str
    negative_url: str
    negative_identifier: str
    negative_content_marker: str


class _ProbeRequestFailure(RuntimeError):
    def __init__(self, attempts: int) -> None:
        super().__init__("bounded probe request failed")
        self.attempts = attempts


def controlled_content_marker(kind: str, identifier: str) -> str:
    """Derive fixture content that is intentionally absent from the URL."""
    if kind not in {"canary", "control"}:
        raise ValueError("unsupported controlled marker kind")
    digest = hashlib.sha256(
        f"obsidian-recon:ssrf:{kind}:{identifier}".encode("utf-8")
    ).hexdigest()[:24]
    return f"or-ssrf-{kind}-content-{digest}"


def _finding_marker_root(finding: Finding) -> str:
    identity = "\x1f".join((
        finding.finding_id,
        finding.scan_id,
        finding.asset_id,
        finding.target,
        finding.endpoint or "",
        finding.http_method or "",
        finding.parameter_location or "",
        finding.parameter_name or "",
    ))
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:20]


def _controlled_url(origin: str, path: str, identifier: str) -> str:
    base = f"{origin.rstrip('/')}/"
    endpoint = urljoin(base, path.lstrip("/"))
    return f"{endpoint}?{urlencode({'id': identifier})}"


def _canary_plan(finding: Finding) -> _CanaryPlan:
    root = _finding_marker_root(finding)
    baseline_identifier = f"or-ssrf-baseline-{root}"
    canary_identifier = f"or-ssrf-canary-{root}"
    negative_identifier = f"or-ssrf-negative-{root}"
    return _CanaryPlan(
        baseline_url=_controlled_url(
            finding.target,
            CONTROLLED_CONTROL_PATH,
            baseline_identifier,
        ),
        baseline_identifier=baseline_identifier,
        baseline_content_marker=controlled_content_marker(
            "control",
            baseline_identifier,
        ),
        canary_url=_controlled_url(
            finding.target,
            CONTROLLED_CANARY_PATH,
            canary_identifier,
        ),
        canary_identifier=canary_identifier,
        canary_content_marker=controlled_content_marker(
            "canary",
            canary_identifier,
        ),
        negative_url=_controlled_url(
            finding.target,
            CONTROLLED_CONTROL_PATH,
            negative_identifier,
        ),
        negative_identifier=negative_identifier,
        negative_content_marker=controlled_content_marker(
            "control",
            negative_identifier,
        ),
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
            endpoint_parts.port or (
                443 if endpoint_parts.scheme.lower() == "https" else 80
            ),
        )
        target_origin = (
            target_parts.scheme.lower(),
            target_parts.hostname,
            target_parts.port or (
                443 if target_parts.scheme.lower() == "https" else 80
            ),
        )
        if endpoint_origin != target_origin:
            raise ValueError("endpoint_origin_mismatch")
        return endpoint
    return urljoin(f"{finding.target.rstrip('/')}/", endpoint.lstrip("/"))


def _validate_context(finding: Finding, session: Any) -> Optional[str]:
    normalized_type = finding.vulnerability_type.lower().replace("-", "_")
    if normalized_type not in {"ssrf", "server_side_request_forgery"}:
        return "unexpected_vulnerability_type"
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
    if finding.parameter_location in {"form", "json", "cookie", "header"}:
        if finding.parameter_location not in finding.http_request_context:
            return "insufficient_original_request_context"
    if finding.parameter_location == "header":
        header_error = header_mutation_error(finding.parameter_name)
        if header_error is not None:
            return header_error
    if session is None:
        return "missing_scoped_http_session"
    if not callable(getattr(session, "request", None)):
        return "scoped_http_session_missing_request_interface"
    return None


def _request_kwargs(finding: Finding, value: str) -> Dict[str, Any]:
    location = finding.parameter_location or ""
    parameter_name = finding.parameter_name or ""
    original = deepcopy(finding.http_request_context.get(location, {}))
    if location == "header":
        existing_name = next(
            (
                name for name in original
                if name.lower() == parameter_name.lower()
            ),
            parameter_name,
        )
        original[existing_name] = value
    else:
        original[parameter_name] = value
    if location == "query":
        return {"params": original}
    if location == "form":
        return {"data": original}
    if location == "json":
        return {"json": original}
    if location == "cookie":
        return {"cookies": original}
    if location == "header":
        return {"headers": original}
    raise ValueError("unsupported_parameter_location")


def _observe_response(response: Any, *, attempts: int) -> _ResponseObservation:
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
    return _ResponseObservation(
        status=status,
        text=text,
        content_type=(
            content_type.lower()
            if isinstance(content_type, str)
            else str(content_type).lower()
        ),
        attempts=attempts,
    )


def _send_request(
    session: Any,
    *,
    method: str,
    url: str,
    kwargs: Optional[Dict[str, Any]] = None,
) -> _ResponseObservation:
    transient_errors = (httpx.TransportError, ConnectionError, TimeoutError)
    for attempt in range(1, _MAX_REQUEST_ATTEMPTS + 1):
        try:
            response = session.request(
                method,
                url,
                timeout=_REQUEST_TIMEOUT_SECONDS,
                **(kwargs or {}),
            )
            return _observe_response(response, attempts=attempt)
        except transient_errors as exc:
            if attempt >= _MAX_REQUEST_ATTEMPTS:
                raise _ProbeRequestFailure(attempt) from exc
            time.sleep(_RETRY_BACKOFF_SECONDS * (2 ** (attempt - 1)))
        except Exception as exc:
            raise _ProbeRequestFailure(attempt) from exc
    raise _ProbeRequestFailure(_MAX_REQUEST_ATTEMPTS)


def _send_sink_probe(
    finding: Finding,
    session: Any,
    *,
    endpoint_url: str,
    destination: str,
) -> _ResponseObservation:
    return _send_request(
        session,
        method=finding.http_method or "",
        url=endpoint_url,
        kwargs=_request_kwargs(finding, destination),
    )


def _waf_interference(observation: _ResponseObservation) -> bool:
    if observation.status in _WAF_STATUS_CODES:
        return True
    bounded = observation.text[:_ANALYSIS_CHARACTER_LIMIT]
    return any(pattern.search(bounded) for pattern in _WAF_TEXT_PATTERNS)


def _is_redirect(observation: _ResponseObservation) -> bool:
    return 300 <= observation.status < 400


def _observation_evidence(observation: _ResponseObservation) -> Dict[str, Any]:
    return {
        "response_status": observation.status,
        "response_content_type": observation.content_type,
        "response_size": len(observation.text.encode("utf-8")),
        "attempts": observation.attempts,
        "redirect_observed": _is_redirect(observation),
    }


def _url_transformation(destination: str, text: str) -> str:
    bounded = text[:_ANALYSIS_CHARACTER_LIMIT]
    if destination in bounded:
        return "raw_reflected"
    if html.escape(destination, quote=True) in bounded:
        return "html_entity_encoded"
    if quote(destination, safe="") in bounded:
        return "url_encoded"
    identifier = urlsplit(destination).query.partition("id=")[2]
    if identifier and identifier in bounded:
        return "partially_transformed"
    return "absent"


def _infrastructure_evidence(
    observation: _ResponseObservation,
    *,
    expected_marker_observed: bool,
    unexpected_marker_observed: bool,
) -> Dict[str, Any]:
    return {
        **_observation_evidence(observation),
        "expected_marker_observed": expected_marker_observed,
        "unexpected_marker_observed": unexpected_marker_observed,
        "waf_or_filter_interference": _waf_interference(observation),
    }


def _probe_evidence(
    observation: _ResponseObservation,
    *,
    destination: str,
    expected_marker: str,
    canary_marker: str,
) -> Dict[str, Any]:
    bounded = observation.text[:_ANALYSIS_CHARACTER_LIMIT]
    return {
        **_observation_evidence(observation),
        "input_url_reflected": destination in bounded,
        "url_transformation": _url_transformation(destination, bounded),
        "expected_content_marker_observed": expected_marker in bounded,
        "canary_content_marker_observed": canary_marker in bounded,
        "waf_or_filter_interference": _waf_interference(observation),
    }


def _base_evidence(
    finding: Finding,
    *,
    infrastructure: Dict[str, Dict[str, Any]],
    probes: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    waf_or_filter_interference = any(
        bool(item.get("waf_or_filter_interference"))
        for item in (*infrastructure.values(), *probes.values())
    )
    return {
        **_context_evidence(finding),
        "detection_method": "same_origin_controlled_canary_content_differential",
        "request_timeout_seconds": _REQUEST_TIMEOUT_SECONDS,
        "maximum_request_attempts": _MAX_REQUEST_ATTEMPTS,
        "analysis_character_limit": _ANALYSIS_CHARACTER_LIMIT,
        "destination_policy": "same_origin_controlled_http_only",
        "dangerous_destinations_probed": [],
        "waf_or_filter_interference": waf_or_filter_interference,
        "infrastructure": infrastructure,
        "probes": probes,
    }


def _infrastructure_failure_evidence(
    finding: Finding,
    infrastructure: Dict[str, Dict[str, Any]],
    reason: str,
) -> Dict[str, Any]:
    return _base_evidence(
        finding,
        infrastructure=infrastructure,
        probes={
            name: {
                "state": "skipped",
                "reason": reason,
            }
            for name in ("baseline", "controlled_canary", "negative_control")
        },
    )


def validate_generic_http_ssrf(
    finding: Finding,
    session: Any,
) -> ValidationResult:
    """Confirm only same-origin controlled canary content retrieval."""
    context_error = _validate_context(finding, session)
    if context_error is not None:
        return _manual_review(finding, context_error)
    try:
        endpoint_url = _resolve_endpoint_url(finding)
    except ValueError as exc:
        return _manual_review(finding, str(exc))

    plan = _canary_plan(finding)
    infrastructure: Dict[str, Dict[str, Any]] = {}
    try:
        canary_preflight = _send_request(
            session,
            method="GET",
            url=plan.canary_url,
        )
        control_preflight = _send_request(
            session,
            method="GET",
            url=plan.negative_url,
        )
    except _ProbeRequestFailure as exc:
        infrastructure["preflight_failure"] = {
            "state": "error",
            "attempts": exc.attempts,
        }
        return _manual_review(
            finding,
            "controlled_canary_unavailable",
            evidence=_infrastructure_failure_evidence(
                finding,
                infrastructure,
                "controlled_canary_unavailable",
            ),
            error="bounded controlled-canary request failed",
        )

    canary_ready = plan.canary_content_marker in canary_preflight.text[
        :_ANALYSIS_CHARACTER_LIMIT
    ]
    canary_unexpected = plan.negative_content_marker in canary_preflight.text[
        :_ANALYSIS_CHARACTER_LIMIT
    ]
    control_ready = plan.negative_content_marker in control_preflight.text[
        :_ANALYSIS_CHARACTER_LIMIT
    ]
    control_unexpected = plan.canary_content_marker in control_preflight.text[
        :_ANALYSIS_CHARACTER_LIMIT
    ]
    infrastructure = {
        "controlled_canary": _infrastructure_evidence(
            canary_preflight,
            expected_marker_observed=canary_ready,
            unexpected_marker_observed=canary_unexpected,
        ),
        "negative_control": _infrastructure_evidence(
            control_preflight,
            expected_marker_observed=control_ready,
            unexpected_marker_observed=control_unexpected,
        ),
    }
    if any(
        item["waf_or_filter_interference"]
        for item in infrastructure.values()
    ):
        return _manual_review(
            finding,
            "waf_or_filter_interference",
            evidence=_infrastructure_failure_evidence(
                finding,
                infrastructure,
                "filter_interference_detected",
            ),
        )
    if any(
        item["redirect_observed"] for item in infrastructure.values()
    ):
        return _manual_review(
            finding,
            "controlled_canary_redirect_ambiguity",
            evidence=_infrastructure_failure_evidence(
                finding,
                infrastructure,
                "controlled_canary_redirect_ambiguity",
            ),
        )
    if not all(
        200 <= item["response_status"] < 300
        for item in infrastructure.values()
    ) or not canary_ready or not control_ready or canary_unexpected or control_unexpected:
        return _manual_review(
            finding,
            "controlled_canary_unavailable",
            evidence=_infrastructure_failure_evidence(
                finding,
                infrastructure,
                "controlled_canary_unavailable",
            ),
        )

    probe_definitions = (
        (
            "baseline",
            plan.baseline_url,
            plan.baseline_content_marker,
        ),
        (
            "controlled_canary",
            plan.canary_url,
            plan.canary_content_marker,
        ),
        (
            "negative_control",
            plan.negative_url,
            plan.negative_content_marker,
        ),
    )
    observations: Dict[str, _ResponseObservation] = {}
    probes: Dict[str, Dict[str, Any]] = {}
    for name, destination, expected_marker in probe_definitions:
        try:
            observation = _send_sink_probe(
                finding,
                session,
                endpoint_url=endpoint_url,
                destination=destination,
            )
        except _ProbeRequestFailure as exc:
            probes[name] = {
                "state": "error",
                "attempts": exc.attempts,
                "reason": "probe_request_failed",
            }
            continue
        observations[name] = observation
        probes[name] = {
            "state": "completed",
            **_probe_evidence(
                observation,
                destination=destination,
                expected_marker=expected_marker,
                canary_marker=plan.canary_content_marker,
            ),
        }

    evidence = _base_evidence(
        finding,
        infrastructure=infrastructure,
        probes=probes,
    )
    if len(observations) != len(probe_definitions):
        return _manual_review(
            finding,
            "partial_probe_failure",
            evidence=evidence,
            error="one or more bounded SSRF probe requests failed",
        )
    if any(_waf_interference(item) for item in observations.values()):
        return _manual_review(
            finding,
            "waf_or_filter_interference",
            evidence=evidence,
        )
    if any(_is_redirect(item) for item in observations.values()):
        return _manual_review(
            finding,
            "redirect_ambiguity",
            evidence=evidence,
        )
    statuses = {item.status for item in observations.values()}
    if not all(200 <= status < 300 for status in statuses):
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

    baseline_text = observations["baseline"].text[:_ANALYSIS_CHARACTER_LIMIT]
    canary_text = observations["controlled_canary"].text[
        :_ANALYSIS_CHARACTER_LIMIT
    ]
    negative_text = observations["negative_control"].text[
        :_ANALYSIS_CHARACTER_LIMIT
    ]
    marker_collision = (
        plan.canary_content_marker in baseline_text
        or plan.negative_content_marker in baseline_text
    )
    evidence["baseline_marker_collision"] = marker_collision
    if marker_collision:
        return _manual_review(
            finding,
            "marker_preexisting_in_baseline",
            evidence=evidence,
        )

    canary_marker_observed = plan.canary_content_marker in canary_text
    canary_marker_in_negative = plan.canary_content_marker in negative_text
    negative_marker_observed = plan.negative_content_marker in negative_text
    baseline_control_observed = plan.baseline_content_marker in baseline_text
    evidence.update({
        "canary_url_reflected": plan.canary_url in canary_text,
        "canary_content_marker_observed": canary_marker_observed,
        "canary_marker_observed_in_negative_control": canary_marker_in_negative,
        "negative_control_marker_observed": negative_marker_observed,
        "baseline_control_marker_observed": baseline_control_observed,
        "reflection_only": (
            plan.canary_url in canary_text and not canary_marker_observed
        ),
    })
    if canary_marker_in_negative:
        return _manual_review(
            finding,
            "ambiguous_marker_attribution",
            evidence=evidence,
        )
    if canary_marker_observed:
        corroborating_controls = sum((
            baseline_control_observed,
            negative_marker_observed,
        ))
        confidence = min(0.99, round(0.93 + 0.02 * corroborating_controls, 2))
        evidence.update({
            "winning_signal": "unique_controlled_canary_content_retrieved",
            "corroborating_control_retrievals": corroborating_controls,
        })
        return _result(
            finding,
            status=ValidationStatus.CONFIRMED,
            confidence=confidence,
            decision="confirmed",
            reason="controlled_server_side_retrieval_confirmed",
            evidence=evidence,
        )
    if baseline_control_observed or negative_marker_observed:
        return _manual_review(
            finding,
            "ambiguous_control_retrieval",
            evidence=evidence,
        )
    reason = (
        "url_reflection_without_server_side_retrieval"
        if evidence["reflection_only"]
        else "controlled_canary_marker_not_observed"
    )
    return _result(
        finding,
        status=ValidationStatus.REJECTED,
        confidence=0.9,
        decision="rejected",
        reason=reason,
        evidence=evidence,
    )
