"""Context-aware inert reflected-XSS validation for normalized findings."""

from __future__ import annotations

import hashlib
import html
import re
import time
from copy import deepcopy
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any, Dict, Iterable, Optional
from urllib.parse import quote, quote_plus, urljoin, urlsplit

import httpx

from app.models.finding import Finding, STATUS_WEIGHT, ValidationStatus
from app.models.validation import ValidationResult


VALIDATOR_ID = "generic-http-reflected-xss"
VALIDATOR_NAME = "generic_http_reflected_xss"
VALIDATION_METHOD = "context-aware inert reflection analysis"

SUPPORTED_METHODS = frozenset({"GET", "POST", "PUT", "PATCH"})
SUPPORTED_PARAMETER_LOCATIONS = frozenset({
    "query", "form", "json", "cookie", "header",
})
SUPPORTED_REQUEST_SHAPES = frozenset(
    (method, location)
    for method in SUPPORTED_METHODS
    for location in SUPPORTED_PARAMETER_LOCATIONS
)

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
    re.compile(r"cloudflare ray id", re.I),
    re.compile(r"temporarily rate[ -]?limited", re.I),
)
_SAFE_REFLECTION_HEADERS = frozenset({
    "user-agent", "referer", "x-forwarded-for",
})
_SENSITIVE_HEADERS = frozenset({
    "authorization", "proxy-authorization", "cookie", "set-cookie",
    "x-api-key", "api-key", "x-auth-token", "x-csrf-token", "x-xsrf-token",
})
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_HTML_LIKE_CONTENT_TYPES = frozenset({"text/html", "application/xhtml+xml"})
_JAVASCRIPT_STRING_STATES = frozenset({
    "javascript_single_quoted_string",
    "javascript_double_quoted_string",
    "javascript_template_string",
})
_STRONG_SIGNAL_CONFIDENCE = {
    "controlled_inert_html_element_created": 0.90,
    "controlled_inert_attribute_created": 0.90,
    "controlled_comment_breakout_element_created": 0.91,
    "controlled_javascript_string_boundary_crossed": 0.92,
}
_CORROBORATION_BONUS = 0.02


@dataclass(frozen=True)
class _Probe:
    name: str
    marker: str
    value: str


@dataclass(frozen=True)
class _ResponseObservation:
    status: int
    text: str
    content_type: str
    attempts: int


@dataclass(frozen=True)
class _HtmlAnalysis:
    contexts: tuple[str, ...]
    attribute_names: tuple[str, ...]
    controlled_element: bool
    controlled_attribute: bool
    javascript_states: tuple[str, ...]


class _ProbeRequestFailure(RuntimeError):
    def __init__(self, attempts: int) -> None:
        super().__init__("bounded probe request failed")
        self.attempts = attempts


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


def _probe_plan(finding: Finding) -> tuple[str, tuple[_Probe, ...]]:
    root = _finding_marker_root(finding)
    control = f"orx-control-{root}"
    element_marker = f"orx-element-{root}"
    attribute_marker = f"orx-attribute-{root}"
    comment_marker = f"orx-comment-{root}"
    script_marker = f"orx-script-{root}"
    return control, (
        _Probe(
            "inert_element",
            element_marker,
            f'<or-reflection data-or-marker="{element_marker}" '
            'data-or-probe="element"></or-reflection>',
        ),
        _Probe(
            "attribute_boundary",
            attribute_marker,
            f'" data-or-marker="{attribute_marker}" '
            'data-or-probe="attribute',
        ),
        _Probe(
            "html_comment_boundary",
            comment_marker,
            f'--><or-reflection data-or-marker="{comment_marker}" '
            'data-or-probe="comment"></or-reflection><!--',
        ),
        _Probe(
            "javascript_string_boundary",
            script_marker,
            f'";/*{script_marker}*/"',
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
    if normalized_type not in {
        "cross_site_scripting",
        "reflected_cross_site_scripting",
        "reflected_xss",
        "xss",
    }:
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
        header_name = finding.parameter_name.strip().lower()
        if header_name in _SENSITIVE_HEADERS:
            return "sensitive_header_not_allowed"
        if (
            header_name not in _SAFE_REFLECTION_HEADERS
            or not _HEADER_NAME_RE.fullmatch(finding.parameter_name.strip())
        ):
            return "unsupported_header_parameter"
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
    if not isinstance(content_type, str):
        content_type = str(content_type)
    return _ResponseObservation(
        status=status,
        text=text,
        content_type=content_type.lower(),
        attempts=attempts,
    )


def _send_probe(
    finding: Finding,
    session: Any,
    *,
    url: str,
    value: str,
) -> _ResponseObservation:
    kwargs = _request_kwargs(finding, value)
    transient_errors = (httpx.TransportError, ConnectionError, TimeoutError)
    for attempt in range(1, _MAX_REQUEST_ATTEMPTS + 1):
        try:
            response = session.request(
                finding.http_method or "",
                url,
                timeout=_REQUEST_TIMEOUT_SECONDS,
                **kwargs,
            )
            return _observe_response(response, attempts=attempt)
        except transient_errors as exc:
            if attempt >= _MAX_REQUEST_ATTEMPTS:
                raise _ProbeRequestFailure(attempt) from exc
            time.sleep(_RETRY_BACKOFF_SECONDS * (2 ** (attempt - 1)))
        except Exception as exc:
            raise _ProbeRequestFailure(attempt) from exc
    raise _ProbeRequestFailure(_MAX_REQUEST_ATTEMPTS)


def _content_type_name(value: str) -> str:
    return value.split(";", 1)[0].strip().lower()


def _is_html_like(content_type: str) -> bool:
    return _content_type_name(content_type) in _HTML_LIKE_CONTENT_TYPES


def _javascript_state_at(source: str, marker_index: int) -> str:
    state = "javascript_code"
    escaped = False
    index = 0
    while index < marker_index:
        char = source[index]
        following = source[index + 1] if index + 1 < marker_index else ""
        if state in _JAVASCRIPT_STRING_STATES:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif (
                (state == "javascript_single_quoted_string" and char == "'")
                or (state == "javascript_double_quoted_string" and char == '"')
                or (state == "javascript_template_string" and char == "`")
            ):
                state = "javascript_code"
        elif state == "javascript_block_comment":
            if char == "*" and following == "/":
                state = "javascript_code"
                index += 1
        elif state == "javascript_line_comment":
            if char in "\r\n":
                state = "javascript_code"
        elif char == "/" and following == "*":
            state = "javascript_block_comment"
            index += 1
        elif char == "/" and following == "/":
            state = "javascript_line_comment"
            index += 1
        elif char == "'":
            state = "javascript_single_quoted_string"
        elif char == '"':
            state = "javascript_double_quoted_string"
        elif char == "`":
            state = "javascript_template_string"
        index += 1
    return state


class _ReflectionContextParser(HTMLParser):
    def __init__(self, marker: str) -> None:
        super().__init__(convert_charrefs=True)
        self.marker = marker
        self.stack: list[str] = []
        self.contexts: list[str] = []
        self.attribute_names: list[str] = []
        self.controlled_element = False
        self.controlled_attribute = False
        self.javascript_states: list[str] = []

    def _record(self, context: str) -> None:
        if context not in self.contexts:
            self.contexts.append(context)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        normalized_tag = tag.lower()
        attributes = {
            name.lower(): value or "" for name, value in attrs
        }
        if attributes.get("data-or-marker") == self.marker:
            if (
                normalized_tag == "or-reflection"
                and attributes.get("data-or-probe") in {"element", "comment"}
            ):
                self.controlled_element = True
            if (
                normalized_tag != "or-reflection"
                and attributes.get("data-or-probe") == "attribute"
            ):
                self.controlled_attribute = True
        for name, value in attrs:
            if value and self.marker in value:
                self._record("html_attribute_value")
                if name.lower() not in self.attribute_names:
                    self.attribute_names.append(name.lower())
        self.stack.append(normalized_tag)

    def handle_startendtag(
        self,
        tag: str,
        attrs: list[tuple[str, Optional[str]]],
    ) -> None:
        self.handle_starttag(tag, attrs)
        if self.stack:
            self.stack.pop()

    def handle_endtag(self, tag: str) -> None:
        normalized_tag = tag.lower()
        if normalized_tag in self.stack:
            reverse_index = self.stack[::-1].index(normalized_tag)
            del self.stack[len(self.stack) - reverse_index - 1:]

    def handle_data(self, data: str) -> None:
        if self.marker not in data:
            return
        current = self.stack[-1] if self.stack else None
        if current == "script":
            self._record("script_block")
            start = 0
            while True:
                marker_index = data.find(self.marker, start)
                if marker_index < 0:
                    break
                state = _javascript_state_at(data, marker_index)
                if state not in self.javascript_states:
                    self.javascript_states.append(state)
                start = marker_index + len(self.marker)
        elif current == "style":
            self._record("style_block")
        else:
            self._record("html_text_node")

    def handle_comment(self, data: str) -> None:
        if self.marker in data:
            self._record("html_comment")


def _analyze_html(text: str, marker: str) -> _HtmlAnalysis:
    bounded = text[:_ANALYSIS_CHARACTER_LIMIT]
    parser = _ReflectionContextParser(marker)
    try:
        parser.feed(bounded)
        parser.close()
    except Exception:
        return _HtmlAnalysis(
            contexts=("malformed_or_unknown",),
            attribute_names=(),
            controlled_element=False,
            controlled_attribute=False,
            javascript_states=(),
        )
    contexts = list(parser.contexts)
    if marker in bounded and not contexts:
        contexts.append("malformed_or_unknown")
    return _HtmlAnalysis(
        contexts=tuple(contexts),
        attribute_names=tuple(parser.attribute_names),
        controlled_element=parser.controlled_element,
        controlled_attribute=parser.controlled_attribute,
        javascript_states=tuple(parser.javascript_states),
    )


def _encoding_fingerprint(probe: _Probe, text: str) -> str:
    bounded = text[:_ANALYSIS_CHARACTER_LIMIT]
    if probe.value in bounded:
        return "raw_unencoded"
    escaped = html.escape(probe.value, quote=True)
    if escaped in bounded:
        return "html_entity_encoded"
    if quote(probe.value, safe="") in bounded or quote_plus(
        probe.value,
        safe="",
    ) in bounded:
        return "url_encoded"
    if probe.marker not in bounded:
        return "absent"
    marker_index = bounded.find(probe.marker)
    window = bounded[max(0, marker_index - 300):marker_index + 300]
    if re.search(r"&(?:lt|gt|#0*(?:60|62)|#x0*3[ce]);", window, re.I):
        return "html_entity_encoded"
    if re.search(r"&(?:quot|apos|#0*3[49]|#x0*2[27]);", window, re.I):
        return "quote_encoded"
    syntax = set(probe.value) - set(probe.marker)
    if syntax and not any(character in window for character in syntax):
        return "stripped"
    return "partially_encoded_or_transformed"


def _waf_interference(observation: _ResponseObservation) -> bool:
    if observation.status in _WAF_STATUS_CODES:
        return True
    bounded = observation.text[:_ANALYSIS_CHARACTER_LIMIT]
    return any(pattern.search(bounded) for pattern in _WAF_TEXT_PATTERNS)


def _primary_context(contexts: Iterable[str], *, html_like: bool) -> str:
    if not html_like:
        return "non_html_response"
    priority = (
        "script_block",
        "style_block",
        "html_comment",
        "html_attribute_value",
        "html_text_node",
        "malformed_or_unknown",
    )
    available = set(contexts)
    return next((item for item in priority if item in available), "not_reflected")


def _strong_signal(
    probe: _Probe,
    analysis: _HtmlAnalysis,
    baseline_analysis: _HtmlAnalysis,
) -> Optional[str]:
    if probe.name == "inert_element" and analysis.controlled_element:
        return "controlled_inert_html_element_created"
    if (
        probe.name == "attribute_boundary"
        and analysis.controlled_attribute
        and "html_attribute_value" in baseline_analysis.contexts
    ):
        return "controlled_inert_attribute_created"
    if (
        probe.name == "html_comment_boundary"
        and analysis.controlled_element
        and "html_comment" in baseline_analysis.contexts
    ):
        return "controlled_comment_breakout_element_created"
    if (
        probe.name == "javascript_string_boundary"
        and any(
            state in _JAVASCRIPT_STRING_STATES
            for state in baseline_analysis.javascript_states
        )
        and "javascript_block_comment" in analysis.javascript_states
    ):
        return "controlled_javascript_string_boundary_crossed"
    return None


def _baseline_evidence(
    observation: _ResponseObservation,
    analysis: _HtmlAnalysis,
    *,
    control_reflected: bool,
    marker_collision: bool,
) -> Dict[str, Any]:
    return {
        "response_status": observation.status,
        "response_content_type": observation.content_type,
        "response_size": len(observation.text.encode("utf-8")),
        "attempts": observation.attempts,
        "control_marker_reflected": control_reflected,
        "reflection_context": _primary_context(
            analysis.contexts,
            html_like=_is_html_like(observation.content_type),
        ),
        "javascript_states": list(analysis.javascript_states),
        "probe_marker_collision": marker_collision,
    }


def _skipped_probe_evidence(reason: str) -> Dict[str, Any]:
    return {
        "state": "skipped",
        "verdict": "inconclusive",
        "reason": reason,
        "reliability": "not_evaluated",
    }


def _base_evidence(
    finding: Finding,
    *,
    baseline: Dict[str, Any],
    probes: Dict[str, Dict[str, Any]],
    reflection_observed: bool,
    strong_signals: list[Dict[str, str]],
    waf_or_filter_interference: bool,
) -> Dict[str, Any]:
    return {
        **_context_evidence(finding),
        "request_timeout_seconds": _REQUEST_TIMEOUT_SECONDS,
        "maximum_request_attempts": _MAX_REQUEST_ATTEMPTS,
        "analysis_character_limit": _ANALYSIS_CHARACTER_LIMIT,
        "baseline": baseline,
        "waf_or_filter_interference": waf_or_filter_interference,
        "reflection_observed": reflection_observed,
        "strong_structural_signals": strong_signals,
        "probes": probes,
    }


def _confirmed_confidence(strong_signals: list[Dict[str, str]]) -> float:
    strongest = max(
        _STRONG_SIGNAL_CONFIDENCE[item["signal"]]
        for item in strong_signals
    )
    bonus = _CORROBORATION_BONUS * max(0, len(strong_signals) - 1)
    return min(0.99, round(strongest + bonus, 2))


def validate_generic_reflected_xss(
    finding: Finding,
    session: Any,
) -> ValidationResult:
    """Aggregate bounded inert probes without executing browser-side code."""
    context_error = _validate_context(finding, session)
    if context_error is not None:
        return _manual_review(finding, context_error)

    try:
        url = _resolve_endpoint_url(finding)
    except ValueError as exc:
        return _manual_review(finding, str(exc))

    control_marker, probe_plan = _probe_plan(finding)
    try:
        baseline = _send_probe(
            finding,
            session,
            url=url,
            value=control_marker,
        )
    except _ProbeRequestFailure as exc:
        return _manual_review(
            finding,
            "baseline_request_failed",
            evidence={
                "request_timeout_seconds": _REQUEST_TIMEOUT_SECONDS,
                "maximum_request_attempts": _MAX_REQUEST_ATTEMPTS,
                "baseline": {
                    "state": "error",
                    "attempts": exc.attempts,
                },
                "probes": {
                    probe.name: _skipped_probe_evidence(
                        "baseline_request_failed"
                    )
                    for probe in probe_plan
                },
            },
            error="bounded HTTP request failed",
        )

    html_like_baseline = _is_html_like(baseline.content_type)
    baseline_analysis = (
        _analyze_html(baseline.text, control_marker)
        if html_like_baseline
        else _HtmlAnalysis((), (), False, False, ())
    )
    marker_collision = any(
        probe.marker in baseline.text for probe in probe_plan
    )
    baseline_evidence = _baseline_evidence(
        baseline,
        baseline_analysis,
        control_reflected=control_marker in baseline.text,
        marker_collision=marker_collision,
    )
    empty_probes = {
        probe.name: _skipped_probe_evidence("baseline_not_usable")
        for probe in probe_plan
    }
    if _waf_interference(baseline):
        return _manual_review(
            finding,
            "waf_or_filter_interference",
            evidence=_base_evidence(
                finding,
                baseline=baseline_evidence,
                probes=empty_probes,
                reflection_observed=control_marker in baseline.text,
                strong_signals=[],
                waf_or_filter_interference=True,
            ),
        )
    if not 200 <= baseline.status < 300:
        return _manual_review(
            finding,
            "non_success_baseline_status",
            evidence=_base_evidence(
                finding,
                baseline=baseline_evidence,
                probes=empty_probes,
                reflection_observed=control_marker in baseline.text,
                strong_signals=[],
                waf_or_filter_interference=False,
            ),
        )
    if marker_collision:
        return _manual_review(
            finding,
            "marker_preexisting_in_baseline",
            evidence=_base_evidence(
                finding,
                baseline=baseline_evidence,
                probes=empty_probes,
                reflection_observed=control_marker in baseline.text,
                strong_signals=[],
                waf_or_filter_interference=False,
            ),
        )

    probes_evidence: Dict[str, Dict[str, Any]] = {}
    strong_signals: list[Dict[str, str]] = []
    reflection_observed = False
    waf_detected = False
    partial_failure = False
    inconsistent_status = False
    ambiguous_context = False
    all_non_html = True

    for probe in probe_plan:
        try:
            observation = _send_probe(
                finding,
                session,
                url=url,
                value=probe.value,
            )
        except _ProbeRequestFailure as exc:
            partial_failure = True
            probes_evidence[probe.name] = {
                "state": "error",
                "attempts": exc.attempts,
                "marker_reflected": False,
                "reflection_context": "not_evaluated",
                "encoding_fingerprint": "unknown",
                "structural_boundary_changed": False,
                "structural_signal": None,
                "verdict": "inconclusive",
                "reason": "probe_request_failed",
                "reliability": "not_evaluated",
            }
            continue

        html_like = _is_html_like(observation.content_type)
        all_non_html = all_non_html and not html_like
        marker_reflected = probe.marker in observation.text[
            :_ANALYSIS_CHARACTER_LIMIT
        ]
        reflection_observed = reflection_observed or marker_reflected
        analysis = (
            _analyze_html(observation.text, probe.marker)
            if html_like
            else _HtmlAnalysis((), (), False, False, ())
        )
        signal = _strong_signal(probe, analysis, baseline_analysis)
        if signal:
            strong_signals.append({
                "probe_name": probe.name,
                "signal": signal,
                "reflection_context": _primary_context(
                    analysis.contexts,
                    html_like=html_like,
                ),
            })
        fingerprint = _encoding_fingerprint(probe, observation.text)
        probe_waf = _waf_interference(observation)
        waf_detected = waf_detected or probe_waf
        status_consistent = observation.status == baseline.status
        inconsistent_status = inconsistent_status or not status_consistent
        context = _primary_context(analysis.contexts, html_like=html_like)
        safely_quoted_javascript = (
            context == "script_block"
            and bool(analysis.javascript_states)
            and all(
                state in _JAVASCRIPT_STRING_STATES
                for state in analysis.javascript_states
            )
        )
        probe_ambiguous = (
            marker_reflected
            and signal is None
            and not safely_quoted_javascript
            and context in {
                "script_block",
                "style_block",
                "html_comment",
                "malformed_or_unknown",
            }
        )
        if probe_ambiguous:
            ambiguous_context = True
        if probe_waf:
            verdict = "inconclusive"
            reason = "filter_interference"
            reliability = "interfered"
        elif signal:
            verdict = "strong_structural_evidence"
            reason = signal
            reliability = "strong"
        elif not marker_reflected:
            verdict = "not_reflected"
            reason = "marker_not_reflected"
            reliability = "complete"
        elif not html_like:
            verdict = "not_xss_context"
            reason = "non_html_reflection"
            reliability = "complete"
        elif probe_ambiguous:
            verdict = "inconclusive"
            reason = "context_requires_manual_review"
            reliability = "ambiguous"
        else:
            verdict = "sanitized_or_non_structural"
            reason = "no_structural_boundary_control"
            reliability = "complete"
        probes_evidence[probe.name] = {
            "state": "completed",
            "response_status": observation.status,
            "response_content_type": observation.content_type,
            "response_size": len(observation.text.encode("utf-8")),
            "attempts": observation.attempts,
            "marker_reflected": marker_reflected,
            "reflection_context": context,
            "reflection_contexts": list(analysis.contexts),
            "attribute_names": list(analysis.attribute_names),
            "javascript_states": list(analysis.javascript_states),
            "encoding_fingerprint": fingerprint,
            "structural_boundary_changed": signal is not None,
            "structural_signal": signal,
            "verdict": verdict,
            "reason": reason,
            "reliability": reliability,
        }

    evidence = _base_evidence(
        finding,
        baseline=baseline_evidence,
        probes=probes_evidence,
        reflection_observed=reflection_observed,
        strong_signals=strong_signals,
        waf_or_filter_interference=waf_detected,
    )
    if waf_detected:
        return _manual_review(
            finding,
            "waf_or_filter_interference",
            evidence=evidence,
        )
    if partial_failure:
        return _manual_review(
            finding,
            "partial_probe_failure",
            evidence=evidence,
            error="one or more bounded HTTP requests failed",
        )
    if inconsistent_status:
        return _manual_review(
            finding,
            "inconsistent_http_status",
            evidence=evidence,
        )
    if strong_signals:
        return _result(
            finding,
            status=ValidationStatus.CONFIRMED,
            confidence=_confirmed_confidence(strong_signals),
            decision="confirmed",
            reason="controlled_structural_breakout_confirmed",
            evidence=evidence,
        )
    if ambiguous_context:
        return _manual_review(
            finding,
            "ambiguous_reflection_context",
            evidence=evidence,
        )
    if reflection_observed and all_non_html:
        reason = "non_html_reflection_only"
    elif reflection_observed:
        reason = "safe_encoding_or_sanitization_observed"
    else:
        reason = "no_probe_reflection"
    return _result(
        finding,
        status=ValidationStatus.REJECTED,
        confidence=0.9,
        decision="rejected",
        reason=reason,
        evidence=evidence,
    )
