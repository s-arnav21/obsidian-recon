"""Comprehensive tests for context-aware inert reflected-XSS validation."""

from __future__ import annotations

import html
import json
import re
import unittest
from dataclasses import replace
from pathlib import Path
from urllib.parse import quote

import httpx

from app.models.finding import ValidationStatus
from app.scanning.normalizer import HttpScannerRecord, normalize_reflected_xss_record
from app.validation.dispatcher import dispatch
from app.validation.xss import _probe_plan


class FakeResponse:
    def __init__(self, text, status_code=200, content_type="text/html"):
        self.text = text
        self.status_code = status_code
        self.headers = {"content-type": content_type}


def _marker(value: str) -> str:
    match = re.search(r"orx-[a-z-]+-[0-9a-f]{20}", value)
    return match.group(0) if match else ""


class ContextSession:
    def __init__(self, parameter_name, renderer, *, transient_failures=0):
        self.parameter_name = parameter_name
        self.renderer = renderer
        self.transient_failures = transient_failures
        self.calls = []

    def request(self, method, url, timeout=None, **kwargs):
        self.calls.append({
            "method": method,
            "url": url,
            "timeout": timeout,
            "kwargs": kwargs,
        })
        if self.transient_failures:
            self.transient_failures -= 1
            raise httpx.ReadTimeout("synthetic transient failure")
        values = next(
            value for key, value in kwargs.items()
            if key in {"params", "data", "json", "cookies", "headers"}
        )
        matching_name = next(
            name for name in values
            if name.lower() == self.parameter_name.lower()
        )
        return self.renderer(values[matching_name], len(self.calls))


def make_record(**overrides):
    values = {
        "record_id": "finding-advanced-xss",
        "scan_id": "scan-advanced-xss",
        "asset_id": "asset-advanced-xss",
        "target": "http://127.0.0.1:8091",
        "endpoint": "/reflect",
        "http_method": "GET",
        "parameter_name": "q",
        "parameter_location": "query",
        "scanner_name": "synthetic_http_scanner",
        "scanner_template_id": "synthetic-reflected-xss-check",
        "vulnerability_type": "reflected_xss",
        "severity": "medium",
        "evidence": {"candidate_parameter": True},
        "evidence_refs": ["scanner://synthetic/xss-advanced"],
    }
    values.update(overrides)
    return HttpScannerRecord(**values)


def make_finding(**overrides):
    return normalize_reflected_xss_record(make_record(**overrides))


def dispatch_with(renderer, *, finding=None, transient_failures=0):
    finding = finding or make_finding()
    session = ContextSession(
        finding.parameter_name,
        renderer,
        transient_failures=transient_failures,
    )
    return dispatch(finding, session=session), session


def raw_text(value, _call):
    return FakeResponse(f"<html><body><p>{value}</p></body></html>")


def safe_text(value, _call):
    sanitized = re.sub(r"[<>'\"/*;=]", "", value)
    return FakeResponse(f"<html><body><p>{sanitized}</p></body></html>")


class TestAdvancedReflectedXssStructure(unittest.TestCase):
    def test_no_reflection_is_rejected(self):
        result, _ = dispatch_with(
            lambda _value, _call: FakeResponse("<html><body>static</body></html>")
        )

        self.assertEqual(result.status, ValidationStatus.REJECTED)
        self.assertEqual(result.evidence["reason"], "no_probe_reflection")

    def test_html_escaped_reflection_is_rejected(self):
        result, _ = dispatch_with(
            lambda value, _call: FakeResponse(html.escape(value, quote=True))
        )

        self.assertEqual(result.status, ValidationStatus.REJECTED)
        self.assertEqual(
            result.evidence["probes"]["inert_element"]["encoding_fingerprint"],
            "html_entity_encoded",
        )

    def test_ordinary_text_reflection_does_not_automatically_confirm(self):
        result, _ = dispatch_with(safe_text)

        self.assertEqual(result.status, ValidationStatus.REJECTED)
        self.assertTrue(result.evidence["reflection_observed"])
        self.assertEqual(result.evidence["strong_structural_signals"], [])

    def test_inert_element_creation_confirms(self):
        result, _ = dispatch_with(raw_text)

        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        self.assertEqual(result.confidence, 0.90)
        self.assertIn(
            "controlled_inert_html_element_created",
            [item["signal"] for item in result.evidence["strong_structural_signals"]],
        )

    def test_attribute_boundary_creation_confirms(self):
        result, _ = dispatch_with(
            lambda value, _call: FakeResponse(
                f'<html><body><div data-value="{value}"></div></body></html>'
            )
        )

        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        probe = result.evidence["probes"]["attribute_boundary"]
        self.assertEqual(
            probe["structural_signal"],
            "controlled_inert_attribute_created",
        )
        self.assertIn("data-or-marker", probe["attribute_names"])

    def test_safely_quoted_attribute_is_not_confirmed(self):
        result, _ = dispatch_with(
            lambda value, _call: FakeResponse(
                f'<html><body><div data-value="{html.escape(value, quote=True)}">'
                "</div></body></html>"
            )
        )

        self.assertEqual(result.status, ValidationStatus.REJECTED)
        self.assertFalse(
            result.evidence["probes"]["attribute_boundary"]
            ["structural_boundary_changed"]
        )

    def test_comment_reflection_without_breakout_is_manual_review(self):
        result, _ = dispatch_with(
            lambda value, _call: FakeResponse(f"<!--{_marker(value)}-->")
        )

        self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
        self.assertEqual(result.evidence["reason"], "ambiguous_reflection_context")

    def test_comment_breakout_creates_controlled_element(self):
        result, _ = dispatch_with(
            lambda value, _call: FakeResponse(f"<!--{value}-->")
        )

        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        self.assertEqual(
            result.evidence["probes"]["html_comment_boundary"]["structural_signal"],
            "controlled_comment_breakout_element_created",
        )

    def test_marker_merely_in_script_code_is_manual_review(self):
        result, _ = dispatch_with(
            lambda value, _call: FakeResponse(
                f"<script>window.reflection = ({_marker(value)});</script>"
            )
        )

        self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
        self.assertEqual(result.evidence["reason"], "ambiguous_reflection_context")

    def test_safely_serialized_javascript_string_is_rejected(self):
        result, _ = dispatch_with(
            lambda value, _call: FakeResponse(
                f"<script>const term = {json.dumps(value)};</script>"
            )
        )

        self.assertEqual(result.status, ValidationStatus.REJECTED)
        self.assertEqual(result.evidence["strong_structural_signals"], [])

    def test_static_javascript_string_boundary_signal_confirms(self):
        result, _ = dispatch_with(
            lambda value, _call: FakeResponse(
                f'<script>const term = "{value}";</script>'
            )
        )

        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        self.assertEqual(
            result.evidence["probes"]["javascript_string_boundary"]
            ["structural_signal"],
            "controlled_javascript_string_boundary_crossed",
        )

    def test_style_only_reflection_is_manual_review(self):
        result, _ = dispatch_with(
            lambda value, _call: FakeResponse(
                f"<style>.sample::after{{content:'{value}'}}</style>"
            )
        )

        self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)


class TestAdvancedReflectedXssEncodingAndContentType(unittest.TestCase):
    def test_quote_encoding_is_classified(self):
        def render(value, _call):
            encoded = value.replace('"', "&quot;").replace("'", "&#39;")
            return FakeResponse(f"<p>{encoded}</p>")

        result, _ = dispatch_with(render)

        fingerprints = {
            probe["encoding_fingerprint"]
            for probe in result.evidence["probes"].values()
        }
        self.assertIn("quote_encoded", fingerprints)
        self.assertNotEqual(result.status, ValidationStatus.CONFIRMED)

    def test_numeric_html_entities_are_classified(self):
        def render(value, _call):
            encoded = (
                value.replace("<", "&#60;")
                .replace(">", "&#62;")
                .replace('"', "&#34;")
                .replace("'", "&#39;")
            )
            return FakeResponse(f"<p>{encoded}</p>")

        result, _ = dispatch_with(render)

        self.assertEqual(result.status, ValidationStatus.REJECTED)
        self.assertEqual(
            result.evidence["probes"]["inert_element"]["encoding_fingerprint"],
            "html_entity_encoded",
        )

    def test_url_encoding_is_classified(self):
        result, _ = dispatch_with(
            lambda value, _call: FakeResponse(f"<p>{quote(value, safe='')}</p>")
        )

        self.assertEqual(result.status, ValidationStatus.REJECTED)
        self.assertEqual(
            result.evidence["probes"]["inert_element"]["encoding_fingerprint"],
            "url_encoded",
        )

    def test_stripped_syntax_is_classified_conservatively(self):
        result, _ = dispatch_with(safe_text)

        fingerprints = {
            probe["encoding_fingerprint"]
            for probe in result.evidence["probes"].values()
        }
        self.assertTrue(fingerprints & {"stripped", "partially_encoded_or_transformed"})
        self.assertEqual(result.status, ValidationStatus.REJECTED)

    def test_partial_transformation_does_not_confirm(self):
        result, _ = dispatch_with(
            lambda value, _call: FakeResponse(
                f"<p>{value.replace('<', '&lt;').replace('>', '&gt;')}</p>"
            )
        )

        self.assertNotEqual(result.status, ValidationStatus.CONFIRMED)

    def test_json_reflection_is_rejected_as_non_html(self):
        result, _ = dispatch_with(
            lambda value, _call: FakeResponse(
                json.dumps({"query": value}),
                content_type="application/json",
            )
        )

        self.assertEqual(result.status, ValidationStatus.REJECTED)
        self.assertEqual(result.evidence["reason"], "non_html_reflection_only")
        self.assertEqual(
            result.evidence["probes"]["inert_element"]["reflection_context"],
            "non_html_response",
        )

    def test_plain_text_reflection_is_not_confirmed(self):
        result, _ = dispatch_with(
            lambda value, _call: FakeResponse(value, content_type="text/plain")
        )

        self.assertEqual(result.status, ValidationStatus.REJECTED)

    def test_xhtml_is_analyzed_as_html_like(self):
        result, _ = dispatch_with(
            lambda value, _call: FakeResponse(
                f"<html><body>{value}</body></html>",
                content_type="application/xhtml+xml; charset=utf-8",
            )
        )

        self.assertEqual(result.status, ValidationStatus.CONFIRMED)


class TestAdvancedReflectedXssRequestsAndSafety(unittest.TestCase):
    def test_all_supported_methods_and_locations_preserve_context(self):
        for method in ("GET", "POST", "PUT", "PATCH"):
            for location in ("query", "form", "json", "cookie", "header"):
                with self.subTest(method=method, location=location):
                    parameter = "User-Agent" if location == "header" else "q"
                    context = {location: {"preserved": "keep", parameter: "old"}}
                    finding = make_finding(
                        http_method=method,
                        parameter_name=parameter,
                        parameter_location=location,
                        http_request_context=context,
                    )
                    result, session = dispatch_with(raw_text, finding=finding)

                    self.assertEqual(result.status, ValidationStatus.CONFIRMED)
                    self.assertEqual(len(session.calls), 5)
                    for call in session.calls:
                        values = next(iter(call["kwargs"].values()))
                        self.assertEqual(values["preserved"], "keep")
                        self.assertNotEqual(values[parameter], "old")
                        self.assertEqual(call["timeout"], 5.0)

    def test_body_cookie_and_header_context_is_required(self):
        for location in ("form", "json", "cookie", "header"):
            with self.subTest(location=location):
                parameter = "User-Agent" if location == "header" else "q"
                finding = make_finding(
                    parameter_name=parameter,
                    parameter_location=location,
                )
                result, session = dispatch_with(raw_text, finding=finding)

                self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
                self.assertEqual(
                    result.evidence["reason"],
                    "insufficient_original_request_context",
                )
                self.assertEqual(session.calls, [])

    def test_sensitive_header_is_not_mutated(self):
        finding = make_finding(
            parameter_name="Authorization",
            parameter_location="header",
            http_request_context={"header": {"Authorization": "secret-token"}},
        )
        result, session = dispatch_with(raw_text, finding=finding)

        self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
        self.assertEqual(result.evidence["reason"], "sensitive_header_not_allowed")
        self.assertEqual(session.calls, [])
        self.assertNotIn("secret-token", json.dumps(result.to_dict()))

    def test_unapproved_header_is_not_mutated(self):
        finding = make_finding(
            parameter_name="X-Custom-Unsafe",
            parameter_location="header",
            http_request_context={"header": {"X-Custom-Unsafe": "old"}},
        )
        result, session = dispatch_with(raw_text, finding=finding)

        self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
        self.assertEqual(result.evidence["reason"], "unsupported_header_parameter")
        self.assertEqual(session.calls, [])

    def test_endpoint_origin_mismatch_is_handled_without_request(self):
        finding = replace(
            make_finding(),
            endpoint="http://127.0.0.1:9999/reflect",
        )
        result, session = dispatch_with(raw_text, finding=finding)

        self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
        self.assertEqual(result.evidence["reason"], "endpoint_origin_mismatch")
        self.assertEqual(session.calls, [])

    def test_transient_failure_is_retried_then_succeeds(self):
        result, session = dispatch_with(raw_text, transient_failures=1)

        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        self.assertEqual(len(session.calls), 6)
        self.assertEqual(result.evidence["baseline"]["attempts"], 2)

    def test_repeated_transport_failure_is_bounded(self):
        result, session = dispatch_with(raw_text, transient_failures=20)

        self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
        self.assertEqual(result.evidence["reason"], "baseline_request_failed")
        self.assertEqual(len(session.calls), 3)
        self.assertNotIn("synthetic transient failure", json.dumps(result.to_dict()))

    def test_waf_interference_is_manual_review(self):
        def render(value, _call):
            if value.startswith("orx-control-"):
                return FakeResponse(f"<p>{value}</p>")
            return FakeResponse("request blocked by security policy", status_code=403)

        result, _ = dispatch_with(render)

        self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
        self.assertTrue(result.evidence["waf_or_filter_interference"])
        self.assertNotEqual(result.status, ValidationStatus.REJECTED)

    def test_marker_collision_is_manual_review(self):
        def render(value, _call):
            if value.startswith("orx-control-"):
                collision = value.replace("orx-control-", "orx-element-")
                return FakeResponse(f"<p>{value}{collision}</p>")
            return FakeResponse(f"<p>{value}</p>")

        result, session = dispatch_with(render)

        self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
        self.assertEqual(result.evidence["reason"], "marker_preexisting_in_baseline")
        self.assertEqual(len(session.calls), 1)

    def test_markers_are_deterministic_and_finding_scoped(self):
        first = make_finding()
        second = make_finding(record_id="finding-other-xss")

        self.assertEqual(_probe_plan(first), _probe_plan(first))
        self.assertNotEqual(_probe_plan(first), _probe_plan(second))

    def test_evidence_contains_no_response_body_or_transient_secret(self):
        secret = "not-for-evidence-SECRET-123"
        finding = make_finding(
            parameter_name="User-Agent",
            parameter_location="header",
            http_request_context={
                "header": {
                    "User-Agent": "old",
                    "Authorization": secret,
                }
            },
        )
        result, _ = dispatch_with(
            lambda value, _call: FakeResponse(
                f"<html><body>{value}<p>{secret}</p></body></html>"
            ),
            finding=finding,
        )
        serialized = json.dumps(result.to_dict())

        self.assertNotIn(secret, serialized)
        self.assertNotIn("response_body", serialized)

    def test_source_contains_no_active_or_browser_execution(self):
        source = (
            Path(__file__).resolve().parents[1]
            / "app"
            / "validation"
            / "xss.py"
        ).read_text().lower()
        for forbidden in (
            "selenium",
            "playwright",
            "document.cookie",
            "javascript:",
            "onerror=",
            "onload=",
            "alert(",
            "subprocess",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)

    def test_caller_supplied_payload_is_ignored(self):
        finding = make_finding(evidence={"payload": "caller-controlled-active-value"})
        result, session = dispatch_with(raw_text, finding=finding)

        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        sent = json.dumps([call["kwargs"] for call in session.calls])
        self.assertNotIn("caller-controlled-active-value", sent)


if __name__ == "__main__":
    unittest.main()
