"""Tests for generic reflected-XSS normalization and validation."""

import html
import unittest
from dataclasses import replace

from app.attack_chain.mitre_mapping import enrich_finding_model
from app.models.finding import ValidationStatus
from app.scanning.normalizer import (
    HttpScannerRecord,
    normalize_reflected_xss_record,
)
from app.validation.dispatcher import apply_validation_result, dispatch


class FakeResponse:
    def __init__(self, text, status_code=200, content_type="text/html"):
        self.text = text
        self.status_code = status_code
        self.headers = {"content-type": content_type}


class ReflectionSession:
    def __init__(self, reflection_mode="raw"):
        self.reflection_mode = reflection_mode
        self.calls = []

    def _respond(self, method, url, values):
        self.calls.append({"method": method, "url": url, "values": values})
        value = next(iter(values.values()))
        if self.reflection_mode == "raw":
            body = f"<html><body>{value}</body></html>"
        elif self.reflection_mode == "encoded":
            body = f"<html><body>{html.escape(value)}</body></html>"
        else:
            body = "<html><body>static response</body></html>"
        return FakeResponse(body)

    def get(self, url, params=None):
        return self._respond("GET", url, params)

    def post(self, url, data=None):
        return self._respond("POST", url, data)


def make_record(**overrides):
    values = {
        "record_id": "finding-reflected-xss",
        "scan_id": "scan-web-validation",
        "asset_id": "asset-web-validation",
        "target": "http://127.0.0.1:8091",
        "endpoint": "/search",
        "http_method": "GET",
        "parameter_name": "query",
        "parameter_location": "query",
        "scanner_name": "synthetic_http_scanner",
        "scanner_template_id": "synthetic-reflected-xss-check",
        "vulnerability_type": "reflected xss",
        "severity": "medium",
        "evidence": {"candidate_parameter": True},
        "evidence_refs": ["scanner://synthetic/xss-1"],
    }
    values.update(overrides)
    return HttpScannerRecord(**values)


def make_finding(**overrides):
    return normalize_reflected_xss_record(make_record(**overrides))


class TestGenericReflectedXssValidator(unittest.TestCase):

    def test_get_query_raw_html_reflection_is_confirmed(self):
        finding = make_finding()
        session = ReflectionSession("raw")

        result = dispatch(finding, session=session)

        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        self.assertEqual(result.validator, "generic_http_reflected_xss")
        self.assertTrue(result.evidence["marker_reflected"])
        self.assertTrue(result.evidence["raw_probe_reflected"])
        self.assertEqual(result.evidence["response_context"], "raw_html_element")
        self.assertEqual([call["method"] for call in session.calls], ["GET", "GET"])

    def test_post_form_raw_html_reflection_is_confirmed(self):
        finding = make_finding(
            http_method="post",
            parameter_location="form",
        )
        session = ReflectionSession("raw")

        result = dispatch(finding, session=session)

        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        self.assertEqual([call["method"] for call in session.calls], ["POST", "POST"])

    def test_no_reflection_is_rejected(self):
        result = dispatch(
            make_finding(),
            session=ReflectionSession("none"),
        )

        self.assertEqual(result.status, ValidationStatus.REJECTED)
        self.assertEqual(result.evidence["reason"], "marker_not_reflected")

    def test_encoded_reflection_is_manual_review(self):
        result = dispatch(
            make_finding(),
            session=ReflectionSession("encoded"),
        )

        self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
        self.assertEqual(
            result.evidence["reason"],
            "reflection_context_requires_browser_review",
        )
        self.assertTrue(result.evidence["marker_reflected"])
        self.assertFalse(result.evidence["raw_probe_reflected"])

    def test_missing_context_returns_manual_review(self):
        finding = replace(make_finding(), endpoint=None)
        result = dispatch(finding, session=ReflectionSession())

        self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
        self.assertEqual(result.evidence["reason"], "missing_endpoint")

    def test_unsupported_method_or_location_returns_manual_review(self):
        findings = [
            replace(make_finding(), http_method="PUT"),
            replace(make_finding(), parameter_location="json"),
        ]
        for finding in findings:
            with self.subTest(
                method=finding.http_method,
                location=finding.parameter_location,
            ):
                result = dispatch(finding, session=ReflectionSession())
                self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
                self.assertEqual(
                    result.evidence["reason"],
                    "unsupported_request_shape",
                )

    def test_scanner_supplied_payload_is_ignored(self):
        finding = make_finding(evidence={"payload": "scanner-controlled-value"})
        session = ReflectionSession("raw")

        dispatch(finding, session=session)

        sent_values = [
            next(iter(call["values"].values()))
            for call in session.calls
        ]
        self.assertNotIn("scanner-controlled-value", sent_values)

    def test_normalization_preserves_template_and_routes_validator(self):
        finding = make_finding()
        result = dispatch(finding, session=ReflectionSession("raw"))
        validated = apply_validation_result(finding, result)

        self.assertEqual(finding.vulnerability_type, "reflected_xss")
        self.assertEqual(finding.validator_id, "generic-http-reflected-xss")
        self.assertEqual(finding.template_id, "synthetic-reflected-xss-check")
        self.assertEqual(validated.template_id, finding.template_id)

    def test_mitre_enrichment_remains_unresolved_without_corruption(self):
        finding = make_finding()
        validated = apply_validation_result(
            finding,
            dispatch(finding, session=ReflectionSession("raw")),
        )
        enriched = enrich_finding_model(validated)

        self.assertEqual(enriched.validation_status, ValidationStatus.CONFIRMED)
        self.assertIsNone(enriched.mitre_technique_id)
        self.assertEqual(enriched.provides, [])
        self.assertEqual(enriched.template_id, finding.template_id)


if __name__ == "__main__":
    unittest.main()
