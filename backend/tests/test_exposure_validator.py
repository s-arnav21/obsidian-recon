"""Tests for generic exposed-resource normalization and validation."""

import unittest
from dataclasses import replace

from app.attack_chain.mitre_mapping import enrich_finding_model
from app.models.finding import ValidationStatus
from app.scanning.normalizer import (
    ExposedResourceScannerRecord,
    normalize_exposed_resource_record,
)
from app.validation.dispatcher import apply_validation_result, dispatch


class FakeResponse:
    def __init__(self, text, status_code=200, content_type="text/html"):
        self.text = text
        self.status_code = status_code
        self.headers = {"content-type": content_type}


class FakeSession:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def get(self, url):
        self.calls.append(url)
        return self.response


def make_record(**overrides):
    values = {
        "record_id": "finding-exposed-resource",
        "scan_id": "scan-web-validation",
        "asset_id": "asset-web-validation",
        "target": "http://127.0.0.1:8092",
        "endpoint": "/discovered-resource",
        "scanner_name": "synthetic_http_scanner",
        "scanner_template_id": "synthetic-sensitive-resource-check",
        "vulnerability_type": "configuration exposure",
        "severity": "high",
        "evidence": {"candidate_resource": True},
        "evidence_refs": ["scanner://synthetic/exposure-1"],
    }
    values.update(overrides)
    return ExposedResourceScannerRecord(**values)


def make_finding(**overrides):
    return normalize_exposed_resource_record(make_record(**overrides))


class TestGenericExposedResourceValidator(unittest.TestCase):

    def test_strong_accessible_exposure_is_confirmed(self):
        response = FakeResponse(
            "APP_MODE=debug\nSERVICE_TOKEN=example-value\n",
            content_type="text/plain",
        )
        result = dispatch(make_finding(), session=FakeSession(response))

        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        self.assertEqual(result.validator, "generic_http_exposed_resource")
        self.assertIn(
            "environment_assignment_set",
            result.evidence["classification_signals"],
        )
        self.assertEqual(result.evidence["response_content_type"], "text/plain")

    def test_not_found_resource_is_rejected(self):
        session = FakeSession(FakeResponse("not found", status_code=404))
        result = dispatch(make_finding(), session=session)

        self.assertEqual(result.status, ValidationStatus.REJECTED)
        self.assertEqual(
            result.evidence["reason"],
            "resource_not_publicly_accessible",
        )

    def test_ambiguous_generic_page_is_manual_review(self):
        session = FakeSession(FakeResponse(
            "<html><body>ordinary public page</body></html>"
        ))
        result = dispatch(make_finding(), session=session)

        self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
        self.assertEqual(
            result.evidence["reason"],
            "accessible_resource_without_strong_sensitive_signal",
        )

    def test_cross_origin_endpoint_is_manual_review_without_request(self):
        finding = replace(
            make_finding(),
            endpoint="http://other.test/discovered-resource",
        )
        session = FakeSession(FakeResponse("unused"))

        result = dispatch(finding, session=session)

        self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
        self.assertEqual(result.evidence["reason"], "endpoint_origin_mismatch")
        self.assertEqual(session.calls, [])

    def test_validator_requests_only_supplied_endpoint_once(self):
        session = FakeSession(FakeResponse(
            "APP_MODE=debug\nSERVICE_TOKEN=example-value\n",
            content_type="text/plain",
        ))

        dispatch(make_finding(), session=session)

        self.assertEqual(
            session.calls,
            ["http://127.0.0.1:8092/discovered-resource"],
        )

    def test_normalization_preserves_provenance_and_routes_validator(self):
        finding = make_finding()
        result = dispatch(
            finding,
            session=FakeSession(FakeResponse(
                "APP_MODE=debug\nSERVICE_TOKEN=example-value\n",
                content_type="text/plain",
            )),
        )
        validated = apply_validation_result(finding, result)

        self.assertEqual(finding.vulnerability_type, "sensitive_data_exposure")
        self.assertEqual(finding.validator_id, "generic-http-exposed-resource")
        self.assertEqual(finding.template_id, "synthetic-sensitive-resource-check")
        self.assertEqual(validated.template_id, finding.template_id)

    def test_disclosure_alias_normalizes_without_inventing_mitre_mapping(self):
        finding = make_finding(vulnerability_type="directory resource disclosure")
        result = dispatch(
            finding,
            session=FakeSession(FakeResponse(
                "<html><title>Index of /</title></html>"
            )),
        )
        validated = apply_validation_result(finding, result)
        enriched = enrich_finding_model(validated)

        self.assertEqual(validated.validation_status, ValidationStatus.CONFIRMED)
        self.assertEqual(finding.vulnerability_type, "information_disclosure")
        self.assertIsNone(enriched.mitre_technique_id)
        self.assertEqual(enriched.provides, ["potential_information_exposure"])
        self.assertEqual(enriched.template_id, finding.template_id)

    def test_response_body_is_not_copied_into_evidence(self):
        body = "APP_MODE=debug\nSERVICE_TOKEN=example-value\n"
        result = dispatch(
            make_finding(),
            session=FakeSession(FakeResponse(body, content_type="text/plain")),
        )

        self.assertNotIn(body, result.evidence.values())
        self.assertEqual(result.evidence["response_size"], len(body))


if __name__ == "__main__":
    unittest.main()
