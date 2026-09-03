"""Tests for the canonical Finding contract."""

import unittest

from app.models.finding import Finding, ParameterLocation, ValidationStatus


def make_finding(**overrides):
    values = {
        "finding_id": "f-001",
        "scan_id": "scan-001",
        "asset_id": "asset-001",
        "target": "http://127.0.0.1",
        "host": "127.0.0.1",
        "port": 80,
        "protocol": "http",
        "endpoint": "/vulnerabilities/sqli/",
        "source": "nuclei",
        "template_id": "dvwa-sqli-low",
        "vulnerability_type": "sql_injection",
        "severity": "high",
        "observed_at": "2026-08-31T10:00:00+00:00",
    }
    values.update(overrides)
    return Finding(**values)


class TestFinding(unittest.TestCase):

    def test_valid_finding_creation(self):
        finding = make_finding()
        self.assertEqual(finding.finding_id, "f-001")
        self.assertEqual(finding.scan_id, "scan-001")
        self.assertEqual(finding.asset_id, "asset-001")
        self.assertEqual(finding.validation_status, ValidationStatus.DETECTED)
        self.assertEqual(finding.validation_confidence, 0.0)

    def test_existing_payloads_default_new_http_fields_to_none(self):
        existing_payload = make_finding().to_dict()
        for field_name in (
            "validator_id",
            "http_method",
            "parameter_name",
            "parameter_location",
        ):
            existing_payload.pop(field_name)

        finding = Finding.from_dict(existing_payload)
        self.assertIsNone(finding.validator_id)
        self.assertIsNone(finding.http_method)
        self.assertIsNone(finding.parameter_name)
        self.assertIsNone(finding.parameter_location)

    def test_http_method_normalizes_to_uppercase(self):
        finding = make_finding(http_method="get")
        self.assertEqual(finding.http_method, "GET")

    def test_supported_parameter_locations_normalize_and_serialize(self):
        for location in ParameterLocation.SUPPORTED:
            with self.subTest(location=location):
                finding = make_finding(parameter_location=location.upper())
                self.assertEqual(finding.parameter_location, location)
                self.assertEqual(finding.to_dict()["parameter_location"], location)

    def test_invalid_parameter_location_fails_clearly(self):
        with self.assertRaisesRegex(ValueError, "unsupported parameter_location"):
            make_finding(parameter_location="body")

    def test_transient_http_context_is_copied_but_not_serialized(self):
        context = {
            "header": {
                "Authorization": "Bearer test-secret",
                "id": "original",
            },
        }
        finding = make_finding(
            parameter_location="header",
            http_request_context=context,
        )
        context["header"]["Authorization"] = "changed"

        self.assertEqual(
            finding.http_request_context["header"]["Authorization"],
            "Bearer test-secret",
        )
        self.assertNotIn("http_request_context", finding.to_dict())
        self.assertNotIn("test-secret", str(finding.to_dict()))

    def test_missing_required_fields_fail_clearly(self):
        with self.assertRaisesRegex(
            ValueError,
            "missing required Finding fields: scan_id, asset_id",
        ):
            Finding.from_dict({
                "finding_id": "f-001",
                "target": "http://127.0.0.1",
                "host": "127.0.0.1",
                "source": "nuclei",
                "vulnerability_type": "sql_injection",
            })

    def test_confidence_must_be_bounded(self):
        for confidence in (-0.1, 1.1, float("nan")):
            with self.subTest(confidence=confidence):
                with self.assertRaises(ValueError):
                    make_finding(validation_confidence=confidence)

        with self.assertRaises(TypeError):
            make_finding(validation_confidence="high")

    def test_not_exploitable_normalizes_to_rejected(self):
        finding = make_finding(validation_status="not_exploitable")
        self.assertEqual(finding.validation_status, ValidationStatus.REJECTED)

    def test_unknown_status_fails(self):
        with self.assertRaisesRegex(ValueError, "unsupported validation status"):
            make_finding(validation_status="probably_confirmed")

    def test_dictionary_round_trip(self):
        original = make_finding(
            validator_id="generic-validator-test",
            http_method="post",
            parameter_name="id",
            parameter_location="form",
            validation_status=ValidationStatus.CONFIRMED,
            validation_confidence=0.95,
            evidence={"comparison": "different"},
            evidence_refs=["evidence://f-001/response-comparison"],
            requires=["discovered_services"],
            provides=["application_compromise"],
        )

        reconstructed = Finding.from_dict(original.to_dict())
        self.assertEqual(reconstructed, original)
        self.assertEqual(reconstructed.http_method, "POST")
        self.assertEqual(reconstructed.parameter_location, "form")


if __name__ == "__main__":
    unittest.main()
