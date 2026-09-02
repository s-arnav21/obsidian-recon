"""Tests for internal scanner-record normalization and generic validation."""

import inspect
import unittest

from app.attack_chain.engine import build_attack_paths
from app.attack_chain.mitre_mapping import enrich_finding_model
from app.models.finding import Finding, ValidationStatus
from app.scanning import normalizer
from app.scanning.normalizer import (
    HttpScannerRecord,
    ScannerNormalizationError,
    normalize_command_execution_record,
    normalize_http_sqli_record,
)
from app.validation.dispatcher import apply_validation_result, dispatch


class FakeResponse:
    def __init__(self, text, status_code=200):
        self.text = text
        self.status_code = status_code


class FakeSession:
    def __init__(self):
        baseline = "<html><body>record available " + ("A" * 500) + "</body></html>"
        false_result = "<html><body>record denied " + ("Z" * 500) + "</body></html>"
        self.responses = iter([
            FakeResponse(baseline),
            FakeResponse(baseline),
            FakeResponse(false_result),
        ])
        self.calls = []

    def get(self, url, params=None):
        self.calls.append((url, params))
        return next(self.responses)


def make_record(**overrides):
    values = {
        "record_id": "finding-scanner-sqli",
        "scan_id": "scan-scanner-sqli",
        "asset_id": "asset-scanner-sqli",
        "target": "http://127.0.0.1:8090",
        "endpoint": "/items",
        "http_method": "get",
        "parameter_name": "id",
        "parameter_location": "query",
        "scanner_name": "synthetic_http_scanner",
        "scanner_template_id": "synthetic-sqli-check",
        "vulnerability_type": "SQL Injection",
        "severity": "high",
        "evidence": {"candidate_parameter": True},
        "evidence_refs": ["scanner://synthetic/record-1"],
        "observed_at": "2026-09-01T10:00:00+00:00",
    }
    values.update(overrides)
    return HttpScannerRecord(**values)


def make_command_record(**overrides):
    values = {
        "record_id": "finding-scanner-command-execution",
        "scan_id": "scan-scanner-command-execution",
        "asset_id": "asset-scanner-command-execution",
        "target": "http://127.0.0.1:8090",
        "endpoint": "/admin/diagnostics",
        "http_method": "post",
        "parameter_name": "diagnostic_token",
        "parameter_location": "form",
        "scanner_name": "synthetic_http_scanner",
        "scanner_template_id": "synthetic-command-execution-check",
        "vulnerability_type": "Unix Shell Command Execution",
        "severity": "critical",
    }
    values.update(overrides)
    return HttpScannerRecord(**values)


class TestHttpScannerNormalizer(unittest.TestCase):

    def test_command_execution_record_uses_canonical_type_and_route(self):
        finding = normalize_command_execution_record(make_command_record())

        self.assertEqual(finding.vulnerability_type, "command_execution")
        self.assertEqual(
            finding.validator_id,
            "generic-http-command-execution",
        )
        self.assertEqual(finding.http_method, "POST")
        self.assertEqual(finding.parameter_location, "form")
        self.assertEqual(finding.parameter_name, "diagnostic_token")

    def test_command_execution_record_rejects_other_request_shapes(self):
        with self.assertRaisesRegex(
            ScannerNormalizationError,
            "requires POST/form",
        ):
            normalize_command_execution_record(make_command_record(
                http_method="GET",
                parameter_location="query",
            ))

    def test_record_normalizes_to_canonical_finding(self):
        finding = normalize_http_sqli_record(make_record())

        self.assertIsInstance(finding, Finding)
        self.assertEqual(finding.finding_id, "finding-scanner-sqli")
        self.assertEqual(finding.scan_id, "scan-scanner-sqli")
        self.assertEqual(finding.asset_id, "asset-scanner-sqli")
        self.assertEqual(finding.target, "http://127.0.0.1:8090")
        self.assertEqual(finding.host, "127.0.0.1")
        self.assertEqual(finding.port, 8090)
        self.assertEqual(finding.protocol, "http")
        self.assertEqual(finding.validation_status, ValidationStatus.DETECTED)

    def test_scanner_identity_and_validator_routing_are_separate(self):
        finding = normalize_http_sqli_record(make_record())

        self.assertEqual(finding.source, "synthetic_http_scanner")
        self.assertEqual(finding.template_id, "synthetic-sqli-check")
        self.assertEqual(finding.validator_id, "generic-http-sqli")
        self.assertEqual(finding.raw_finding_ref, "finding-scanner-sqli")

    def test_http_request_context_is_preserved_and_normalized(self):
        finding = normalize_http_sqli_record(make_record())

        self.assertEqual(finding.endpoint, "/items")
        self.assertEqual(finding.http_method, "GET")
        self.assertEqual(finding.parameter_name, "id")
        self.assertEqual(finding.parameter_location, "query")

    def test_sqli_aliases_normalize_to_canonical_type(self):
        for vulnerability_type in ("sqli", "sql-injection", "SQL Injection"):
            with self.subTest(vulnerability_type=vulnerability_type):
                finding = normalize_http_sqli_record(make_record(
                    vulnerability_type=vulnerability_type,
                ))
                self.assertEqual(finding.vulnerability_type, "sql_injection")

    def test_missing_or_invalid_context_fails_clearly(self):
        cases = {
            "missing endpoint": ({"endpoint": ""}, "endpoint"),
            "missing parameter": ({"parameter_name": ""}, "parameter_name"),
            "unsupported method": ({"http_method": "PUT"}, "request shapes"),
            "unsupported location": (
                {"parameter_location": "json"},
                "request shapes",
            ),
            "target path": (
                {"target": "http://127.0.0.1:8090/items"},
                "target must be an origin",
            ),
            "absolute endpoint": (
                {"endpoint": "http://other.test/items"},
                "approved target origin",
            ),
            "non-sqli type": (
                {"vulnerability_type": "command_injection"},
                "SQL injection",
            ),
        }
        for name, (overrides, message) in cases.items():
            with self.subTest(name=name):
                with self.assertRaisesRegex(ScannerNormalizationError, message):
                    normalize_http_sqli_record(make_record(**overrides))

    def test_evidence_is_copied_not_shared(self):
        record = make_record()
        finding = normalize_http_sqli_record(record)

        finding.evidence["normalized"] = True
        finding.evidence_refs.append("scanner://synthetic/record-2")

        self.assertNotIn("normalized", record.evidence)
        self.assertEqual(record.evidence_refs, ["scanner://synthetic/record-1"])

    def test_normalizer_contains_no_lab_specific_dependencies(self):
        source = inspect.getsource(normalizer)
        finding = normalize_http_sqli_record(make_record())

        self.assertNotIn("dvwa", source.lower())
        self.assertNotIn("First name:", source)
        self.assertNotIn("/vulnerabilities/sqli/", source)
        self.assertNotIn("dvwa", finding.template_id.lower())
        self.assertNotIn("dvwa", finding.endpoint.lower())

    def test_normalized_finding_routes_and_confirms_with_fake_client(self):
        finding = normalize_http_sqli_record(make_record())
        session = FakeSession()

        result = dispatch(finding, session=session)
        validated = apply_validation_result(finding, result)

        self.assertEqual(result.validator, "generic_http_sqli")
        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        self.assertEqual(validated.validation_status, ValidationStatus.CONFIRMED)
        self.assertEqual(len(session.calls), 3)
        self.assertTrue(all(url == "http://127.0.0.1:8090/items" for url, _ in session.calls))

    def test_normalized_confirmed_finding_maps_to_t1190_and_chains(self):
        finding = normalize_http_sqli_record(make_record())
        result = dispatch(finding, session=FakeSession())
        validated = apply_validation_result(finding, result)
        enriched = enrich_finding_model(validated)

        reachability = Finding(
            finding_id="finding-reachability",
            scan_id=finding.scan_id,
            asset_id=finding.asset_id,
            target=finding.target,
            host=finding.host,
            port=finding.port,
            protocol=finding.protocol,
            endpoint="/",
            source="synthetic_http_scanner",
            template_id="synthetic-http-reachability",
            vulnerability_type="service_scan",
            validation_status=ValidationStatus.CONFIRMED,
            validation_confidence=1.0,
        )
        chains = build_attack_paths([reachability, enriched])

        self.assertEqual(enriched.mitre_technique_id, "T1190")
        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0].status, "confirmed")
        self.assertEqual(chains[0].mitre_techniques, ["T1190"])
        self.assertEqual(
            [step.finding_id for step in chains[0].steps],
            ["finding-reachability", "finding-scanner-sqli"],
        )


if __name__ == "__main__":
    unittest.main()
