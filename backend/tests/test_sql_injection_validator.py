"""Tests for the generic HTTP SQL injection validator."""

import inspect
import unittest

from app.attack_chain.engine import build_attack_paths
from app.attack_chain.mitre_mapping import enrich_finding_model
from app.models.finding import Finding, ValidationStatus
from app.models.validation import ValidationResult
from app.validation import sql_injection
from app.validation.dispatcher import apply_validation_result, dispatch


class FakeResponse:
    def __init__(self, text, status_code=200):
        self.text = text
        self.status_code = status_code


class FakeSession:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []

    def get(self, url, params=None):
        self.calls.append({"method": "GET", "url": url, "params": params})
        return next(self.responses)

    def post(self, url, data=None):
        self.calls.append({"method": "POST", "url": url, "data": data})
        return next(self.responses)


def clear_differential_responses():
    baseline = "<html><body>account available " + ("A" * 500) + "</body></html>"
    false_result = "<html><body>request denied " + ("Z" * 500) + "</body></html>"
    return [
        FakeResponse(baseline),
        FakeResponse(baseline),
        FakeResponse(false_result),
    ]


def make_sqli_finding(**overrides):
    values = {
        "finding_id": "f-generic-sqli",
        "scan_id": "scan-generic-sqli",
        "asset_id": "asset-generic-sqli",
        "target": "http://app.test",
        "host": "app.test",
        "port": 80,
        "protocol": "http",
        "endpoint": "/items",
        "http_method": "GET",
        "parameter_name": "id",
        "parameter_location": "query",
        "source": "synthetic_scanner",
        "template_id": "scanner-template-sqli-001",
        "validator_id": "generic-http-sqli",
        "vulnerability_type": "sql_injection",
        "severity": "high",
        "evidence": {"scanner_match": True},
    }
    values.update(overrides)
    return Finding(**values)


class TestGenericHttpSqlInjectionValidator(unittest.TestCase):

    def test_get_query_clear_differential_is_confirmed(self):
        session = FakeSession(clear_differential_responses())
        result = dispatch(make_sqli_finding(), session=session)

        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        self.assertEqual(result.validator, "generic_http_sqli")
        self.assertEqual(len(session.calls), 3)
        self.assertTrue(all(call["method"] == "GET" for call in session.calls))
        self.assertTrue(all(call["url"] == "http://app.test/items" for call in session.calls))
        self.assertTrue(all(set(call["params"]) == {"id"} for call in session.calls))
        self.assertEqual(result.evidence["parameter_location"], "query")
        self.assertEqual(result.evidence["http_method"], "GET")
        self.assertGreaterEqual(result.evidence["baseline_true_similarity"], 0.90)
        self.assertLessEqual(result.evidence["baseline_false_similarity"], 0.70)

    def test_post_form_clear_differential_is_confirmed(self):
        session = FakeSession(clear_differential_responses())
        finding = make_sqli_finding(
            http_method="post",
            parameter_location="form",
        )
        result = dispatch(finding, session=session)

        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        self.assertTrue(all(call["method"] == "POST" for call in session.calls))
        self.assertTrue(all(set(call["data"]) == {"id"} for call in session.calls))

    def test_equivalent_true_and_false_responses_are_rejected(self):
        same = "<html><body>same application response</body></html>"
        session = FakeSession([FakeResponse(same) for _ in range(3)])

        result = dispatch(make_sqli_finding(), session=session)

        self.assertEqual(result.status, ValidationStatus.REJECTED)
        self.assertEqual(
            result.evidence["reason"],
            "true_and_false_responses_equivalent",
        )

    def test_ambiguous_comparison_returns_manual_review(self):
        session = FakeSession([
            FakeResponse("A" * 100),
            FakeResponse(("A" * 70) + ("B" * 30)),
            FakeResponse(("A" * 55) + ("C" * 45)),
        ])

        result = dispatch(make_sqli_finding(), session=session)

        self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
        self.assertEqual(
            result.evidence["reason"],
            "ambiguous_response_differential",
        )

    def test_missing_endpoint_returns_manual_review(self):
        result = dispatch(
            make_sqli_finding(endpoint=None),
            session=FakeSession([]),
        )
        self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
        self.assertEqual(result.evidence["reason"], "missing_endpoint")

    def test_missing_parameter_name_returns_manual_review(self):
        result = dispatch(
            make_sqli_finding(parameter_name=None),
            session=FakeSession([]),
        )
        self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
        self.assertEqual(result.evidence["reason"], "missing_parameter_name")

    def test_unsupported_http_method_returns_manual_review(self):
        result = dispatch(
            make_sqli_finding(http_method="PUT"),
            session=FakeSession([]),
        )
        self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
        self.assertEqual(result.evidence["reason"], "unsupported_http_method")

    def test_unsupported_parameter_location_returns_manual_review(self):
        result = dispatch(
            make_sqli_finding(parameter_location="json"),
            session=FakeSession([]),
        )
        self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
        self.assertEqual(
            result.evidence["reason"],
            "unsupported_parameter_location",
        )

    def test_scanner_template_id_remains_unchanged(self):
        finding = make_sqli_finding()
        result = dispatch(finding, session=FakeSession(clear_differential_responses()))
        updated = apply_validation_result(finding, result)

        self.assertEqual(updated.template_id, "scanner-template-sqli-001")
        self.assertEqual(updated.validator_id, "generic-http-sqli")

    def test_validator_id_routes_to_generic_handler(self):
        result = dispatch(
            make_sqli_finding(template_id="unregistered-scanner-template"),
            session=FakeSession(clear_differential_responses()),
        )
        self.assertIsInstance(result, ValidationResult)
        self.assertEqual(result.validator, "generic_http_sqli")
        self.assertEqual(result.status, ValidationStatus.CONFIRMED)

    def test_existing_dvwa_template_still_uses_lab_handler(self):
        class LabSession:
            def __init__(self):
                self.responses = iter([
                    FakeResponse('<input name="user_token" value="one">'),
                    FakeResponse(
                        '<pre>First name: admin</pre>'
                        '<input name="user_token" value="two">'
                    ),
                    FakeResponse("<pre>First name: user</pre>" * 5),
                ])

            def get(self, url, params=None):
                return next(self.responses)

        finding = make_sqli_finding(
            target="http://127.0.0.1:8080",
            template_id="dvwa-sqli-low",
            validator_id=None,
        )
        result = dispatch(finding, session=LabSession())

        self.assertEqual(result.validator, "dvwa_sqli_low")
        self.assertEqual(result.status, ValidationStatus.CONFIRMED)

    def test_module_has_no_target_specific_marker_or_path_dependency(self):
        source = inspect.getsource(sql_injection)
        self.assertNotIn("First name:", source)
        self.assertNotIn("/vulnerabilities/sqli/", source)
        self.assertNotIn("dvwa", source.lower())

    def test_scanner_supplied_payload_evidence_is_not_executed(self):
        session = FakeSession(clear_differential_responses())
        finding = make_sqli_finding(
            evidence={"payload": "scanner-controlled-value"},
        )

        dispatch(finding, session=session)

        sent_values = [call["params"]["id"] for call in session.calls]
        self.assertNotIn("scanner-controlled-value", sent_values)
        self.assertEqual(len(set(sent_values)), 3)

    def test_confirmed_finding_enriches_to_t1190_and_builds_chain(self):
        finding = make_sqli_finding()
        result = dispatch(
            finding,
            session=FakeSession(clear_differential_responses()),
        )
        validated = apply_validation_result(finding, result)
        enriched = enrich_finding_model(validated)

        reachability = Finding(
            finding_id="f-reachability",
            scan_id=finding.scan_id,
            asset_id=finding.asset_id,
            target=finding.target,
            host=finding.host,
            source="synthetic_scanner",
            vulnerability_type="nmap_scan",
            validation_status=ValidationStatus.CONFIRMED,
            validation_confidence=1.0,
        )
        chains = build_attack_paths([reachability, enriched])

        self.assertEqual(validated.validation_status, ValidationStatus.CONFIRMED)
        self.assertEqual(enriched.mitre_technique_id, "T1190")
        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0].status, "confirmed")
        self.assertEqual(chains[0].mitre_techniques, ["T1190"])


if __name__ == "__main__":
    unittest.main()
