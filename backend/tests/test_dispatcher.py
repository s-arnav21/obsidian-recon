"""Tests for structured validation dispatch behavior."""

import unittest

from app.models.finding import Finding, ValidationStatus
from app.models.validation import ValidationResult
from app.validation.dispatcher import (
    HANDLERS,
    apply_validation_result,
    dispatch,
    dispatch_and_apply,
    register,
)


def make_finding(template_id="unit-test-confirmed", validator_id=None, **overrides):
    values = {
        "finding_id": "f-dispatch-001",
        "scan_id": "scan-dispatch-001",
        "asset_id": "asset-dispatch-001",
        "target": "http://127.0.0.1",
        "host": "127.0.0.1",
        "port": 80,
        "protocol": "http",
        "endpoint": "/test",
        "source": "unit_test_scanner",
        "template_id": template_id,
        "validator_id": validator_id,
        "vulnerability_type": "sql_injection",
        "severity": "high",
        "evidence": {"scanner_match": True},
        "evidence_refs": ["evidence://scanner/1"],
    }
    values.update(overrides)
    return Finding(**values)


class TestDispatcher(unittest.TestCase):

    def setUp(self):
        @register("unit-test-confirmed")
        def confirmed_handler(finding, session):
            return ValidationResult(
                status=ValidationStatus.CONFIRMED,
                confidence=0.95,
                validator="unit_test_handler",
                method="controlled_test",
                evidence={"validated": True},
                evidence_refs=["evidence://validator/1"],
            )

        @register("unit-test-rejected")
        def rejected_handler(finding, session):
            return ValidationResult(
                status="not_exploitable",
                confidence=0.9,
                validator="unit_test_handler",
                method="controlled_test",
                evidence={"validated": False},
            )

        self.addCleanup(HANDLERS.pop, "unit-test-confirmed", None)
        self.addCleanup(HANDLERS.pop, "unit-test-rejected", None)

    def test_registered_handler_returns_validation_result(self):
        result = dispatch(make_finding())
        self.assertIsInstance(result, ValidationResult)
        self.assertEqual(result.status, ValidationStatus.CONFIRMED)

    def test_validator_id_takes_precedence_over_template_id(self):
        result = dispatch(make_finding(
            template_id="unit-test-confirmed",
            validator_id="unit-test-rejected",
        ))
        self.assertEqual(result.status, ValidationStatus.REJECTED)

    def test_missing_validator_id_falls_back_to_template_id(self):
        finding = make_finding(
            template_id="unit-test-confirmed",
            validator_id=None,
        )
        result = dispatch(finding)
        self.assertEqual(result.status, ValidationStatus.CONFIRMED)

    def test_unknown_explicit_validator_id_returns_manual_review(self):
        result = dispatch(make_finding(
            template_id="unit-test-confirmed",
            validator_id="unsupported-validator",
        ))
        self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
        self.assertEqual(result.validator, "dispatcher_manual_review")
        self.assertEqual(result.evidence["reason"], "no_registered_handler")

    def test_unsupported_template_returns_manual_review(self):
        result = dispatch(make_finding("unsupported-template"))
        self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
        self.assertEqual(result.confidence, 0.6)
        self.assertEqual(result.validator, "dispatcher_manual_review")
        self.assertEqual(
            result.evidence["reason"],
            "no_registered_handler",
        )

    def test_applying_result_preserves_finding_context(self):
        finding = make_finding(
            validator_id="unit-test-confirmed",
            http_method="post",
            parameter_name="id",
            parameter_location="form",
        )
        updated = apply_validation_result(finding, dispatch(finding))

        for field_name in (
            "finding_id",
            "scan_id",
            "asset_id",
            "target",
            "host",
            "port",
            "protocol",
            "endpoint",
            "http_method",
            "parameter_name",
            "parameter_location",
            "source",
            "template_id",
            "validator_id",
            "vulnerability_type",
            "severity",
        ):
            self.assertEqual(
                getattr(updated, field_name),
                getattr(finding, field_name),
            )

        self.assertTrue(updated.evidence["scanner_match"])
        self.assertTrue(updated.evidence["validated"])
        self.assertEqual(
            updated.evidence_refs,
            ["evidence://scanner/1", "evidence://validator/1"],
        )

    def test_rejected_result_updates_finding_status(self):
        finding = make_finding("unit-test-rejected")
        updated = dispatch_and_apply(finding)
        self.assertEqual(updated.validation_status, ValidationStatus.REJECTED)
        self.assertEqual(updated.validation_confidence, 0.9)

    def test_confirmed_result_preserves_assessment_identifiers(self):
        finding = make_finding()
        updated = dispatch_and_apply(finding)
        self.assertEqual(updated.validation_status, ValidationStatus.CONFIRMED)
        self.assertEqual(updated.target, finding.target)
        self.assertEqual(updated.host, finding.host)
        self.assertEqual(updated.scan_id, finding.scan_id)
        self.assertEqual(updated.asset_id, finding.asset_id)

    def test_dvwa_handler_returns_structured_result(self):
        class Response:
            def __init__(self, text):
                self.text = text

        class FakeSession:
            def __init__(self):
                self.calls = []
                self.responses = iter([
                    Response(
                        '<input name="user_token" value="token-one">'
                    ),
                    Response(
                        '<pre>ID: 1<br />First name: admin<br />'
                        'Surname: admin</pre>'
                        '<input name="user_token" value="token-two">'
                    ),
                    Response(
                        "".join(
                            f'<pre>ID: {index}<br />First name: user{index}'
                            f'<br />Surname: surname{index}</pre>'
                            for index in range(1, 6)
                        )
                    ),
                ])

            def get(self, url, params=None):
                self.calls.append((url, params))
                return next(self.responses)

        session = FakeSession()
        result = dispatch(
            make_finding("dvwa-sqli-low"),
            session=session,
        )

        self.assertIsInstance(result, ValidationResult)
        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        self.assertEqual(result.validator, "dvwa_sqli_low")
        self.assertEqual(result.evidence["baseline_result_count"], 1)
        self.assertEqual(result.evidence["injected_result_count"], 5)
        self.assertGreater(
            result.evidence["injected_length"],
            result.evidence["baseline_length"],
        )
        self.assertEqual(session.calls[1][1]["user_token"], "token-one")
        self.assertEqual(session.calls[2][1]["user_token"], "token-two")


if __name__ == "__main__":
    unittest.main()
