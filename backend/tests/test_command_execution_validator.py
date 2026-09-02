"""Tests for the fixed-token synthetic command-execution validator."""

from __future__ import annotations

import ast
import unittest
from pathlib import Path

from app.attack_chain.mitre_mapping import enrich_finding_model
from app.models.finding import Finding, ValidationStatus
from app.validation.command_execution import (
    BASELINE_DIAGNOSTIC_TOKEN,
    CONTROL_PROBE_TOKEN,
    EXECUTION_MARKER,
    EXECUTION_PROBE_TOKEN,
    validate_generic_http_command_execution,
)
from app.validation.dispatcher import dispatch


class FakeResponse:
    def __init__(self, text, status_code=200):
        self.text = text
        self.status_code = status_code


class RecordingSession:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []

    def post(self, url, data=None):
        self.calls.append((url, data))
        return next(self.responses)


def make_finding(**overrides):
    values = {
        "finding_id": "finding-command-execution",
        "scan_id": "scan-command-execution",
        "asset_id": "asset-command-execution",
        "target": "http://127.0.0.1:8090",
        "host": "127.0.0.1",
        "port": 8090,
        "protocol": "http",
        "endpoint": "/admin/diagnostics",
        "source": "unit_test_scanner",
        "template_id": "unit-test-command-execution",
        "validator_id": "generic-http-command-execution",
        "vulnerability_type": "command_execution",
        "severity": "critical",
        "http_method": "POST",
        "parameter_name": "diagnostic_token",
        "parameter_location": "form",
        "validation_status": ValidationStatus.DETECTED,
        "validation_confidence": 0.2,
        "evidence": {"caller_supplied_value": "must-not-be-sent"},
    }
    values.update(overrides)
    return Finding(**values)


class GenericCommandExecutionValidatorTests(unittest.TestCase):

    def test_unique_execution_marker_confirms(self):
        session = RecordingSession([
            FakeResponse("synthetic diagnostics ready"),
            FakeResponse(f"synthetic result: {EXECUTION_MARKER}"),
            FakeResponse("synthetic diagnostic control rejected"),
        ])

        result = validate_generic_http_command_execution(
            make_finding(),
            session,
        )

        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        self.assertEqual(result.confidence, 0.9)
        self.assertTrue(result.evidence["execution_marker_present"])
        self.assertFalse(result.evidence["control_marker_present"])
        self.assertNotIn(EXECUTION_MARKER, repr(result.evidence))
        self.assertEqual(
            [call[1]["diagnostic_token"] for call in session.calls],
            [
                BASELINE_DIAGNOSTIC_TOKEN,
                EXECUTION_PROBE_TOKEN,
                CONTROL_PROBE_TOKEN,
            ],
        )
        self.assertNotIn(
            "must-not-be-sent",
            repr(session.calls),
        )

    def test_missing_execution_marker_rejects(self):
        session = RecordingSession([
            FakeResponse("baseline"),
            FakeResponse("no marker"),
            FakeResponse("control"),
        ])

        result = validate_generic_http_command_execution(
            make_finding(),
            session,
        )

        self.assertEqual(result.status, ValidationStatus.REJECTED)
        self.assertEqual(result.confidence, 0.9)
        self.assertEqual(
            result.evidence["reason"],
            "synthetic_execution_marker_not_observed",
        )

    def test_control_marker_is_ambiguous_and_requires_manual_review(self):
        session = RecordingSession([
            FakeResponse("baseline"),
            FakeResponse(f"probe {EXECUTION_MARKER}"),
            FakeResponse(f"control {EXECUTION_MARKER}"),
        ])

        result = validate_generic_http_command_execution(
            make_finding(),
            session,
        )

        self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
        self.assertEqual(result.confidence, 0.6)
        self.assertEqual(
            result.evidence["reason"],
            "execution_marker_not_unique_to_probe",
        )

    def test_dispatcher_routes_registered_validator(self):
        session = RecordingSession([
            FakeResponse("baseline"),
            FakeResponse(f"probe {EXECUTION_MARKER}"),
            FakeResponse("control"),
        ])

        result = dispatch(make_finding(), session=session)

        self.assertEqual(result.validator, "generic_http_command_execution")
        self.assertEqual(result.status, ValidationStatus.CONFIRMED)

    def test_confirmed_finding_maps_to_t1059_004(self):
        finding = make_finding(
            validation_status=ValidationStatus.CONFIRMED,
            validation_confidence=0.9,
        )

        enriched = enrich_finding_model(finding)

        self.assertEqual(enriched.mitre_technique_id, "T1059.004")
        self.assertEqual(
            enriched.mitre_technique_name,
            "Command and Scripting Interpreter: Unix Shell",
        )
        self.assertEqual(enriched.requires_any, ["application_compromise"])
        self.assertEqual(enriched.provides, ["command_execution"])

    def test_non_confirmed_mapping_preserves_validation_state(self):
        finding = make_finding(
            validation_status=ValidationStatus.MANUAL_REVIEW,
            validation_confidence=0.6,
        )

        enriched = enrich_finding_model(finding)

        self.assertEqual(enriched.mitre_technique_id, "T1059.004")
        self.assertEqual(
            enriched.validation_status,
            ValidationStatus.MANUAL_REVIEW,
        )

    def test_validator_module_has_no_operating_system_execution_api(self):
        module_path = (
            Path(__file__).resolve().parents[1]
            / "app"
            / "validation"
            / "command_execution.py"
        )
        tree = ast.parse(module_path.read_text())

        imported_roots = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(
                    alias.name.split(".")[0] for alias in node.names
                )
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots.add(node.module.split(".")[0])
        self.assertTrue({"os", "subprocess"}.isdisjoint(imported_roots))

        forbidden_calls = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
                forbidden_calls.append(node.func.id)
            if isinstance(node.func, ast.Attribute) and node.func.attr in {
                "system",
                "popen",
            }:
                forbidden_calls.append(node.func.attr)
            if any(
                keyword.arg == "shell"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
                for keyword in node.keywords
            ):
                forbidden_calls.append("shell=True")
        self.assertEqual(forbidden_calls, [])


if __name__ == "__main__":
    unittest.main()
