import json
import unittest
from pathlib import Path

from app.presentation.security import decorate_pipeline_response
from app.validation.command_execution import (
    BASELINE_DIAGNOSTIC_TOKEN,
    CONTROL_PROBE_TOKEN,
    EXECUTION_PROBE_TOKEN,
)


def finding(
    finding_id,
    vulnerability_type,
    *,
    endpoint,
    method="GET",
    parameter="id",
    location="query",
    technique_id=None,
    technique_name=None,
    tactic=None,
    requires=None,
    provides=None,
    severity="high",
):
    return {
        "finding_id": finding_id,
        "scan_id": "scan-presentation",
        "asset_id": "asset-presentation",
        "target": "http://127.0.0.1:8090",
        "endpoint": endpoint,
        "http_method": method,
        "parameter_name": parameter,
        "parameter_location": location,
        "vulnerability_type": vulnerability_type,
        "severity": severity,
        "validation_status": "confirmed",
        "validation_confidence": 0.9,
        "mitre_technique_id": technique_id,
        "mitre_technique_name": technique_name,
        "mitre_tactic": tactic,
        "requires_any": requires or [],
        "requires_all": [],
        "provides": provides or [],
    }


def validation(method, evidence):
    return {
        "status": "confirmed",
        "confidence": 0.9,
        "validator": "existing_validator",
        "method": method,
        "evidence": evidence,
    }


class SecurityPresentationTests(unittest.TestCase):
    def setUp(self):
        self.sqli = finding(
            "finding-sqli",
            "sql_injection",
            endpoint="/items",
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            tactic="Initial Access",
            requires=["discovered_services"],
            provides=["application_compromise", "possible_database_access"],
        )
        self.sqli_validation = validation(
            "boolean-response-differential SQLi",
            {
                "baseline_status": 200,
                "true_probe_status": 200,
                "false_probe_status": 200,
                "baseline_true_similarity": 1.0,
                "baseline_false_similarity": 0.25,
                "true_false_similarity": 0.25,
                "similarity_delta": 0.75,
                "decision": "confirmed",
                "reason": "boolean_response_differential_confirmed",
            },
        )

    def decorate(self, finding_value, validation_value, *, controlled=True, chains=None):
        return decorate_pipeline_response(
            {
                "findings": [finding_value],
                "validations": [validation_value],
                "chains": chains or [],
            },
            controlled_lab=controlled,
        )

    def test_controlled_sqli_poc_uses_existing_fixed_request_shapes(self):
        result = self.decorate(self.sqli, self.sqli_validation)
        presentation = result["finding_presentations"][0]
        requests = [item["request"] for item in presentation["poc"]["requests"]]

        self.assertEqual(presentation["poc"]["label"], "Controlled Lab")
        self.assertEqual(requests, [
            "GET /items?id=1",
            "GET /items?id=1+AND+1%3D1",
            "GET /items?id=1+AND+1%3D2",
        ])
        self.assertEqual(presentation["mitre"], {
            "technique_id": "T1190",
            "technique_name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
        })
        self.assertEqual(presentation["risk"]["rating"], "High")
        self.assertEqual(presentation["risk"]["cia"]["confidentiality"], "High")
        self.assertEqual(presentation["risk"]["cvss"], "Not supplied")

    def test_real_scan_does_not_fabricate_or_disclose_reproduction_requests(self):
        result = self.decorate(self.sqli, self.sqli_validation, controlled=False)
        poc = result["finding_presentations"][0]["poc"]

        self.assertEqual(poc["requests"], [])
        self.assertEqual(
            poc["request_note"],
            "Detailed PoC request not available from the observed evidence.",
        )

    def test_advanced_sqli_evidence_presents_methods_and_all_boolean_pairs(self):
        pairs = [
            {
                "pair_index": index,
                "true_probe": true_probe,
                "false_probe": false_probe,
                "pair_confirmed": index < 3,
            }
            for index, (true_probe, false_probe) in enumerate((
                ("1 AND 1=1", "1 AND 1=2"),
                ("1 AND 'x'='x'", "1 AND 'x'='y'"),
                ("0 OR 1=1 AND 1=1", "0 OR 1=1 AND 1=2"),
            ), start=1)
        ]
        advanced_validation = validation(
            "multi-method deterministic SQLi",
            {
                "methods_triggered": ["boolean-response-differential"],
                "waf_or_filter_interference": False,
                "detection_methods": {
                    "boolean-response-differential": {
                        "state": "confirmed",
                        "reason": "multiple_boolean_pairs_confirmed",
                        "control_value": "1",
                        "confirming_pairs": 2,
                        "total_pairs": 3,
                        "pairs": pairs,
                    },
                    "error-based": {
                        "state": "negative",
                        "reason": "no_new_database_error_signature",
                    },
                    "time-based-blind": {
                        "state": "skipped",
                        "reason": "strong_non_timing_method_confirmed",
                    },
                },
                "decision": "confirmed",
                "reason": "one_or_more_detection_methods_confirmed",
            },
        )
        result = self.decorate(self.sqli, advanced_validation)
        poc = result["finding_presentations"][0]["poc"]

        self.assertEqual(len(poc["requests"]), 7)
        self.assertEqual(
            [method["state"] for method in poc["detection_methods"]],
            ["confirmed", "negative", "skipped"],
        )
        self.assertEqual(
            poc["detection_methods"][0]["summary"],
            "2/3 pairs confirmed",
        )
        self.assertIn("detection_methods", poc["observed_evidence"])

    def test_legacy_dvwa_row_count_presentation_is_preserved(self):
        dvwa_validation = {
            "status": "confirmed",
            "confidence": 1.0,
            "validator": "dvwa_sqli_low",
            "method": "boolean-based SQLi, id parameter",
            "evidence": {
                "baseline_result_count": 1,
                "injected_result_count": 5,
                "baseline_length": 4500,
                "injected_length": 4800,
            },
        }
        result = self.decorate(self.sqli, dvwa_validation)
        poc = result["finding_presentations"][0]["poc"]

        self.assertIn("database-result records", poc["interpretation"])
        self.assertEqual(poc["observed_evidence"]["baseline_result_count"], 1)
        self.assertEqual(poc["observed_evidence"]["injected_result_count"], 5)

    def test_risk_rating_is_deterministic(self):
        first = self.decorate(self.sqli, self.sqli_validation)
        second = self.decorate(self.sqli, self.sqli_validation)
        self.assertEqual(
            first["finding_presentations"][0]["risk"],
            second["finding_presentations"][0]["risk"],
        )

    def test_command_execution_poc_is_explicitly_synthetic_and_critical(self):
        command = finding(
            "finding-command",
            "command_execution",
            endpoint="/controlled/command",
            method="POST",
            parameter="diagnostic",
            location="form",
            technique_id="T1059.004",
            technique_name="Command and Scripting Interpreter: Unix Shell",
            tactic="Execution",
            requires=["application_compromise"],
            provides=["command_execution"],
            severity="critical",
        )
        command_validation = validation(
            "synthetic-unix-shell-marker-differential",
            {
                "baseline_status": 200,
                "probe_status": 200,
                "control_status": 200,
                "baseline_marker_present": False,
                "execution_marker_present": True,
                "control_marker_present": False,
                "decision": "confirmed",
                "reason": "unique_synthetic_execution_marker_observed",
            },
        )
        result = self.decorate(command, command_validation)
        presentation = result["finding_presentations"][0]
        serialized_requests = json.dumps(presentation["poc"]["requests"])

        for fixed_token in (
            BASELINE_DIAGNOSTIC_TOKEN,
            EXECUTION_PROBE_TOKEN,
            CONTROL_PROBE_TOKEN,
        ):
            self.assertIn(fixed_token, serialized_requests)
        self.assertEqual(presentation["risk"]["rating"], "Critical")
        self.assertIn("No arbitrary operating-system command", presentation["poc"]["safety_note"])
        self.assertIn("Potential impact", presentation["risk"]["scope_note"])

    def test_unmapped_xss_and_disclosure_keep_honest_mitre_and_cia_output(self):
        cases = (
            ("reflected_xss", "/reflect", "Moderate"),
            ("information_disclosure", "/.env", "High"),
        )
        for vulnerability_type, endpoint, confidentiality in cases:
            with self.subTest(vulnerability_type=vulnerability_type):
                item = finding(
                    f"finding-{vulnerability_type}",
                    vulnerability_type,
                    endpoint=endpoint,
                    technique_id=None,
                    provides=["potential_information_exposure"] if vulnerability_type == "information_disclosure" else [],
                )
                result = self.decorate(item, validation("existing deterministic method", {"decision": "confirmed"}))
                presentation = result["finding_presentations"][0]
                self.assertIsNone(presentation["mitre"])
                self.assertEqual(presentation["risk"]["cia"]["confidentiality"], confidentiality)

    def test_context_aware_xss_evidence_renders_probe_results(self):
        xss = finding(
            "finding-context-xss",
            "reflected_xss",
            endpoint="/reflect",
            technique_id=None,
        )
        xss_validation = {
            "status": "confirmed",
            "confidence": 0.91,
            "validator": "generic_http_reflected_xss",
            "method": "context-aware inert reflection analysis",
            "evidence": {
                "reflection_observed": True,
                "waf_or_filter_interference": False,
                "strong_structural_signals": [{
                    "probe_name": "inert_element",
                    "signal": "controlled_inert_html_element_created",
                    "reflection_context": "html_attribute_value",
                }],
                "probes": {
                    "inert_element": {
                        "state": "completed",
                        "verdict": "strong_structural_evidence",
                        "reason": "controlled_inert_html_element_created",
                        "structural_boundary_changed": True,
                        "structural_signal": "controlled_inert_html_element_created",
                        "reflection_context": "html_attribute_value",
                        "encoding_fingerprint": "raw_unencoded",
                    },
                    "attribute_boundary": {
                        "state": "completed",
                        "verdict": "sanitized_or_non_structural",
                        "reason": "no_structural_boundary_control",
                        "structural_boundary_changed": False,
                        "reflection_context": "html_text_node",
                        "encoding_fingerprint": "html_entity_encoded",
                    },
                },
                "decision": "confirmed",
                "reason": "controlled_structural_breakout_confirmed",
            },
        }
        presentation = self.decorate(xss, xss_validation)[
            "finding_presentations"
        ][0]

        self.assertEqual(
            presentation["poc"]["verification_method"],
            "Context-aware inert reflection analysis",
        )
        self.assertEqual(
            [item["state"] for item in presentation["poc"]["detection_methods"]],
            ["confirmed", "rejected"],
        )
        self.assertIn("probes", presentation["poc"]["observed_evidence"])
        self.assertIn("No browser", presentation["poc"]["safety_note"])
        self.assertIsNone(presentation["mitre"])

    def test_safe_xss_reflection_is_described_without_claiming_confirmation(self):
        xss = finding(
            "finding-safe-xss",
            "reflected_xss",
            endpoint="/reflect",
            technique_id=None,
        )
        xss["validation_status"] = "rejected"
        xss_validation = {
            "status": "rejected",
            "confidence": 0.9,
            "validator": "generic_http_reflected_xss",
            "method": "context-aware inert reflection analysis",
            "evidence": {
                "reflection_observed": True,
                "strong_structural_signals": [],
                "probes": {},
                "decision": "rejected",
                "reason": "safe_encoding_or_sanitization_observed",
            },
        }

        presentation = self.decorate(xss, xss_validation)[
            "finding_presentations"
        ][0]

        self.assertFalse(presentation["poc"]["available"])
        self.assertIn(
            "did not establish unsafe structural control",
            presentation["poc"]["interpretation"],
        )
        self.assertEqual(presentation["risk"]["rating"], "Not rated")

    def test_attack_flow_explains_capability_dependencies_and_cumulative_risk(self):
        command = finding(
            "finding-command",
            "command_execution",
            endpoint="/controlled/command",
            method="POST",
            parameter="diagnostic",
            location="form",
            technique_id="T1059.004",
            technique_name="Command and Scripting Interpreter: Unix Shell",
            tactic="Execution",
            requires=["application_compromise"],
            provides=["command_execution"],
            severity="critical",
        )
        command_validation = validation(
            "synthetic-unix-shell-marker-differential",
            {"decision": "confirmed", "execution_marker_present": True},
        )
        chain = {
            "chain_id": "chain-sqli-command",
            "status": "confirmed",
            "confidence": 0.9,
            "steps": [
                {
                    "step_number": 1,
                    "finding_id": "finding-service",
                    "vulnerability_type": "service_scan",
                    "provides": ["discovered_services"],
                },
                {
                    "step_number": 2,
                    **self.sqli,
                },
                {
                    "step_number": 3,
                    **command,
                },
            ],
        }
        result = decorate_pipeline_response(
            {
                "findings": [self.sqli, command],
                "validations": [self.sqli_validation, command_validation],
                "chains": [chain],
            },
            controlled_lab=True,
        )
        path = result["attack_flow"]["multi_stage_paths"][0]

        self.assertEqual([item["capability"] for item in path["dependencies"]], [
            "discovered_services",
            "application_compromise",
        ])
        self.assertEqual(path["cumulative_risk"], "Critical")
        self.assertEqual(path["cumulative_capabilities"], [
            "discovered_services",
            "application_compromise",
            "possible_database_access",
            "command_execution",
        ])
        self.assertTrue(path["potential_business_impact"])

    def test_single_action_chain_is_presented_as_standalone(self):
        xss = finding(
            "finding-xss",
            "reflected_xss",
            endpoint="/reflect",
            technique_id=None,
        )
        xss_validation = validation(
            "inert-html-reflection",
            {"marker_reflected": True, "decision": "confirmed"},
        )
        result = self.decorate(
            xss,
            xss_validation,
            chains=[{
                "chain_id": "chain-xss",
                "status": "confirmed",
                "steps": [{"step_number": 1, **xss}],
            }],
        )

        self.assertEqual(result["attack_flow"]["multi_stage_paths"], [])
        standalone = result["attack_flow"]["standalone_findings"]
        self.assertEqual(len(standalone), 1)
        self.assertIn("standalone", standalone[0]["impact_summary"])

    def test_presentation_layer_contains_no_execution_primitive(self):
        source = (Path(__file__).resolve().parents[1] / "app" / "presentation" / "security.py").read_text()
        for forbidden in ("os.system", "subprocess", "shell=True", "eval(", "exec("):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
