"""Real-HTTP integration tests for the local multi-validator pipeline."""

from __future__ import annotations

import unittest
from dataclasses import replace
from urllib.parse import urlsplit

from app.models.finding import ValidationStatus
from app.scanning.normalizer import (
    ExposedResourceScannerRecord,
    normalize_exposed_resource_record,
)
from app.validation.dispatcher import dispatch
from app.validation.command_execution import (
    BASELINE_DIAGNOSTIC_TOKEN,
    CONTROL_PROBE_TOKEN,
    EXECUTION_MARKER,
    EXECUTION_PROBE_TOKEN,
)
from tests.integration_apps.local_multi_validator_pipeline import (
    ScopedLoopbackHttpClient,
    TargetScopeError,
    run_local_multi_validator_pipeline,
)
from tests.integration_apps.vulnerable_web_app import (
    SYNTHETIC_EXPOSURE_BODY,
    LocalVulnerableAppServer,
)


class TestLocalVulnerableAppLifecycle(unittest.TestCase):

    def test_local_vulnerable_app_starts_and_stops(self):
        server = LocalVulnerableAppServer()
        try:
            origin = server.start()
            self.assertTrue(server.is_running)
            self.assertEqual(urlsplit(origin).hostname, "127.0.0.1")
            with ScopedLoopbackHttpClient(origin) as client:
                response = client.get(f"{origin}/health")
            self.assertEqual(response.status_code, 200)
        finally:
            server.stop()
        self.assertFalse(server.is_running)


class TestLiveMultiValidatorIntegration(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.server = LocalVulnerableAppServer()
        cls.origin = cls.server.start()
        cls.addClassCleanup(cls.server.stop)
        with ScopedLoopbackHttpClient(cls.origin) as client:
            cls.pipeline_result = run_local_multi_validator_pipeline(
                cls.origin,
                client,
            )
            cls.requested_urls = list(client.requested_urls)

    def validation(self, name):
        return self.pipeline_result["validations"][name]

    def test_sqli_endpoint_has_deterministic_boolean_behavior(self):
        with ScopedLoopbackHttpClient(self.origin) as client:
            baseline = client.get(f"{self.origin}/items", params={"id": "1"})
            true_result = client.get(
                f"{self.origin}/items",
                params={"id": "1 AND 1=1"},
            )
            false_result = client.get(
                f"{self.origin}/items",
                params={"id": "1 AND 1=2"},
            )
        self.assertEqual(baseline.text, true_result.text)
        self.assertNotEqual(baseline.text, false_result.text)

    def test_xss_endpoint_reflects_only_supplied_test_input(self):
        marker = "local-integration-reflection-marker"
        with ScopedLoopbackHttpClient(self.origin) as client:
            response = client.get(
                f"{self.origin}/search",
                params={"q": marker},
            )
        self.assertEqual(
            response.text,
            f"<html><body>{marker}</body></html>",
        )

    def test_exposure_endpoint_uses_only_static_synthetic_data(self):
        with ScopedLoopbackHttpClient(self.origin) as client:
            response = client.get(f"{self.origin}/debug-config")
        self.assertEqual(response.text, SYNTHETIC_EXPOSURE_BODY)
        self.assertIn("FAKE-NOT-A-REAL-SECRET", response.text)

    def test_command_endpoint_recognizes_only_fixed_synthetic_probe(self):
        with ScopedLoopbackHttpClient(self.origin) as client:
            baseline = client.post(
                f"{self.origin}/admin/diagnostics",
                data={"diagnostic_token": BASELINE_DIAGNOSTIC_TOKEN},
            )
            probe = client.post(
                f"{self.origin}/admin/diagnostics",
                data={"diagnostic_token": EXECUTION_PROBE_TOKEN},
            )
            control = client.post(
                f"{self.origin}/admin/diagnostics",
                data={"diagnostic_token": CONTROL_PROBE_TOKEN},
            )
            arbitrary = client.post(
                f"{self.origin}/admin/diagnostics",
                data={"diagnostic_token": "caller-controlled-value"},
            )

        self.assertNotIn(EXECUTION_MARKER, baseline.text)
        self.assertIn(EXECUTION_MARKER, probe.text)
        self.assertNotIn(EXECUTION_MARKER, control.text)
        self.assertNotIn(EXECUTION_MARKER, arbitrary.text)

    def test_all_records_normalize_with_independent_routing(self):
        expected = {
            "sql_injection": (
                "sql_injection",
                "generic-http-sqli",
                "local-fixture-sqli-check",
            ),
            "reflected_xss": (
                "reflected_xss",
                "generic-http-reflected-xss",
                "local-fixture-reflected-xss-check",
            ),
            "command_execution": (
                "command_execution",
                "generic-http-command-execution",
                "local-fixture-command-execution-check",
            ),
            "exposed_resource": (
                "information_disclosure",
                "generic-http-exposed-resource",
                "local-fixture-exposure-check",
            ),
        }
        for name, expected_values in expected.items():
            finding = self.validation(name)["finding"]
            with self.subTest(name=name):
                self.assertEqual(
                    (
                        finding["vulnerability_type"],
                        finding["validator_id"],
                        finding["template_id"],
                    ),
                    expected_values,
                )
                self.assertEqual(finding["scan_id"], self.pipeline_result["scan_id"])
                self.assertEqual(finding["asset_id"], self.pipeline_result["asset_id"])

    def test_live_sqli_confirms_and_maps_to_t1190(self):
        validation = self.validation("sql_injection")
        self.assertEqual(
            validation["validation_result"]["validator"],
            "generic_http_sqli",
        )
        self.assertEqual(
            validation["validation_result"]["status"],
            ValidationStatus.CONFIRMED,
        )
        self.assertEqual(validation["finding"]["mitre_technique_id"], "T1190")

    def test_live_xss_confirms_without_invented_mapping(self):
        validation = self.validation("reflected_xss")
        self.assertEqual(
            validation["validation_result"]["validator"],
            "generic_http_reflected_xss",
        )
        self.assertEqual(
            validation["validation_result"]["status"],
            ValidationStatus.CONFIRMED,
        )
        self.assertIsNone(validation["finding"]["mitre_technique_id"])
        self.assertEqual(validation["finding"]["provides"], [])

    def test_live_exposure_confirms_with_conservative_capability(self):
        validation = self.validation("exposed_resource")
        self.assertEqual(
            validation["validation_result"]["validator"],
            "generic_http_exposed_resource",
        )
        self.assertEqual(
            validation["validation_result"]["status"],
            ValidationStatus.CONFIRMED,
        )
        self.assertIsNone(validation["finding"]["mitre_technique_id"])
        self.assertEqual(
            validation["finding"]["provides"],
            ["potential_information_exposure"],
        )

    def test_live_command_execution_confirms_and_maps_to_t1059_004(self):
        validation = self.validation("command_execution")
        self.assertEqual(
            validation["validation_result"]["validator"],
            "generic_http_command_execution",
        )
        self.assertEqual(
            validation["validation_result"]["status"],
            ValidationStatus.CONFIRMED,
        )
        self.assertEqual(
            validation["finding"]["mitre_technique_id"],
            "T1059.004",
        )
        self.assertEqual(
            validation["finding"]["requires_any"],
            ["application_compromise"],
        )
        self.assertEqual(
            validation["finding"]["provides"],
            ["command_execution"],
        )

    def test_attack_chain_contains_t1190_without_fabricated_mappings(self):
        chains = self.pipeline_result["chains"]
        self.assertEqual(len(chains), 3)
        t1190_chains = [
            chain for chain in chains
            if "T1190" in chain["mitre_techniques"]
        ]
        self.assertEqual(len(t1190_chains), 1)
        self.assertEqual(t1190_chains[0]["status"], "confirmed")
        self.assertEqual(
            t1190_chains[0]["mitre_techniques"],
            ["T1190", "T1059.004"],
        )
        self.assertIn(
            self.validation("sql_injection")["finding"]["finding_id"],
            [step["finding_id"] for step in t1190_chains[0]["steps"]],
        )
        reachability_id = next(
            step["finding_id"]
            for chain in chains
            for step in chain["steps"]
            if step["vulnerability_type"] == "service_scan"
        )
        self.assertEqual(
            {
                tuple(step["finding_id"] for step in chain["steps"])
                for chain in chains
            },
            {
                (self.validation("exposed_resource")["finding"]["finding_id"],),
                (self.validation("reflected_xss")["finding"]["finding_id"],),
                (
                    reachability_id,
                    self.validation("sql_injection")["finding"]["finding_id"],
                    self.validation("command_execution")["finding"][
                        "finding_id"
                    ],
                ),
            },
        )
        non_mapped_ids = {
            self.validation("reflected_xss")["finding"]["finding_id"],
            self.validation("exposed_resource")["finding"]["finding_id"],
        }
        for chain in chains:
            for step in chain["steps"]:
                if step["finding_id"] in non_mapped_ids:
                    self.assertIsNone(step["mitre_technique_id"])

    def test_every_pipeline_request_stays_on_approved_origin(self):
        approved = (
            urlsplit(self.origin).scheme,
            urlsplit(self.origin).hostname,
            urlsplit(self.origin).port,
        )
        self.assertGreaterEqual(len(self.requested_urls), 10)
        for requested_url in self.requested_urls:
            parsed = urlsplit(requested_url)
            self.assertEqual(
                (parsed.scheme, parsed.hostname, parsed.port),
                approved,
            )
        self.assertEqual(
            {urlsplit(url).path for url in self.requested_urls},
            {
                "/health",
                "/items",
                "/search",
                "/debug-config",
                "/admin/diagnostics",
            },
        )

    def test_cross_origin_finding_is_rejected_without_contact(self):
        record = ExposedResourceScannerRecord(
            record_id="finding-cross-origin",
            scan_id="scan-cross-origin",
            asset_id="asset-cross-origin",
            target=self.origin,
            endpoint="/debug-config",
            scanner_name="local_integration_fixture",
            scanner_template_id="local-fixture-exposure-check",
            vulnerability_type="information_disclosure",
        )
        finding = replace(
            normalize_exposed_resource_record(record),
            endpoint="http://external.invalid/debug-config",
        )
        with ScopedLoopbackHttpClient(self.origin) as client:
            result = dispatch(finding, session=client)
            self.assertEqual(client.requested_urls, [])

        self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
        self.assertEqual(result.evidence["reason"], "endpoint_origin_mismatch")

    def test_scoped_client_rejects_non_loopback_origin_before_request(self):
        with self.assertRaisesRegex(TargetScopeError, "loopback"):
            ScopedLoopbackHttpClient("http://external.invalid")


if __name__ == "__main__":
    unittest.main()
