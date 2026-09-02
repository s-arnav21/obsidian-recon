"""Real-loopback validation persisted into an isolated database."""

from __future__ import annotations

import unittest
from urllib.parse import urlsplit

from app.attack_chain.engine import build_attack_paths
from app.attack_chain.mitre_mapping import enrich_finding_model
from app.db.repository import PersistenceRepository
from app.models.finding import Finding, ValidationStatus
from app.scanning.normalizer import HttpScannerRecord, normalize_http_sqli_record
from app.services.generic_local_web_validation import ScopedLoopbackHttpClient
from app.services.persistence import (
    ServicePersistenceRecord,
    ValidationPersistenceRecord,
    persist_validation_run,
)
from app.validation.dispatcher import apply_validation_result, dispatch
from tests.db_utils import make_test_session_factory
from tests.integration_apps.vulnerable_web_app import LocalVulnerableAppServer


class LiveValidationPersistenceIntegrationTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.server = LocalVulnerableAppServer()
        cls.origin = cls.server.start()
        cls.addClassCleanup(cls.server.stop)

    def setUp(self):
        self.engine, factory = make_test_session_factory()
        self.session = factory()

    def tearDown(self):
        self.session.close()
        self.engine.dispose()

    def test_existing_sqli_pipeline_persists_and_retrieves_by_scan(self):
        scan_id = "scan-live-persistence"
        asset_id = "asset-live-persistence"
        parsed = urlsplit(self.origin)
        candidate = normalize_http_sqli_record(HttpScannerRecord(
            record_id="finding-live-persisted-sqli",
            scan_id=scan_id,
            asset_id=asset_id,
            target=self.origin,
            endpoint="/items",
            http_method="GET",
            parameter_name="id",
            parameter_location="query",
            scanner_name="local_integration_fixture",
            scanner_template_id="local-fixture-sqli-check",
            vulnerability_type="sql_injection",
            severity="high",
            evidence={"fixture_endpoint": True},
        ))

        with ScopedLoopbackHttpClient(self.origin) as client:
            validation = dispatch(candidate, session=client)
        validated = apply_validation_result(candidate, validation)
        enriched = enrich_finding_model(validated)
        reachability = Finding(
            finding_id="finding-live-persisted-reachability",
            scan_id=scan_id,
            asset_id=asset_id,
            target=self.origin,
            host=parsed.hostname or "127.0.0.1",
            port=parsed.port,
            protocol=parsed.scheme,
            endpoint="/health",
            source="local_integration_fixture",
            template_id="local-fixture-health-check",
            vulnerability_type="service_scan",
            validation_status=ValidationStatus.CONFIRMED,
            validation_confidence=1.0,
        )
        chains = build_attack_paths([reachability, enriched])

        persisted_scan_id = persist_validation_run(
            self.session,
            target_url=self.origin,
            authorized=True,
            findings=[reachability, candidate],
            validations=[ValidationPersistenceRecord(
                candidate=candidate,
                validation=validation,
                enriched=enriched,
            )],
            attack_chains=chains,
            services=[ServicePersistenceRecord(
                service_id="service-live-persisted-http",
                asset_id=asset_id,
                port=parsed.port,
                protocol="tcp",
                service_name="http",
                state="open",
                source="local_integration_fixture",
            )],
        )

        repository = PersistenceRepository(self.session)
        scan = repository.get_scan(persisted_scan_id)
        findings = repository.list_findings_for_scan(persisted_scan_id)
        attack_chains = repository.list_attack_chains_for_scan(persisted_scan_id)
        stored_sqli = next(
            finding for finding in findings
            if finding.id == candidate.finding_id
        )

        self.assertEqual(validation.status, ValidationStatus.CONFIRMED)
        self.assertEqual(enriched.mitre_technique_id, "T1190")
        self.assertEqual(scan.status, "completed")
        self.assertIsNotNone(scan.completed_at)
        self.assertEqual(scan.id, scan_id)
        self.assertEqual(scan.assets[0].id, asset_id)
        self.assertEqual(scan.services[0].id, "service-live-persisted-http")
        self.assertEqual(stored_sqli.status, ValidationStatus.DETECTED)
        self.assertEqual(
            stored_sqli.validations[0].status,
            ValidationStatus.CONFIRMED,
        )
        self.assertEqual(
            stored_sqli.validations[0].evidence_records[0].evidence_json[
                "decision"
            ],
            "confirmed",
        )
        self.assertEqual(
            stored_sqli.mitre_mappings[0].technique_id,
            "T1190",
        )
        self.assertEqual(len(attack_chains), 1)
        self.assertEqual(
            [step.finding_id for step in attack_chains[0].steps],
            [reachability.finding_id, candidate.finding_id],
        )
        self.assertEqual(attack_chains[0].steps[1].technique_id, "T1190")
        self.assertTrue(all(
            finding.scan_id == persisted_scan_id for finding in findings
        ))


if __name__ == "__main__":
    unittest.main()
