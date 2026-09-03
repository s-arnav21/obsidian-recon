import json
import unittest

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.api.recon import _configured_pipeline
from app.db.models import (
    AssetORM,
    AttackChainORM,
    EvidenceORM,
    FindingORM,
    MitreMappingORM,
    ScanORM,
    ServiceORM,
    ValidationORM,
)
from app.db.repository import PersistenceRepository
from app.db.session import get_db
from app.main import app
from app.scanning.models import ScannerCandidateRecord, ServiceObservation
from app.scanning.nmap import NmapScanner
from app.scanning.nuclei import NucleiScanner
from app.scanning.tool_runner import ScannerToolTimeoutError
from app.services.recon_pipeline import ReconPipeline
from tests.db_utils import make_test_session_factory
from tests.integration_apps.vulnerable_web_app import LocalVulnerableAppServer


class Response:
    def __init__(self, text="", status_code=200, headers=None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {"content-type": "text/html"}


class DeterministicScopedClient:
    def __init__(self, target, *, fail=False):
        self.target = target
        self.fail = fail

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return None

    def get(self, url, params=None):
        if self.fail:
            raise RuntimeError("synthetic discovery failure with secret-value")
        if params is None:
            return Response("local fixture")
        value = next(iter(params.values()))
        if value in {"1", "1 AND 1=1"}:
            return Response("available " + ("A" * 500))
        return Response("denied " + ("Z" * 500))

    def post(self, url, data=None):
        return Response("unsupported", 405)


class SyntheticNmap:
    def scan(self, target, *, asset_id):
        return [
            ServiceObservation(
                asset_id=asset_id,
                port=target.port,
                protocol="tcp",
                service_name="http",
                product="Synthetic Server",
                version="1.0",
                state="open",
                source="nmap",
            ),
            ServiceObservation(
                asset_id=asset_id,
                port=22,
                protocol="tcp",
                service_name="ssh",
                state="open",
                source="nmap",
            ),
        ]


class SyntheticNuclei:
    def __init__(self, *, include_command=False):
        self.include_command = include_command

    def scan(self, target, *, scan_id, asset_id):
        common = {
            "scan_id": scan_id,
            "asset_id": asset_id,
            "target": target.origin,
            "scanner_name": "nuclei",
            "severity": "high",
        }
        records = [ScannerCandidateRecord(
            record_id=f"candidate-{scan_id}-sqli",
            scanner_template_id="synthetic-sqli",
            vulnerability_type="sql_injection",
            endpoint="/items",
            http_method="GET",
            parameter_name="id",
            parameter_location="query",
            evidence={"scanner_detection": True},
            **common,
        )]
        if self.include_command:
            records.append(ScannerCandidateRecord(
                record_id=f"candidate-{scan_id}-command",
                scanner_template_id="generic-http-command-execution",
                vulnerability_type="command_execution",
                endpoint="/diagnostics",
                http_method="POST",
                parameter_name="command",
                parameter_location="form",
                **common,
            ))
        return records


class TimedOutNmap:
    def scan(self, target, *, asset_id):
        raise ScannerToolTimeoutError("scanner exceeded its configured timeout")


def pipeline(*, fail=False, include_command=False):
    return ReconPipeline(
        nmap_scanner=SyntheticNmap(),
        nuclei_scanner=SyntheticNuclei(include_command=include_command),
        http_client_factory=lambda target: DeterministicScopedClient(
            target,
            fail=fail,
        ),
    )


class ReconPipelinePersistenceTests(unittest.TestCase):
    def setUp(self):
        self.engine, self.factory = make_test_session_factory()

    def tearDown(self):
        self.engine.dispose()

    def test_recon_flows_through_validation_chains_and_persistence(self):
        with self.factory() as session:
            run = pipeline().run(
                target_url="http://127.0.0.1:8090",
                authorized=True,
                session=session,
            )
            self.assertEqual(run.validations[0].validation.status, "confirmed")
            self.assertEqual(
                run.validations[0].enriched.mitre_technique_id,
                "T1190",
            )
            self.assertTrue(run.chains)

            scan = PersistenceRepository(session).get_scan(run.scan_id)
            self.assertEqual(scan.status, "completed")
            self.assertTrue(scan.authorized)
            self.assertIsNotNone(scan.completed_at)
            self.assertEqual(len(scan.assets), 1)
            self.assertEqual(scan.assets[0].ip_address, "127.0.0.1")
            self.assertEqual(len(scan.services), 2)
            self.assertEqual(len(scan.findings), 2)

            candidate = next(
                finding for finding in scan.findings
                if finding.source == "nuclei"
            )
            self.assertEqual(candidate.status, "detected")
            self.assertEqual(len(candidate.validations), 1)
            self.assertEqual(candidate.validations[0].status, "confirmed")
            self.assertEqual(len(candidate.validations[0].evidence_records), 1)
            self.assertEqual(candidate.mitre_mappings[0].technique_id, "T1190")
            self.assertFalse(any(
                mapping.technique_id == "T1595"
                for finding in scan.findings
                for mapping in finding.mitre_mappings
            ))
            for chain in scan.attack_chains:
                numbers = [step.step_number for step in chain.steps]
                self.assertEqual(numbers, sorted(numbers))

    def test_command_candidate_is_persisted_as_manual_review(self):
        with self.factory() as session:
            run = pipeline(include_command=True).run(
                target_url="http://127.0.0.1:8090",
                authorized=True,
                session=session,
            )
            command = next(
                item for item in run.validations
                if item.candidate.vulnerability_type == "command_execution"
            )
            self.assertEqual(command.validation.status, "manual_review")
            self.assertEqual(command.validation.validator, "dispatcher_manual_review")

    def test_failure_marks_started_scan_failed_without_secret(self):
        with self.factory() as session:
            with self.assertRaises(RuntimeError):
                pipeline(fail=True).run(
                    target_url="http://127.0.0.1:8090",
                    authorized=True,
                    session=session,
                )
            scan = session.scalars(select(ScanORM)).one()
            self.assertEqual(scan.status, "failed")
            self.assertIsNotNone(scan.completed_at)
            self.assertNotIn("secret-value", scan.failure_reason)

    def test_scanner_timeout_marks_scan_failed_without_partial_outputs(self):
        recon = ReconPipeline(
            nmap_scanner=TimedOutNmap(),
            http_client_factory=DeterministicScopedClient,
        )
        with self.factory() as session:
            with self.assertRaises(ScannerToolTimeoutError):
                recon.run(
                    target_url="http://127.0.0.1:8090",
                    authorized=True,
                    session=session,
                )
            scan = session.scalars(select(ScanORM)).one()
            self.assertEqual(scan.status, "failed")
            self.assertEqual(len(scan.assets), 0)
            self.assertEqual(len(scan.services), 0)
            self.assertEqual(len(scan.findings), 0)

    def test_two_runs_are_isolated(self):
        with self.factory() as session:
            first = pipeline().run(
                target_url="http://127.0.0.1:8090",
                authorized=True,
                session=session,
            )
            second = pipeline().run(
                target_url="http://127.0.0.1:8090",
                authorized=True,
                session=session,
            )
            self.assertNotEqual(first.scan_id, second.scan_id)
            counts = session.execute(
                select(FindingORM.scan_id, func.count(FindingORM.id))
                .group_by(FindingORM.scan_id)
            ).all()
            self.assertEqual(dict(counts), {first.scan_id: 2, second.scan_id: 2})


class LiveReconPipelineIntegrationTests(unittest.TestCase):
    def test_synthetic_scanner_outputs_drive_real_local_http_validation(self):
        engine, factory = make_test_session_factory()
        server = LocalVulnerableAppServer()
        try:
            origin = server.start()
            port = int(origin.rsplit(":", 1)[1])
            nmap_output = (
                "<nmaprun><host><ports>"
                f'<port protocol="tcp" portid="{port}">'
                '<state state="open"/><service name="http" '
                'product="Synthetic Server" version="1.0"/></port>'
                "</ports></host></nmaprun>"
            )
            nuclei_output = json.dumps({
                "template-id": "synthetic-local-sqli",
                "matched-at": f"{origin}/items?id=1",
                "info": {
                    "name": "Controlled SQLi candidate",
                    "severity": "high",
                    "metadata": {
                        "obsidian-vulnerability-type": "sql_injection",
                        "obsidian-http-method": "GET",
                        "obsidian-parameter-name": "id",
                        "obsidian-parameter-location": "query",
                    },
                },
            })
            recon = ReconPipeline(
                nmap_scanner=NmapScanner(
                    "/synthetic/nmap",
                    runner=lambda arguments, **kwargs: nmap_output,
                ),
                nuclei_scanner=NucleiScanner(
                    "/synthetic/nuclei",
                    runner=lambda arguments, **kwargs: nuclei_output,
                ),
            )
            with factory() as session:
                run = recon.run(
                    target_url=origin,
                    authorized=True,
                    session=session,
                )
                self.assertEqual(run.validations[0].validation.status, "confirmed")
                self.assertEqual(
                    run.validations[0].enriched.mitre_technique_id,
                    "T1190",
                )
                self.assertTrue(run.chains)
                stored = PersistenceRepository(session).get_scan(run.scan_id)
                self.assertEqual(stored.status, "completed")
                self.assertEqual(len(stored.findings), 2)
                self.assertEqual(len(stored.services), 1)
        finally:
            server.stop()
            engine.dispose()


class ReconApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine, cls.factory = make_test_session_factory()

        def override_db():
            with cls.factory() as session:
                yield session

        app.dependency_overrides[get_db] = override_db
        app.dependency_overrides[_configured_pipeline] = pipeline
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(_configured_pipeline, None)
        cls.engine.dispose()

    def test_api_requires_authorization_and_local_scope(self):
        unauthorized = self.client.post("/api/scans/run", json={
            "target_url": "http://127.0.0.1:8090",
            "authorized": False,
        })
        self.assertEqual(unauthorized.status_code, 403)
        external = self.client.post("/api/scans/run", json={
            "target_url": "https://example.com",
            "authorized": True,
        })
        self.assertEqual(external.status_code, 400)

    def test_api_rejects_malformed_and_extra_input(self):
        malformed = self.client.post("/api/scans/run", json={
            "target_url": "not-a-url",
            "authorized": True,
        })
        self.assertEqual(malformed.status_code, 422)
        command = self.client.post("/api/scans/run", json={
            "target_url": "http://127.0.0.1:8090",
            "authorized": True,
            "command": "id",
        })
        self.assertEqual(command.status_code, 422)

    def test_api_returns_retrievable_scan(self):
        response = self.client.post("/api/scans/run", json={
            "target_url": "http://127.0.0.1:8090",
            "authorized": True,
        })
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "completed")
        self.assertEqual(body["findings"][0]["mitre_technique_id"], "T1190")
        scan_id = body["scan_id"]
        self.assertEqual(self.client.get(f"/api/scans/{scan_id}").status_code, 200)
        self.assertEqual(
            len(self.client.get(f"/api/scans/{scan_id}/findings").json()),
            2,
        )
        self.assertTrue(self.client.get(f"/api/scans/{scan_id}/chains").json())


if __name__ == "__main__":
    unittest.main()
