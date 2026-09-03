import os
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from app.api.readiness import get_optional_readiness_db
from app.main import app
from tests.db_utils import make_test_session_factory


STATIC_DIR = Path(__file__).resolve().parents[1] / "app" / "static"


class ReadinessApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine, cls.factory = make_test_session_factory()

        def override_readiness_db():
            with cls.factory() as session:
                yield session

        app.dependency_overrides[get_optional_readiness_db] = override_readiness_db
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        app.dependency_overrides.pop(get_optional_readiness_db, None)
        cls.engine.dispose()

    def test_readiness_reports_backend_database_and_configured_scanners(self):
        with patch.dict(os.environ, {
            "RECON_NMAP_PATH": "/bin/sh",
            "RECON_NUCLEI_PATH": "/bin/sh",
        }):
            response = self.client.get("/api/readiness")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["status"], "ready")
        self.assertEqual(set(body["components"]), {
            "backend", "postgresql", "nmap", "nuclei",
        })
        self.assertTrue(all(
            set(component) == {"status"}
            for component in body["components"].values()
        ))

    def test_readiness_reports_missing_scanners_without_leaking_paths(self):
        with patch.dict(os.environ, {
            "RECON_NMAP_PATH": "",
            "RECON_NUCLEI_PATH": "/definitely/not/a/scanner",
        }):
            response = self.client.get("/api/readiness")
        body = response.json()
        self.assertEqual(body["status"], "degraded")
        self.assertEqual(body["components"]["nmap"]["status"], "not_configured")
        self.assertEqual(body["components"]["nuclei"]["status"], "unavailable")
        serialized = response.text
        self.assertNotIn("/definitely/not/a/scanner", serialized)
        self.assertNotIn("DATABASE_URL", serialized)

    def test_existing_health_contract_is_unchanged(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "healthy"})


class PrototypeStaticUiTests(unittest.TestCase):
    def test_existing_static_page_contains_real_and_controlled_workflows(self):
        html = (STATIC_DIR / "index.html").read_text()
        self.assertIn('id="scan-form"', html)
        self.assertIn('id="demo-form"', html)
        self.assertIn("START SCAN", html)
        self.assertIn("Controlled Lab Demonstration", html)
        self.assertIn("View raw response", html)
        self.assertIn("T1059.004", html)
        self.assertIn("ATTACK FLOW", html)
        self.assertIn("<th>Risk</th><th>PoC</th>", html)

    def test_javascript_wires_real_scan_harness_retrieval_and_summary(self):
        javascript = (STATIC_DIR / "app.js").read_text()
        for contract in (
            'postJson("/api/scans/run"',
            'postJson("/api/test-harness/run"',
            'requestJson("/api/readiness"',
            "function computeSummary(data)",
            "function renderChains(data)",
            "VIEW PROOF OF CONCEPT",
            "Business-risk rationale",
            "Controlled request shapes",
            'requestJson(`/api/scans/${encoded}/findings`)',
            'requestJson(`/api/scans/${encoded}/chains`)',
        ):
            with self.subTest(contract=contract):
                self.assertIn(contract, javascript)

    def test_progress_copy_does_not_claim_streaming_events(self):
        html = (STATIC_DIR / "index.html").read_text()
        self.assertIn("Stage-level events are not streamed yet", html)
        for stage in (
            "Target validation",
            "Reconnaissance",
            "Service discovery",
            "Vulnerability discovery",
            "Active validation",
            "MITRE mapping",
            "Attack-path analysis",
            "Persistence",
        ):
            with self.subTest(stage=stage):
                self.assertIn(f'"{stage}"', (STATIC_DIR / "app.js").read_text())


if __name__ == "__main__":
    unittest.main()
