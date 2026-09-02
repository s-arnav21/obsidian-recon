"""API tests for persisted scan creation and retrieval."""

import unittest

from fastapi.testclient import TestClient

from app.db.session import get_db
from app.main import app
from tests.db_utils import make_test_session_factory


class ScanPersistenceApiTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.engine, cls.factory = make_test_session_factory()

        def override_get_db():
            session = cls.factory()
            try:
                yield session
            finally:
                session.close()

        app.dependency_overrides[get_db] = override_get_db
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        app.dependency_overrides.pop(get_db, None)
        cls.engine.dispose()

    def test_create_and_fetch_scan(self):
        response = self.client.post(
            "/api/scans",
            json={
                "target_url": "http://127.0.0.1:8090",
                "authorized": True,
            },
        )
        self.assertEqual(response.status_code, 200)
        created = response.json()
        self.assertTrue(created["id"].startswith("scan-"))
        self.assertEqual(created["status"], "created")
        self.assertTrue(created["authorized"])

        fetched = self.client.get(f"/api/scans/{created['id']}")
        self.assertEqual(fetched.status_code, 200)
        self.assertEqual(fetched.json(), created)

        findings = self.client.get(f"/api/scans/{created['id']}/findings")
        chains = self.client.get(f"/api/scans/{created['id']}/chains")
        self.assertEqual(findings.json(), [])
        self.assertEqual(chains.json(), [])

    def test_missing_scan_returns_404(self):
        for suffix in ("", "/findings", "/chains"):
            with self.subTest(suffix=suffix):
                response = self.client.get(f"/api/scans/missing{suffix}")
                self.assertEqual(response.status_code, 404)

    def test_create_scan_rejects_extra_fields(self):
        response = self.client.post(
            "/api/scans",
            json={
                "target_url": "http://127.0.0.1:8090",
                "authorized": True,
                "command": "not-accepted",
            },
        )
        self.assertEqual(response.status_code, 422)


if __name__ == "__main__":
    unittest.main()
