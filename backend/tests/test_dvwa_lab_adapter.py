"""Tests for the isolated DVWA development-lab session adapter."""

import os
import unittest
from unittest.mock import patch

import httpx

from app.integrations.labs.dvwa import (
    DVWALabAdapter,
    DVWALabConfig,
    DVWALabConfigurationError,
    DVWALabConnectionError,
    DVWALabSetupError,
)


class FakeResponse:
    def __init__(self, text="", url="http://127.0.0.1:8080/index.php"):
        self.text = text
        self.url = url

    def raise_for_status(self):
        return None


class FakeClient:
    def __init__(self, *, login_failed=False, setup_incomplete=False):
        self.login_failed = login_failed
        self.setup_incomplete = setup_incomplete
        self.cookies = httpx.Cookies()
        self.post_data = None
        self.closed = False

    def get(self, url):
        return FakeResponse(
            '<input type="hidden" name="user_token" value="test-token">',
            url,
        )

    def post(self, url, data):
        self.post_data = data
        if self.setup_incomplete:
            return FakeResponse(
                "Database setup",
                "http://127.0.0.1:8080/setup.php",
            )
        if self.login_failed:
            return FakeResponse("Login failed", url)
        return FakeResponse("Welcome", "http://127.0.0.1:8080/index.php")

    def close(self):
        self.closed = True


class TestDVWALabAdapter(unittest.TestCase):

    def test_missing_environment_configuration_fails_clearly(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(
                DVWALabConfigurationError,
                "DVWA_BASE_URL",
            ):
                DVWALabConfig.from_environment()

    def test_adapter_logs_in_and_sets_low_security_cookie(self):
        client = FakeClient()
        adapter = DVWALabAdapter(
            DVWALabConfig(
                base_url="http://127.0.0.1:8080",
                username="fixture-user",
                password="fixture-password",
            ),
            client_factory=lambda **kwargs: client,
        )

        with adapter.session() as prepared:
            self.assertIs(prepared, client)
            self.assertEqual(client.post_data["user_token"], "test-token")
            self.assertEqual(client.cookies.get("security"), "low")

        self.assertTrue(client.closed)

    def test_login_failure_is_reported_without_exposing_credentials(self):
        client = FakeClient(login_failed=True)
        adapter = DVWALabAdapter(
            DVWALabConfig(
                base_url="http://127.0.0.1:8080",
                username="fixture-user",
                password="fixture-password",
            ),
            client_factory=lambda **kwargs: client,
        )

        with self.assertRaisesRegex(DVWALabSetupError, "login failed"):
            with adapter.session():
                pass

    def test_connection_failure_is_wrapped_cleanly(self):
        class OfflineClient(FakeClient):
            def get(self, url):
                request = httpx.Request("GET", url)
                raise httpx.ConnectError("offline", request=request)

        adapter = DVWALabAdapter(
            DVWALabConfig(
                base_url="http://127.0.0.1:8080",
                username="fixture-user",
                password="fixture-password",
            ),
            client_factory=lambda **kwargs: OfflineClient(),
        )

        with self.assertRaisesRegex(
            DVWALabConnectionError,
            "configured DVWA lab request",
        ):
            with adapter.session():
                pass

    def test_incomplete_dvwa_database_setup_is_reported(self):
        client = FakeClient(setup_incomplete=True)
        adapter = DVWALabAdapter(
            DVWALabConfig(
                base_url="http://127.0.0.1:8080",
                username="fixture-user",
                password="fixture-password",
            ),
            client_factory=lambda **kwargs: client,
        )

        with self.assertRaisesRegex(DVWALabSetupError, "setup is incomplete"):
            with adapter.session():
                pass


if __name__ == "__main__":
    unittest.main()
