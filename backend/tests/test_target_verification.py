"""Deterministic DNS ownership verification and external-scope tests."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

import dns.exception
import dns.resolver
from fastapi.testclient import TestClient
from sqlalchemy import inspect, select

from app.api.recon import _configured_pipeline
from app.api.target_verifications import _verification_service
from app.db.models import ScanORM, TargetVerificationORM
from app.db.session import get_db
from app.main import app
from app.scanning.dns import BoundedDnsResolver, DnsLookupError
from app.scanning.http_discovery import ScopedReconHttpClient
from app.scanning.scope import (
    ReconScopeError,
    TargetVerificationRequiredError,
    authorize_target,
)
from app.services.recon_pipeline import ReconPipeline
from app.services.target_verification import TargetVerificationService
from tests.db_utils import make_test_session_factory


PUBLIC_V4 = "93.184.216.34"
PUBLIC_V6 = "2606:2800:220:1:248:1893:25c8:1946"


class FakeDns:
    def __init__(self):
        self.txt = {}
        self.addresses = {}
        self.txt_error = None
        self.txt_calls = []
        self.address_calls = []

    def resolve_txt(self, name):
        self.txt_calls.append(name)
        if self.txt_error is not None:
            raise self.txt_error
        return tuple(self.txt.get(name, ()))

    def resolve_addresses(self, hostname):
        self.address_calls.append(hostname)
        return tuple(self.addresses.get(hostname, (PUBLIC_V4,)))


class MutableClock:
    def __init__(self):
        self.value = datetime(2026, 9, 3, 12, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.value


class Response:
    status_code = 200
    text = "controlled response"
    headers = {"content-type": "text/html"}


class ControlledClient:
    def __init__(self, target):
        self.target = target

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return None

    def get(self, url, params=None, **kwargs):
        return Response()


class FakeTxtRecord:
    def __init__(self, *segments):
        self.strings = segments


class FakeAddressRecord:
    def __init__(self, address):
        self.address = address


class FakeUnderlyingResolver:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []
        self.timeout = None

    def resolve(self, name, record_type, **kwargs):
        self.calls.append((name, record_type, kwargs))
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


class BoundedDnsResolverTests(unittest.TestCase):
    def test_txt_segments_and_multiple_values_are_decoded(self):
        underlying = FakeUnderlyingResolver([[
            FakeTxtRecord(b"obsidian-recon-", b"verification=one"),
            FakeTxtRecord(b"unrelated=value"),
        ]])
        resolver = BoundedDnsResolver(resolver=underlying, attempts=1)
        self.assertEqual(
            resolver.resolve_txt("_obsidian-recon.app.example.com"),
            (
                "obsidian-recon-verification=one",
                "unrelated=value",
            ),
        )
        self.assertFalse(underlying.calls[0][2]["search"])
        self.assertEqual(underlying.calls[0][2]["lifetime"], 2.0)

    def test_nxdomain_and_no_answer_are_empty(self):
        for error in (dns.resolver.NXDOMAIN(), dns.resolver.NoAnswer()):
            with self.subTest(error=type(error).__name__):
                resolver = BoundedDnsResolver(
                    resolver=FakeUnderlyingResolver([error]),
                    attempts=1,
                )
                self.assertEqual(resolver.resolve_txt("missing.example"), ())

    def test_timeout_is_bounded_and_sanitized(self):
        underlying = FakeUnderlyingResolver([
            dns.exception.Timeout("resolver secret"),
            dns.exception.Timeout("resolver secret"),
        ])
        resolver = BoundedDnsResolver(resolver=underlying, attempts=2)
        with self.assertRaisesRegex(DnsLookupError, "^DNS lookup timed out$"):
            resolver.resolve_txt("_obsidian-recon.app.example.com")
        self.assertEqual(len(underlying.calls), 2)

    def test_malformed_txt_is_ignored(self):
        malformed = type("Malformed", (), {"strings": [b"\xff"]})()
        resolver = BoundedDnsResolver(
            resolver=FakeUnderlyingResolver([[malformed]]),
            attempts=1,
        )
        self.assertEqual(resolver.resolve_txt("record.example"), ())

    def test_address_lookup_collects_ipv4_and_ipv6(self):
        resolver = BoundedDnsResolver(
            resolver=FakeUnderlyingResolver([
                [FakeAddressRecord(PUBLIC_V4)],
                [FakeAddressRecord(PUBLIC_V6)],
            ]),
            attempts=1,
        )
        self.assertEqual(
            resolver.resolve_addresses("app.example.com"),
            (PUBLIC_V4, PUBLIC_V6),
        )


class TargetVerificationServiceTests(unittest.TestCase):
    def setUp(self):
        self.engine, self.factory = make_test_session_factory()
        self.dns = FakeDns()
        self.clock = MutableClock()
        self.service = TargetVerificationService(
            dns_resolver=self.dns,
            clock=self.clock,
        )

    def tearDown(self):
        self.engine.dispose()

    def create(self, session, origin="https://app.example.com"):
        return self.service.create_challenge(session, target_url=origin)

    def test_valid_challenge_is_canonical_persisted_and_pending(self):
        with self.factory() as session:
            view = self.create(session, "https://APP.example.com/")
            record = session.scalars(select(TargetVerificationORM)).one()
            self.assertEqual(view.canonical_origin, "https://app.example.com")
            self.assertEqual(view.status, "pending")
            self.assertEqual(
                view.txt_record_name,
                "_obsidian-recon.app.example.com",
            )
            self.assertTrue(view.txt_record_value.startswith(
                "obsidian-recon-verification="
            ))
            self.assertEqual(record.origin, view.canonical_origin)
            self.assertEqual(len(record.token_digest), 64)
            self.assertNotEqual(record.token_digest, record.challenge_token)
            self.assertEqual(
                record.expires_at.replace(tzinfo=timezone.utc),
                self.clock.value + timedelta(hours=24),
            )

    def test_secure_tokens_have_entropy_and_differ_between_challenges(self):
        with self.factory() as session:
            first = self.create(session, "https://one.example.com")
            second = self.create(session, "https://two.example.com")
            first_token = first.txt_record_value.split("=", 1)[1]
            second_token = second.txt_record_value.split("=", 1)[1]
            self.assertRegex(first_token, r"^[A-Za-z0-9_-]{32,}$")
            self.assertNotEqual(first_token, second_token)

    def test_invalid_targets_do_not_create_challenges(self):
        invalid = (
            "not-a-url",
            "https://user:password@app.example.com",
            "https://app.example.com/#fragment",
            "ftp://app.example.com",
            "http://app.example.com",
            "https://bad_host.example.com",
            "https://203.0.113.5",
            "http://127.0.0.1:8090",
        )
        with self.factory() as session:
            for target in invalid:
                with self.subTest(target=target), self.assertRaises(ReconScopeError):
                    self.create(session, target)
            self.assertEqual(
                session.scalar(select(TargetVerificationORM)),
                None,
            )

    def test_exact_matching_among_multiple_records_verifies_and_clears_token(self):
        with self.factory() as session:
            pending = self.create(session)
            self.dns.txt[pending.txt_record_name] = (
                "unrelated=value",
                pending.txt_record_value,
                "obsidian-recon-verification=wrong",
            )
            verified = self.service.verify_challenge(session, pending.id)
            record = session.get(TargetVerificationORM, pending.id)
            self.assertEqual(verified.status, "verified")
            self.assertIsNotNone(verified.verified_at)
            self.assertIsNone(verified.txt_record_value)
            self.assertIsNone(record.challenge_token)
            self.assertTrue(
                self.service.is_origin_verified(session, pending.canonical_origin)
            )

    def test_wrong_or_missing_record_is_not_verified(self):
        cases = (
            (("obsidian-recon-verification=wrong",), "record_mismatch"),
            ((), "record_not_found"),
        )
        for index, (values, expected_code) in enumerate(cases):
            with self.subTest(expected_code=expected_code), self.factory() as session:
                pending = self.create(
                    session,
                    f"https://wrong-{index}.example.com",
                )
                self.dns.txt[pending.txt_record_name] = values
                result = self.service.verify_challenge(session, pending.id)
                record = session.get(TargetVerificationORM, pending.id)
                self.assertEqual(result.status, "verification_failed")
                self.assertEqual(record.failure_code, expected_code)
                self.assertFalse(self.service.is_origin_verified(
                    session,
                    pending.canonical_origin,
                ))

    def test_dns_timeout_fails_without_leaking_resolver_details(self):
        with self.factory() as session:
            pending = self.create(session)
            self.dns.txt_error = DnsLookupError("secret resolver 10.0.0.1")
            result = self.service.verify_challenge(session, pending.id)
            self.assertEqual(result.status, "verification_failed")
            self.assertNotIn("secret", str(result.to_dict()))
            self.assertNotIn("10.0.0.1", str(result.to_dict()))

    def test_expired_challenge_is_rejected_and_regenerated(self):
        with self.factory() as session:
            first = self.create(session)
            self.clock.value += timedelta(hours=25)
            expired = self.service.verify_challenge(session, first.id)
            self.assertEqual(expired.status, "expired")
            self.assertIsNone(expired.txt_record_value)
            second = self.create(session)
            self.assertEqual(first.id, second.id)
            self.assertNotEqual(first.txt_record_value, second.txt_record_value)

    def test_repeated_pending_request_reuses_bounded_challenge(self):
        with self.factory() as session:
            first = self.create(session)
            second = self.create(session)
            self.assertEqual(first.id, second.id)
            self.assertEqual(
                session.query(TargetVerificationORM).count(),
                1,
            )

    def test_exact_origin_does_not_authorize_parent_sibling_or_other_port(self):
        with self.factory() as session:
            pending = self.create(session)
            self.dns.txt[pending.txt_record_name] = (pending.txt_record_value,)
            self.service.verify_challenge(session, pending.id)
            self.assertTrue(self.service.is_origin_verified(
                session,
                "https://app.example.com",
            ))
            for origin in (
                "https://example.com",
                "https://admin.example.com",
                "https://app.example.com:8443",
            ):
                with self.subTest(origin=origin):
                    self.assertFalse(
                        self.service.is_origin_verified(session, origin)
                    )

    def test_api_view_never_exposes_hash_or_database_fields(self):
        with self.factory() as session:
            body = self.create(session).to_dict()
            serialized_keys = set(body)
            self.assertNotIn("token_digest", serialized_keys)
            self.assertNotIn("challenge_token", serialized_keys)
            self.assertNotIn("failure_code", serialized_keys)


class ExternalTargetScopeTests(unittest.TestCase):
    def test_unverified_external_target_is_blocked_structurally(self):
        with self.assertRaises(TargetVerificationRequiredError) as context:
            authorize_target("https://app.example.com", authorized=True)
        self.assertEqual(context.exception.target.origin, "https://app.example.com")

    def test_verified_target_must_use_https(self):
        with self.assertRaisesRegex(ReconScopeError, "must use HTTPS"):
            authorize_target(
                "http://app.example.com",
                authorized=True,
                ownership_verified=True,
                address_resolver=lambda _host: (PUBLIC_V4,),
            )

    def test_private_loopback_link_local_and_reserved_addresses_are_blocked(self):
        unsafe = (
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "0.0.0.0",
            "224.0.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "ff02::1",
        )
        for address in unsafe:
            with self.subTest(address=address), self.assertRaisesRegex(
                ReconScopeError,
                "non-public",
            ):
                authorize_target(
                    "https://app.example.com",
                    authorized=True,
                    ownership_verified=True,
                    address_resolver=lambda _host, value=address: (value,),
                )

    def test_mixed_public_and_private_answers_are_blocked(self):
        with self.assertRaisesRegex(ReconScopeError, "non-public"):
            authorize_target(
                "https://app.example.com",
                authorized=True,
                ownership_verified=True,
                address_resolver=lambda _host: (PUBLIC_V4, "10.0.0.2"),
            )

    def test_public_ipv4_and_ipv6_are_accepted(self):
        target = authorize_target(
            "https://app.example.com",
            authorized=True,
            ownership_verified=True,
            address_resolver=lambda _host: (PUBLIC_V4, PUBLIC_V6),
        )
        self.assertEqual(target.resolved_addresses, (PUBLIC_V4, PUBLIC_V6))

    def test_loopback_behavior_never_calls_external_resolver(self):
        target = authorize_target(
            "http://127.0.0.1:8090",
            authorized=True,
            address_resolver=lambda _host: self.fail("resolver called"),
        )
        self.assertEqual(target.origin, "http://127.0.0.1:8090")

    def test_scoped_http_client_rechecks_external_address_before_request(self):
        target = authorize_target(
            "https://app.example.com",
            authorized=True,
            ownership_verified=True,
            address_resolver=lambda _host: (PUBLIC_V4,),
        )
        client = ScopedReconHttpClient(
            target,
            address_resolver=lambda _host: ("127.0.0.1",),
        )
        try:
            with self.assertRaisesRegex(ReconScopeError, "non-public"):
                client.get("/")
        finally:
            client.close()


class TargetVerificationApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine, cls.factory = make_test_session_factory()
        cls.dns = FakeDns()
        cls.service = TargetVerificationService(dns_resolver=cls.dns)

        def override_db():
            with cls.factory() as session:
                yield session

        app.dependency_overrides[get_db] = override_db
        app.dependency_overrides[_verification_service] = lambda: cls.service
        app.dependency_overrides[_configured_pipeline] = lambda: ReconPipeline(
            http_client_factory=ControlledClient,
            target_verification_service=cls.service,
            address_resolver=cls.dns.resolve_addresses,
        )
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        app.dependency_overrides.pop(get_db, None)
        app.dependency_overrides.pop(_verification_service, None)
        app.dependency_overrides.pop(_configured_pipeline, None)
        cls.engine.dispose()

    def test_create_get_verify_api_contract(self):
        created_response = self.client.post(
            "/api/target-verifications",
            json={"target_url": "https://api-contract.example.com"},
        )
        self.assertEqual(created_response.status_code, 200)
        created = created_response.json()
        self.assertEqual(created["status"], "pending")
        self.dns.txt[created["txt_record_name"]] = (
            created["txt_record_value"],
        )

        fetched = self.client.get(
            f"/api/target-verifications/{created['id']}"
        )
        self.assertEqual(fetched.status_code, 200)
        self.assertEqual(fetched.json()["txt_record_value"], created["txt_record_value"])

        verified = self.client.post(
            f"/api/target-verifications/{created['id']}/verify",
            json={},
        )
        self.assertEqual(verified.status_code, 200)
        self.assertEqual(verified.json()["status"], "verified")
        self.assertIsNone(verified.json()["txt_record_value"])
        self.assertNotIn("token_digest", verified.text)

    def test_invalid_api_targets_and_extra_fields_are_rejected(self):
        cases = (
            ({"target_url": "not-a-url"}, 400),
            ({"target_url": "https://u:p@app.example.com"}, 400),
            ({"target_url": "https://app.example.com/#x"}, 400),
            ({"target_url": "ftp://app.example.com"}, 400),
            ({"target_url": "https://app.example.com", "token": "caller"}, 422),
        )
        for body, status in cases:
            with self.subTest(body=body):
                self.assertEqual(
                    self.client.post(
                        "/api/target-verifications",
                        json=body,
                    ).status_code,
                    status,
                )

    def test_missing_verification_is_404(self):
        self.assertEqual(
            self.client.get(
                "/api/target-verifications/missing"
            ).status_code,
            404,
        )

    def test_verified_origin_unlocks_scan_api_but_sibling_stays_blocked(self):
        origin = "https://api-scan.example.com"
        created = self.client.post(
            "/api/target-verifications",
            json={"target_url": origin},
        ).json()
        self.dns.txt[created["txt_record_name"]] = (
            created["txt_record_value"],
        )
        self.assertEqual(
            self.client.post(
                f"/api/target-verifications/{created['id']}/verify",
                json={},
            ).json()["status"],
            "verified",
        )
        scanned = self.client.post("/api/scans/run", json={
            "target_url": origin,
            "authorized": True,
        })
        self.assertEqual(scanned.status_code, 200)
        self.assertEqual(scanned.json()["target_url"], origin)

        sibling = self.client.post("/api/scans/run", json={
            "target_url": "https://sibling.api-scan.example.com",
            "authorized": True,
        })
        self.assertEqual(sibling.status_code, 403)
        self.assertEqual(
            sibling.json()["detail"]["code"],
            "target_verification_required",
        )
        self.assertEqual(
            self.client.post(
                "/api/target-verifications/missing/verify",
                json={},
            ).status_code,
            404,
        )


class ReconVerificationIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.engine, self.factory = make_test_session_factory()
        self.dns = FakeDns()
        self.service = TargetVerificationService(dns_resolver=self.dns)

    def tearDown(self):
        self.engine.dispose()

    def pipeline(self):
        return ReconPipeline(
            http_client_factory=ControlledClient,
            target_verification_service=self.service,
            address_resolver=self.dns.resolve_addresses,
        )

    def verify(self, session, origin):
        pending = self.service.create_challenge(session, target_url=origin)
        self.dns.txt[pending.txt_record_name] = (pending.txt_record_value,)
        self.service.verify_challenge(session, pending.id)
        session.commit()

    def test_unverified_external_scan_is_blocked_before_scan_creation(self):
        with self.factory() as session:
            with self.assertRaises(TargetVerificationRequiredError):
                self.pipeline().run(
                    target_url="https://unverified.example.com",
                    authorized=True,
                    session=session,
                )
            self.assertEqual(session.query(ScanORM).count(), 0)

    def test_verified_external_scan_passes_gate_and_persists(self):
        origin = "https://verified.example.com"
        with self.factory() as session:
            self.verify(session, origin)
            run = self.pipeline().run(
                target_url=origin,
                authorized=True,
                session=session,
            )
            self.assertEqual(run.target.origin, origin)
            self.assertEqual(run.asset.ip_address, PUBLIC_V4)
            self.assertEqual(session.get(ScanORM, run.scan_id).status, "completed")

    def test_sibling_and_parent_remain_blocked_after_verification(self):
        with self.factory() as session:
            self.verify(session, "https://app.example.com")
            for origin in (
                "https://admin.example.com",
                "https://example.com",
            ):
                with self.subTest(origin=origin), self.assertRaises(
                    TargetVerificationRequiredError
                ):
                    self.pipeline().run(
                        target_url=origin,
                        authorized=True,
                        session=session,
                    )

    def test_verified_host_resolving_private_is_blocked(self):
        origin = "https://private-answer.example.com"
        with self.factory() as session:
            self.verify(session, origin)
            self.dns.addresses["private-answer.example.com"] = ("10.0.0.8",)
            with self.assertRaisesRegex(ReconScopeError, "non-public"):
                self.pipeline().run(
                    target_url=origin,
                    authorized=True,
                    session=session,
                )

    def test_address_change_before_network_use_is_blocked_and_recorded(self):
        origin = "https://rebind.example.com"
        with self.factory() as session:
            self.verify(session, origin)
            answers = iter(((PUBLIC_V4,), ("127.0.0.1",)))
            pipeline = ReconPipeline(
                http_client_factory=ControlledClient,
                target_verification_service=self.service,
                address_resolver=lambda _host: next(answers),
            )
            with self.assertRaisesRegex(ReconScopeError, "non-public"):
                pipeline.run(
                    target_url=origin,
                    authorized=True,
                    session=session,
                )
            scan = session.scalars(select(ScanORM)).one()
            self.assertEqual(scan.status, "failed")
            self.assertNotIn("127.0.0.1", scan.failure_reason)


class TargetVerificationSchemaTests(unittest.TestCase):
    def test_sqlalchemy_schema_and_migration_chain(self):
        engine, _factory = make_test_session_factory()
        try:
            columns = {
                item["name"]
                for item in inspect(engine).get_columns("target_verifications")
            }
            self.assertTrue({
                "id", "origin", "hostname", "token_digest", "challenge_token",
                "status", "created_at", "expires_at", "verified_at",
                "last_checked_at", "failure_code",
            }.issubset(columns))
            unique_columns = {
                tuple(item["column_names"])
                for item in inspect(engine).get_unique_constraints(
                    "target_verifications"
                )
            }
            self.assertIn(("origin",), unique_columns)
        finally:
            engine.dispose()
        migration = (
            Path(__file__).resolve().parents[1]
            / "alembic/versions/0003_add_target_verifications.py"
        ).read_text()
        self.assertIn('down_revision: Union[str, None] = "0002_add_scan_failure_reason"', migration)
        self.assertIn('"target_verifications"', migration)


if __name__ == "__main__":
    unittest.main()
