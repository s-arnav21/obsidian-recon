"""Deterministic SSRF validator, routing, and safety tests."""

from __future__ import annotations

import json
import unittest
from dataclasses import replace
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx

from app.attack_chain.engine import build_attack_paths
from app.attack_chain.mitre_mapping import enrich_finding_model
from app.models.finding import Finding, ValidationStatus
from app.scanning.normalizer import (
    HttpScannerRecord,
    ScannerNormalizationError,
    normalize_scanner_candidate,
    normalize_ssrf_record,
)
from app.scanning.models import ScannerCandidateRecord
from app.validation.dispatcher import apply_validation_result, dispatch
from app.validation.ssrf import (
    CONTROLLED_CANARY_PATH,
    CONTROLLED_CONTROL_PATH,
    SUPPORTED_METHODS,
    SUPPORTED_PARAMETER_LOCATIONS,
    VALIDATOR_ID,
    _canary_plan,
    controlled_content_marker,
)


class FakeResponse:
    def __init__(self, text, status_code=200, content_type="text/plain"):
        self.text = text
        self.status_code = status_code
        self.headers = {"content-type": content_type}


class ControlledSsrfSession:
    def __init__(self, parameter_name="url", mode="fetch", failures=0):
        self.parameter_name = parameter_name
        self.mode = mode
        self.failures = failures
        self.calls = []

    @staticmethod
    def _controlled_response(url):
        parsed = urlsplit(url)
        identifier = parse_qs(parsed.query)["id"][0]
        kind = "canary" if parsed.path == CONTROLLED_CANARY_PATH else "control"
        return FakeResponse(controlled_content_marker(kind, identifier))

    def request(self, method, url, timeout=None, **kwargs):
        self.calls.append({
            "method": method,
            "url": url,
            "timeout": timeout,
            "kwargs": kwargs,
        })
        if self.failures:
            self.failures -= 1
            raise httpx.ReadTimeout("synthetic secret transport detail")

        path = urlsplit(url).path
        if path in {CONTROLLED_CANARY_PATH, CONTROLLED_CONTROL_PATH}:
            if self.mode == "preflight_missing":
                return FakeResponse("controlled infrastructure unavailable")
            if self.mode == "preflight_redirect":
                return FakeResponse("redirect", status_code=302)
            return self._controlled_response(url)

        values = next(
            value for key, value in kwargs.items()
            if key in {"params", "data", "json", "cookies", "headers"}
        )
        parameter = next(
            name for name in values
            if name.lower() == self.parameter_name.lower()
        )
        destination = values[parameter]
        destination_parts = urlsplit(destination)
        identifier = parse_qs(destination_parts.query)["id"][0]
        kind = (
            "canary"
            if destination_parts.path == CONTROLLED_CANARY_PATH
            else "control"
        )
        marker = controlled_content_marker(kind, identifier)

        if self.mode == "fetch":
            return FakeResponse(marker)
        if self.mode == "canary_only":
            return FakeResponse(marker if kind == "canary" else "static")
        if self.mode == "reflect":
            return FakeResponse(f"submitted URL: {destination}")
        if self.mode == "none":
            return FakeResponse("request accepted without retrieval")
        if self.mode == "sanitize":
            return FakeResponse(f"accepted scheme: {destination_parts.scheme}")
        if self.mode == "blocked":
            return FakeResponse("request blocked by security policy", status_code=403)
        if self.mode == "redirect":
            return FakeResponse("redirect", status_code=302)
        if self.mode == "inconsistent":
            status = 201 if kind == "canary" else 200
            return FakeResponse(marker, status_code=status)
        if self.mode == "collision":
            root = identifier.rsplit("-", 1)[-1]
            canary_id = f"or-ssrf-canary-{root}"
            return FakeResponse(controlled_content_marker("canary", canary_id))
        if self.mode == "ambiguous_negative":
            root = identifier.rsplit("-", 1)[-1]
            canary_id = f"or-ssrf-canary-{root}"
            if identifier.startswith("or-ssrf-negative-"):
                return FakeResponse(controlled_content_marker("canary", canary_id))
            return FakeResponse(marker)
        raise AssertionError(f"unsupported fake mode {self.mode}")


def make_record(**overrides):
    values = {
        "record_id": "finding-ssrf",
        "scan_id": "scan-ssrf",
        "asset_id": "asset-ssrf",
        "target": "http://127.0.0.1:8091",
        "endpoint": "/ssrf/fetch",
        "http_method": "GET",
        "parameter_name": "url",
        "parameter_location": "query",
        "scanner_name": "synthetic_http_scanner",
        "scanner_template_id": "synthetic-ssrf-check",
        "vulnerability_type": "ssrf",
        "severity": "high",
        "evidence": {"candidate_url_parameter": True},
        "evidence_refs": ["scanner://synthetic/ssrf-1"],
    }
    values.update(overrides)
    return HttpScannerRecord(**values)


def make_finding(**overrides):
    return normalize_ssrf_record(make_record(**overrides))


class SsrfValidatorTests(unittest.TestCase):
    def dispatch_mode(self, mode, *, finding=None, failures=0):
        finding = finding or make_finding()
        session = ControlledSsrfSession(
            finding.parameter_name or "url",
            mode=mode,
            failures=failures,
        )
        return dispatch(finding, session=session), session

    def test_validator_identity_and_supported_shapes(self):
        self.assertEqual(VALIDATOR_ID, "generic-http-ssrf")
        self.assertEqual(SUPPORTED_METHODS, {"GET", "POST", "PUT", "PATCH"})
        self.assertEqual(
            SUPPORTED_PARAMETER_LOCATIONS,
            {"query", "form", "json", "cookie", "header"},
        )

    def test_markers_are_deterministic_and_finding_scoped(self):
        first = make_finding()
        other = make_finding(record_id="finding-other-ssrf")

        self.assertEqual(_canary_plan(first), _canary_plan(first))
        self.assertNotEqual(_canary_plan(first), _canary_plan(other))
        self.assertNotIn(
            _canary_plan(first).canary_content_marker,
            _canary_plan(first).canary_url,
        )

    def test_controlled_canary_retrieval_confirms(self):
        result, session = self.dispatch_mode("fetch")

        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        self.assertEqual(result.validator, "generic_http_ssrf")
        self.assertEqual(result.confidence, 0.97)
        self.assertTrue(result.evidence["canary_content_marker_observed"])
        self.assertTrue(result.evidence["negative_control_marker_observed"])
        self.assertEqual(
            result.evidence["winning_signal"],
            "unique_controlled_canary_content_retrieved",
        )
        self.assertEqual(len(session.calls), 5)

    def test_url_reflection_alone_is_rejected(self):
        result, _ = self.dispatch_mode("reflect")

        self.assertEqual(result.status, ValidationStatus.REJECTED)
        self.assertTrue(result.evidence["canary_url_reflected"])
        self.assertTrue(result.evidence["reflection_only"])
        self.assertFalse(result.evidence["canary_content_marker_observed"])
        self.assertEqual(
            result.evidence["reason"],
            "url_reflection_without_server_side_retrieval",
        )

    def test_non_fetching_endpoint_is_rejected(self):
        result, _ = self.dispatch_mode("none")

        self.assertEqual(result.status, ValidationStatus.REJECTED)
        self.assertEqual(
            result.evidence["reason"],
            "controlled_canary_marker_not_observed",
        )

    def test_sanitized_url_is_a_clean_negative(self):
        result, _ = self.dispatch_mode("sanitize")

        self.assertEqual(result.status, ValidationStatus.REJECTED)
        self.assertEqual(
            result.evidence["probes"]["controlled_canary"]["url_transformation"],
            "absent",
        )

    def test_negative_control_corroborates_without_using_canary_marker(self):
        result, _ = self.dispatch_mode("fetch")
        negative = result.evidence["probes"]["negative_control"]

        self.assertTrue(negative["expected_content_marker_observed"])
        self.assertFalse(negative["canary_content_marker_observed"])

    def test_baseline_marker_collision_is_manual_review(self):
        result, _ = self.dispatch_mode("collision")

        self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
        self.assertTrue(result.evidence["baseline_marker_collision"])
        self.assertEqual(result.evidence["reason"], "marker_preexisting_in_baseline")

    def test_canary_marker_in_negative_control_is_ambiguous(self):
        result, _ = self.dispatch_mode("ambiguous_negative")

        self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
        self.assertEqual(result.evidence["reason"], "ambiguous_marker_attribution")

    def test_partial_control_retrieval_is_manual_review(self):
        result, _ = self.dispatch_mode("canary_only")

        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        self.assertEqual(result.confidence, 0.93)

    def test_waf_interference_is_manual_review(self):
        result, _ = self.dispatch_mode("blocked")

        self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
        self.assertEqual(result.evidence["reason"], "waf_or_filter_interference")

    def test_redirect_is_not_followed_or_confirmed(self):
        result, session = self.dispatch_mode("redirect")

        self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
        self.assertEqual(result.evidence["reason"], "redirect_ambiguity")
        self.assertEqual(len(session.calls), 5)

    def test_canary_preflight_redirect_is_manual_review(self):
        result, session = self.dispatch_mode("preflight_redirect")

        self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
        self.assertEqual(
            result.evidence["reason"],
            "controlled_canary_redirect_ambiguity",
        )
        self.assertEqual(len(session.calls), 2)

    def test_missing_canary_infrastructure_is_manual_review(self):
        result, _ = self.dispatch_mode("preflight_missing")

        self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
        self.assertEqual(result.evidence["reason"], "controlled_canary_unavailable")

    def test_transient_failure_is_retried_then_succeeds(self):
        result, session = self.dispatch_mode("fetch", failures=1)

        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        self.assertEqual(len(session.calls), 6)
        self.assertEqual(
            result.evidence["infrastructure"]["controlled_canary"]["attempts"],
            2,
        )

    def test_repeated_transport_failure_is_bounded_and_redacted(self):
        result, session = self.dispatch_mode("fetch", failures=20)
        serialized = json.dumps(result.to_dict())

        self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
        self.assertEqual(result.evidence["reason"], "controlled_canary_unavailable")
        self.assertEqual(len(session.calls), 3)
        self.assertNotIn("synthetic secret transport detail", serialized)

    def test_all_requests_have_explicit_timeout(self):
        result, session = self.dispatch_mode("fetch")

        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        self.assertTrue(all(call["timeout"] == 5.0 for call in session.calls))

    def test_all_supported_request_shapes_preserve_unrelated_context(self):
        for method in SUPPORTED_METHODS:
            for location in SUPPORTED_PARAMETER_LOCATIONS:
                with self.subTest(method=method, location=location):
                    parameter = "User-Agent" if location == "header" else "url"
                    context = {
                        location: {
                            "preserved": "keep-this-value",
                            parameter: "original-value",
                        }
                    }
                    finding = make_finding(
                        http_method=method,
                        parameter_name=parameter,
                        parameter_location=location,
                        http_request_context=context,
                    )
                    result, session = self.dispatch_mode("fetch", finding=finding)

                    self.assertEqual(result.status, ValidationStatus.CONFIRMED)
                    sink_calls = [
                        call for call in session.calls
                        if urlsplit(call["url"]).path == "/ssrf/fetch"
                    ]
                    self.assertEqual(len(sink_calls), 3)
                    for call in sink_calls:
                        values = next(iter(call["kwargs"].values()))
                        self.assertEqual(values["preserved"], "keep-this-value")
                        self.assertNotEqual(values[parameter], "original-value")

    def test_non_query_locations_require_original_context(self):
        for location in {"form", "json", "cookie", "header"}:
            with self.subTest(location=location):
                parameter = "User-Agent" if location == "header" else "url"
                finding = make_finding(
                    parameter_name=parameter,
                    parameter_location=location,
                )
                result, session = self.dispatch_mode("fetch", finding=finding)

                self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
                self.assertEqual(
                    result.evidence["reason"],
                    "insufficient_original_request_context",
                )
                self.assertEqual(session.calls, [])

    def test_sensitive_and_unapproved_headers_are_not_mutated(self):
        cases = {
            "Authorization": "sensitive_header_not_allowed",
            "X-Arbitrary-Destination": "unsupported_header_parameter",
        }
        for header, reason in cases.items():
            with self.subTest(header=header):
                finding = make_finding(
                    parameter_name=header,
                    parameter_location="header",
                    http_request_context={"header": {header: "secret-value"}},
                )
                result, session = self.dispatch_mode("fetch", finding=finding)

                self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
                self.assertEqual(result.evidence["reason"], reason)
                self.assertEqual(session.calls, [])
                self.assertNotIn("secret-value", json.dumps(result.to_dict()))

    def test_endpoint_origin_mismatch_is_stopped_before_requests(self):
        finding = replace(
            make_finding(),
            endpoint="http://127.0.0.1:9999/ssrf/fetch",
        )
        result, session = self.dispatch_mode("fetch", finding=finding)

        self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
        self.assertEqual(result.evidence["reason"], "endpoint_origin_mismatch")
        self.assertEqual(session.calls, [])

    def test_evidence_is_bounded_and_contains_no_body_or_request_context(self):
        secret = "DO-NOT-PERSIST-SSRF-SECRET"
        finding = make_finding(
            http_request_context={"query": {"session_token": secret}},
        )
        result, session = self.dispatch_mode("fetch", finding=finding)
        serialized = json.dumps(result.to_dict())

        self.assertNotIn(secret, serialized)
        self.assertNotIn("response_body", serialized)
        self.assertNotIn("http_request_context", serialized)
        self.assertLess(len(serialized), 20_000)
        self.assertTrue(all(
            call["url"].startswith(finding.target)
            for call in session.calls
        ))

    def test_scanner_or_caller_payload_is_never_used_as_destination(self):
        dangerous = "http://169.254.169.254/latest/meta-data/"
        finding = make_finding(evidence={"payload": dangerous})
        result, session = self.dispatch_mode("fetch", finding=finding)

        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        self.assertNotIn(dangerous, json.dumps(session.calls))
        self.assertEqual(result.evidence["dangerous_destinations_probed"], [])

    def test_source_has_no_external_pivot_or_execution_primitive(self):
        source = (
            Path(__file__).resolve().parents[1]
            / "app"
            / "validation"
            / "ssrf.py"
        ).read_text().lower()
        for forbidden in (
            "169.254.169.254",
            "file://",
            "gopher://",
            "subprocess",
            "shell=true",
            "playwright",
            "selenium",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, source)


class SsrfNormalizationAndChainTests(unittest.TestCase):
    def test_normalizer_uses_canonical_type_and_validator(self):
        for value in ("ssrf", "server-side-request-forgery", "Server Side Request Forgery"):
            with self.subTest(value=value):
                finding = make_finding(vulnerability_type=value)
                self.assertEqual(finding.vulnerability_type, "ssrf")
                self.assertEqual(finding.validator_id, "generic-http-ssrf")
                self.assertEqual(finding.template_id, "synthetic-ssrf-check")

    def test_normalizer_rejects_unrelated_type_and_unsupported_shape(self):
        with self.assertRaisesRegex(ScannerNormalizationError, "request forgery"):
            make_finding(vulnerability_type="open_redirect")
        with self.assertRaisesRegex(ScannerNormalizationError, "request shape"):
            make_finding(http_method="DELETE")

    def test_complete_scanner_candidate_routes_but_incomplete_candidate_does_not(self):
        common = {
            "record_id": "candidate-ssrf",
            "scan_id": "scan-ssrf-candidate",
            "asset_id": "asset-ssrf-candidate",
            "target": "http://127.0.0.1:8091",
            "scanner_name": "nuclei",
            "scanner_template_id": "ssrf-detection",
            "vulnerability_type": "ssrf",
            "endpoint": "/ssrf/fetch",
            "http_method": "GET",
            "parameter_name": "url",
            "parameter_location": "query",
        }
        complete = normalize_scanner_candidate(ScannerCandidateRecord(**common))
        incomplete = normalize_scanner_candidate(ScannerCandidateRecord(
            **{**common, "record_id": "candidate-incomplete", "parameter_name": None}
        ))

        self.assertEqual(complete.validator_id, "generic-http-ssrf")
        self.assertEqual(incomplete.validator_id, "recon-manual-review")
        self.assertEqual(incomplete.vulnerability_type, "ssrf")

    def test_dispatch_and_apply_preserve_candidate_identity(self):
        finding = make_finding()
        result = dispatch(finding, session=ControlledSsrfSession(mode="fetch"))
        validated = apply_validation_result(finding, result)

        self.assertEqual(validated.finding_id, finding.finding_id)
        self.assertEqual(validated.scan_id, finding.scan_id)
        self.assertEqual(validated.asset_id, finding.asset_id)
        self.assertEqual(validated.validation_status, ValidationStatus.CONFIRMED)

    def test_confirmed_ssrf_remains_unmapped_without_capability_invention(self):
        finding = make_finding()
        validation = dispatch(finding, session=ControlledSsrfSession(mode="fetch"))
        enriched = enrich_finding_model(apply_validation_result(finding, validation))
        chains = build_attack_paths([enriched])

        self.assertIsNone(enriched.mitre_technique_id)
        self.assertEqual(enriched.provides, [])
        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0].status, "confirmed")
        self.assertEqual(chains[0].mitre_techniques, [])


if __name__ == "__main__":
    unittest.main()
