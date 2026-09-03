import json
import unittest
from unittest.mock import patch

import httpx

from app.models.finding import Finding, ValidationStatus
from app.validation import sql_injection
from app.validation.sql_injection import validate_generic_http_sqli


BASELINE_BODY = "<html><body>account available " + ("A" * 500) + "</body></html>"
FALSE_BODY = "<html><body>account denied " + ("Z" * 500) + "</body></html>"


class FakeResponse:
    def __init__(self, text=BASELINE_BODY, status_code=200, elapsed_seconds=0.01):
        self.text = text
        self.status_code = status_code
        self.elapsed_seconds = elapsed_seconds


class BehaviorSession:
    def __init__(self, behavior=None):
        self.behavior = behavior or (lambda value, call: FakeResponse())
        self.calls = []

    def request(self, method, url, timeout=None, **kwargs):
        call = {
            "method": method,
            "url": url,
            "timeout": timeout,
            **kwargs,
        }
        self.calls.append(call)
        values = next(
            value
            for key in ("params", "data", "json", "cookies", "headers")
            if isinstance(kwargs.get(key), dict)
            for name, value in kwargs[key].items()
            if name == "id"
        )
        return self.behavior(values, call)


def make_finding(**overrides):
    values = {
        "finding_id": "finding-advanced-sqli",
        "scan_id": "scan-advanced-sqli",
        "asset_id": "asset-advanced-sqli",
        "target": "http://app.test",
        "host": "app.test",
        "port": 80,
        "protocol": "http",
        "endpoint": "/items",
        "http_method": "GET",
        "parameter_name": "id",
        "parameter_location": "query",
        "source": "trusted_scanner",
        "template_id": "scanner-sqli",
        "validator_id": "generic-http-sqli",
        "vulnerability_type": "sql_injection",
        "severity": "high",
    }
    values.update(overrides)
    return Finding(**values)


def confirming_boolean_behavior(confirming_pairs=3, error_signature=False):
    confirming_true = {
        pair[0]
        for pair in sql_injection._BOOLEAN_PROBE_PAIRS[:confirming_pairs]
    }
    confirming_false = {
        pair[1]
        for pair in sql_injection._BOOLEAN_PROBE_PAIRS[:confirming_pairs]
    }

    def behavior(value, _call):
        if value in confirming_true:
            return FakeResponse(BASELINE_BODY)
        if value in confirming_false:
            return FakeResponse(FALSE_BODY)
        if error_signature and value == "1'":
            return FakeResponse("You have an error in your SQL syntax", 500)
        return FakeResponse(BASELINE_BODY)

    return behavior


class BooleanAndNormalizationTests(unittest.TestCase):
    def test_two_of_three_pairs_confirm_boolean_method(self):
        result = validate_generic_http_sqli(
            make_finding(),
            BehaviorSession(confirming_boolean_behavior(2)),
        )
        boolean = result.evidence["detection_methods"][
            "boolean-response-differential"
        ]
        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        self.assertEqual(boolean["state"], "confirmed")
        self.assertEqual(boolean["confirming_pairs"], 2)
        self.assertEqual(len(boolean["pairs"]), 3)

    def test_only_one_confirming_pair_is_not_confirmation(self):
        result = validate_generic_http_sqli(
            make_finding(),
            BehaviorSession(confirming_boolean_behavior(1)),
        )
        self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
        self.assertEqual(
            result.evidence["detection_methods"]
            ["boolean-response-differential"]["state"],
            "inconclusive",
        )

    def test_equivalent_responses_produce_clean_negative(self):
        result = validate_generic_http_sqli(
            make_finding(), BehaviorSession(),
        )
        self.assertEqual(result.status, ValidationStatus.REJECTED)
        self.assertEqual(result.evidence["reason"], "all_detection_methods_negative")

    def test_dynamic_tokens_timestamps_and_uuids_are_normalized(self):
        left = (
            '<input name="csrf_token" value="abc123"> '
            "2026-09-03T10:00:00Z "
            "550e8400-e29b-41d4-a716-446655440000"
        )
        right = (
            '<input name="csrf_token" value="xyz987"> '
            "2026-09-03T10:00:03Z "
            "6ba7b810-9dad-41d1-80b4-00c04fd430c8"
        )
        self.assertEqual(
            sql_injection._normalize_response_text(left),
            sql_injection._normalize_response_text(right),
        )

    def test_meaningful_content_difference_survives_normalization(self):
        left = (
            '<input name="nonce" value="one"> account approved '
            + ("A" * 200)
        )
        right = (
            '<input name="nonce" value="two"> account denied '
            + ("Z" * 200)
        )
        self.assertLess(sql_injection._similarity(left, right), 0.90)

    def test_dynamic_noise_alone_does_not_create_false_confirmation(self):
        counter = 0

        def behavior(value, _call):
            nonlocal counter
            counter += 1
            return FakeResponse(
                '<input name="csrf_token" value="token-'
                f'{counter}"> generated_at=2026-09-03T10:00:{counter:02d}Z '
                "same meaningful response"
            )

        result = validate_generic_http_sqli(
            make_finding(), BehaviorSession(behavior),
        )
        self.assertEqual(result.status, ValidationStatus.REJECTED)


class ErrorAndTimingTests(unittest.TestCase):
    def test_common_database_error_categories_are_recognized(self):
        cases = {
            "mysql": "You have an error in your SQL syntax",
            "postgresql": "PG::SyntaxError: unterminated quoted string",
            "mssql": "Unclosed quotation mark in SQL Server request",
            "oracle": "ORA-00933: SQL command not properly ended",
            "sqlite": "sqlite3.OperationalError: near quote: syntax error",
        }
        for expected, message in cases.items():
            with self.subTest(expected=expected):
                self.assertIn(
                    expected,
                    sql_injection._database_error_categories(message),
                )

    def test_existing_baseline_database_error_does_not_confirm(self):
        body = "You have an error in your SQL syntax"
        result = validate_generic_http_sqli(
            make_finding(),
            BehaviorSession(lambda value, call: FakeResponse(body)),
        )
        self.assertEqual(result.status, ValidationStatus.REJECTED)
        error = result.evidence["detection_methods"]["error-based"]
        self.assertEqual(error["baseline_error_categories"], ["mysql"])
        self.assertEqual(error["introduced_error_categories"], [])

    def test_new_database_error_signature_confirms(self):
        result = validate_generic_http_sqli(
            make_finding(),
            BehaviorSession(confirming_boolean_behavior(0, error_signature=True)),
        )
        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        self.assertEqual(result.evidence["methods_triggered"], ["error-based"])
        error = result.evidence["detection_methods"]["error-based"]
        self.assertEqual(error["introduced_error_categories"], ["mysql"])

    def test_generic_application_error_does_not_confirm(self):
        def behavior(value, _call):
            if value in {probe for _, probe in sql_injection._ERROR_PROBES}:
                return FakeResponse("Internal application exception", 500)
            return FakeResponse()

        result = validate_generic_http_sqli(
            make_finding(), BehaviorSession(behavior),
        )
        self.assertEqual(result.status, ValidationStatus.REJECTED)
        self.assertEqual(
            result.evidence["detection_methods"]["error-based"]["state"],
            "negative",
        )

    def test_stable_baseline_and_repeatable_delay_confirm_time_method(self):
        def behavior(value, _call):
            elapsed = 3.1 if "SLEEP" in value else 0.1
            return FakeResponse(elapsed_seconds=elapsed)

        session = BehaviorSession(behavior)
        result = validate_generic_http_sqli(make_finding(), session)
        timing = result.evidence["detection_methods"]["time-based-blind"]
        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        self.assertEqual(result.evidence["methods_triggered"], ["time-based-blind"])
        self.assertEqual(timing["state"], "confirmed")
        self.assertEqual(timing["probes"][0]["delayed_observations"], 2)
        self.assertLessEqual(len(session.calls), 17)

    def test_normal_fast_timing_is_negative(self):
        result = validate_generic_http_sqli(
            make_finding(), BehaviorSession(),
        )
        self.assertEqual(
            result.evidence["detection_methods"]["time-based-blind"]["state"],
            "negative",
        )

    def test_slow_or_unstable_baseline_is_inconclusive(self):
        call_count = 0

        def behavior(value, _call):
            nonlocal call_count
            call_count += 1
            if call_count == 10:
                return FakeResponse(elapsed_seconds=0.1)
            if call_count == 11:
                return FakeResponse(elapsed_seconds=1.2)
            return FakeResponse(elapsed_seconds=0.1)

        result = validate_generic_http_sqli(
            make_finding(), BehaviorSession(behavior),
        )
        timing = result.evidence["detection_methods"]["time-based-blind"]
        self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
        self.assertEqual(timing["state"], "inconclusive")
        self.assertEqual(timing["reason"], "slow_or_unstable_baseline")


class RequestShapeAndContextTests(unittest.TestCase):
    def _confirm_and_calls(self, **finding_overrides):
        session = BehaviorSession(
            confirming_boolean_behavior(0, error_signature=True)
        )
        result = validate_generic_http_sqli(
            make_finding(**finding_overrides), session,
        )
        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        return session.calls

    def test_get_post_put_and_patch_are_supported(self):
        for method in ("GET", "POST", "PUT", "PATCH"):
            with self.subTest(method=method):
                calls = self._confirm_and_calls(http_method=method)
                self.assertTrue(all(call["method"] == method for call in calls))
                self.assertTrue(all(call["timeout"] == 5.0 for call in calls))

    def test_query_form_json_cookie_and_header_are_supported(self):
        kwargs_for_location = {
            "query": {},
            "form": {"http_request_context": {"form": {"keep": "yes"}}},
            "json": {"http_request_context": {"json": {"keep": "yes"}}},
            "cookie": {"http_request_context": {"cookie": {"keep": "yes"}}},
            "header": {"http_request_context": {"header": {"keep": "yes"}}},
        }
        argument_for_location = {
            "query": "params",
            "form": "data",
            "json": "json",
            "cookie": "cookies",
            "header": "headers",
        }
        for location, overrides in kwargs_for_location.items():
            with self.subTest(location=location):
                calls = self._confirm_and_calls(
                    http_method="POST",
                    parameter_location=location,
                    **overrides,
                )
                argument = argument_for_location[location]
                self.assertTrue(all("id" in call[argument] for call in calls))
                if location != "query":
                    self.assertTrue(all(call[argument]["keep"] == "yes" for call in calls))

    def test_original_json_form_cookie_and_header_fields_are_preserved(self):
        contexts = {
            "json": {"username": "test", "id": "original", "filter": "active"},
            "form": {"username": "test", "id": "original", "filter": "active"},
            "cookie": {"session": "secret-cookie", "id": "original"},
            "header": {"Authorization": "Bearer secret", "id": "original"},
        }
        argument_names = {
            "json": "json", "form": "data",
            "cookie": "cookies", "header": "headers",
        }
        for location, context in contexts.items():
            with self.subTest(location=location):
                calls = self._confirm_and_calls(
                    http_method="POST",
                    parameter_location=location,
                    http_request_context={location: context},
                )
                sent = calls[0][argument_names[location]]
                for name, value in context.items():
                    if name != "id":
                        self.assertEqual(sent[name], value)
                self.assertNotEqual(sent["id"], "original")

    def test_missing_structured_request_context_returns_manual_review(self):
        for location in ("json", "cookie", "header"):
            with self.subTest(location=location):
                result = validate_generic_http_sqli(
                    make_finding(
                        http_method="POST",
                        parameter_location=location,
                    ),
                    BehaviorSession(),
                )
                self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
                self.assertEqual(
                    result.evidence["reason"],
                    "insufficient_original_request_context",
                )

    def test_transient_request_context_never_serializes(self):
        secret = "Bearer should-never-serialize"
        finding = make_finding(
            http_method="POST",
            parameter_location="header",
            http_request_context={"header": {
                "Authorization": secret,
                "id": "original",
            }},
        )
        result = validate_generic_http_sqli(
            finding,
            BehaviorSession(confirming_boolean_behavior(0, error_signature=True)),
        )
        self.assertNotIn(secret, json.dumps(finding.to_dict()))
        self.assertNotIn(secret, json.dumps(result.to_dict()))


class NetworkWafAggregationAndSecurityTests(unittest.TestCase):
    def test_transient_failure_is_retried_then_succeeds(self):
        attempts = 0

        def behavior(value, _call):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise httpx.ConnectError("transient")
            return confirming_boolean_behavior(2)(value, _call)

        session = BehaviorSession(behavior)
        with patch.object(sql_injection.time, "sleep") as sleep:
            result = validate_generic_http_sqli(make_finding(), session)
        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        sleep.assert_called_once_with(0.05)
        self.assertEqual(session.calls[1]["params"]["id"], "1")
        self.assertEqual(
            result.evidence["detection_methods"]
            ["boolean-response-differential"]["baseline"]["attempts"],
            2,
        )

    def test_retry_backoff_is_exponential_and_bounded(self):
        attempts = 0

        def behavior(value, _call):
            nonlocal attempts
            attempts += 1
            if attempts <= 2:
                raise httpx.ConnectError("transient")
            return confirming_boolean_behavior(2)(value, _call)

        with patch.object(sql_injection.time, "sleep") as sleep:
            result = validate_generic_http_sqli(
                make_finding(), BehaviorSession(behavior),
            )

        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        self.assertEqual(
            [call.args[0] for call in sleep.call_args_list],
            [0.05, 0.1],
        )

    def test_repeated_transport_failures_are_bounded_and_inconclusive(self):
        session = BehaviorSession(
            lambda value, call: (_ for _ in ()).throw(TimeoutError("secret"))
        )
        result = validate_generic_http_sqli(make_finding(), session)
        self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
        self.assertEqual(result.evidence["maximum_request_attempts"], 3)
        self.assertEqual(len(session.calls), 9)
        self.assertNotIn("secret", json.dumps(result.to_dict()))

    def test_blocked_probe_returns_manual_review_not_false_verdict(self):
        first_true = sql_injection._BOOLEAN_PROBE_PAIRS[0][0]

        def behavior(value, _call):
            if value == first_true:
                return FakeResponse("Request blocked by security policy", 403)
            return FakeResponse()

        session = BehaviorSession(behavior)
        result = validate_generic_http_sqli(make_finding(), session)
        self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
        self.assertTrue(result.evidence["waf_or_filter_interference"])
        self.assertEqual(result.evidence["methods_triggered"], [])
        self.assertEqual(len(session.calls), 3)

    def test_corroborating_boolean_and_error_methods_add_small_bonus(self):
        result = validate_generic_http_sqli(
            make_finding(),
            BehaviorSession(confirming_boolean_behavior(2, error_signature=True)),
        )
        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        self.assertEqual(
            result.evidence["methods_triggered"],
            ["boolean-response-differential", "error-based"],
        )
        self.assertEqual(result.confidence, 0.89)

    def test_partial_method_failure_with_no_confirmation_is_manual_review(self):
        error_probe = sql_injection._ERROR_PROBES[0][1]

        def behavior(value, _call):
            if value == error_probe:
                raise RuntimeError("internal secret")
            return FakeResponse()

        result = validate_generic_http_sqli(
            make_finding(), BehaviorSession(behavior),
        )
        self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
        self.assertNotIn("internal secret", json.dumps(result.to_dict()))

    def test_origin_mismatch_is_handled_without_request(self):
        session = BehaviorSession()
        result = validate_generic_http_sqli(
            make_finding(endpoint="https://other.test/items"), session,
        )
        self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)
        self.assertEqual(result.evidence["reason"], "endpoint_origin_mismatch")
        self.assertEqual(session.calls, [])

    def test_scanner_supplied_payload_is_never_used(self):
        caller_value = "caller supplied SQL"
        session = BehaviorSession(confirming_boolean_behavior(2))
        validate_generic_http_sqli(
            make_finding(evidence={"payload": caller_value}), session,
        )
        self.assertNotIn(caller_value, json.dumps(session.calls))

    def test_fixed_probes_do_not_enumerate_or_modify_data(self):
        probes = " ".join(sql_injection.fixed_probe_values()).lower()
        for forbidden in (
            "information_schema",
            "select version",
            "@@version",
            "select user from dual",
            " drop ",
            " delete ",
            " update ",
            " insert ",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, f" {probes} ")

    def test_raw_response_bodies_are_not_persisted_in_evidence(self):
        raw_marker = "RAW-BODY-MARKER-SHOULD-NOT-PERSIST"

        def behavior(value, call):
            return FakeResponse(f"{raw_marker}-{value}")

        result = validate_generic_http_sqli(
            make_finding(), BehaviorSession(behavior),
        )
        self.assertNotIn(raw_marker, json.dumps(result.to_dict()))


if __name__ == "__main__":
    unittest.main()
