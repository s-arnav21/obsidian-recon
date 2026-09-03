import unittest

from app.models.finding import ValidationStatus
from app.scanning.models import ScannerCandidateRecord
from app.scanning.normalizer import (
    GENERIC_SQLI_VALIDATOR_ID,
    RECON_MANUAL_REVIEW_VALIDATOR_ID,
    normalize_scanner_candidate,
)


def candidate(**overrides):
    values = {
        "record_id": "candidate-1",
        "scan_id": "scan-1",
        "asset_id": "asset-1",
        "target": "http://127.0.0.1:8090",
        "scanner_name": "nuclei",
        "scanner_template_id": "candidate-template",
        "vulnerability_type": "sql_injection",
        "severity": "high",
        "endpoint": "/items",
        "http_method": "get",
        "parameter_name": "id",
        "parameter_location": "query",
        "evidence": {"scanner": "nuclei"},
    }
    values.update(overrides)
    return ScannerCandidateRecord(**values)


class ReconCandidateNormalizerTests(unittest.TestCase):
    def test_explicit_complete_sqli_context_routes_generic_validator(self):
        finding = normalize_scanner_candidate(candidate())
        self.assertEqual(finding.validator_id, GENERIC_SQLI_VALIDATOR_ID)
        self.assertEqual(finding.http_method, "GET")
        self.assertEqual(finding.validation_status, ValidationStatus.DETECTED)
        self.assertEqual(finding.evidence, {"scanner": "nuclei"})

    def test_incomplete_context_is_preserved_for_manual_review(self):
        finding = normalize_scanner_candidate(candidate(parameter_name=None))
        self.assertEqual(finding.validator_id, RECON_MANUAL_REVIEW_VALIDATOR_ID)
        self.assertEqual(finding.template_id, "candidate-template")
        self.assertEqual(finding.vulnerability_type, "sql_injection")

    def test_command_candidate_never_routes_active_validator(self):
        finding = normalize_scanner_candidate(candidate(
            vulnerability_type="command_execution",
            scanner_template_id="generic-http-command-execution",
            http_method="POST",
            parameter_name="command",
            parameter_location="form",
        ))
        self.assertEqual(finding.validator_id, RECON_MANUAL_REVIEW_VALIDATOR_ID)
        self.assertEqual(finding.vulnerability_type, "command_execution")

    def test_unknown_candidate_is_not_promoted(self):
        finding = normalize_scanner_candidate(candidate(
            vulnerability_type="nuclei_candidate",
            endpoint="/status",
            http_method=None,
            parameter_name=None,
            parameter_location=None,
        ))
        self.assertEqual(finding.validator_id, RECON_MANUAL_REVIEW_VALIDATOR_ID)
        self.assertEqual(finding.vulnerability_type, "nuclei_candidate")


if __name__ == "__main__":
    unittest.main()
