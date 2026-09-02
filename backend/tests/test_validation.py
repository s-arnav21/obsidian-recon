"""Tests for the ValidationResult contract."""

import unittest

from app.models.finding import ValidationStatus
from app.models.validation import ValidationResult


def make_result(status, confidence):
    return ValidationResult(
        status=status,
        confidence=confidence,
        validator="unit_test_validator",
        method="controlled_comparison",
        evidence={"matched": True},
        evidence_refs=["evidence://validation/1"],
    )


class TestValidationResult(unittest.TestCase):

    def test_valid_confirmed_result(self):
        result = make_result(ValidationStatus.CONFIRMED, 0.95)
        self.assertEqual(result.status, ValidationStatus.CONFIRMED)
        self.assertEqual(result.confidence, 0.95)

    def test_valid_rejected_result(self):
        result = make_result(ValidationStatus.REJECTED, 0.9)
        self.assertEqual(result.status, ValidationStatus.REJECTED)

    def test_valid_manual_review_result(self):
        result = make_result(ValidationStatus.MANUAL_REVIEW, 0.6)
        self.assertEqual(result.status, ValidationStatus.MANUAL_REVIEW)

    def test_invalid_confidence_fails(self):
        for confidence in (-0.01, 1.01):
            with self.subTest(confidence=confidence):
                with self.assertRaises(ValueError):
                    make_result(ValidationStatus.CONFIRMED, confidence)

        with self.assertRaises(TypeError):
            make_result(ValidationStatus.CONFIRMED, "high")

    def test_invalid_status_fails(self):
        with self.assertRaisesRegex(ValueError, "unsupported validation status"):
            make_result("unknown", 0.5)


if __name__ == "__main__":
    unittest.main()
