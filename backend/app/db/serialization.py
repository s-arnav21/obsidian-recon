"""JSON-safe serialization for persistence API responses."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from app.db.models import AttackChainORM, FindingORM, ScanORM


def _timestamp(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value is not None else None


def scan_to_dict(scan: ScanORM) -> Dict[str, Any]:
    return {
        "id": scan.id,
        "target_url": scan.target_url,
        "status": scan.status,
        "authorized": scan.authorized,
        "started_at": _timestamp(scan.started_at),
        "completed_at": _timestamp(scan.completed_at),
        "failure_reason": scan.failure_reason,
        "created_at": _timestamp(scan.created_at),
    }


def finding_to_dict(finding: FindingORM) -> Dict[str, Any]:
    return {
        "id": finding.id,
        "scan_id": finding.scan_id,
        "asset_id": finding.asset_id,
        "source": finding.source,
        "scanner_template_id": finding.scanner_template_id,
        "validator_id": finding.validator_id,
        "vulnerability_type": finding.vulnerability_type,
        "severity": finding.severity,
        "target": finding.target,
        "endpoint": finding.endpoint,
        "http_method": finding.http_method,
        "parameter_name": finding.parameter_name,
        "parameter_location": finding.parameter_location,
        "status": finding.status,
        "created_at": _timestamp(finding.created_at),
        "validations": [
            {
                "id": validation.id,
                "validator_id": validation.validator_id,
                "status": validation.status,
                "confidence": validation.confidence,
                "decision_reason": validation.decision_reason,
                "validated_at": _timestamp(validation.validated_at),
                "evidence": [
                    {
                        "id": evidence.id,
                        "evidence_type": evidence.evidence_type,
                        "evidence_json": evidence.evidence_json,
                        "created_at": _timestamp(evidence.created_at),
                    }
                    for evidence in validation.evidence_records
                ],
            }
            for validation in finding.validations
        ],
        "mitre_mappings": [
            {
                "id": mapping.id,
                "technique_id": mapping.technique_id,
                "technique_name": mapping.technique_name,
                "tactic": mapping.tactic,
                "mapping_confidence": mapping.mapping_confidence,
            }
            for mapping in finding.mitre_mappings
        ],
    }


def attack_chain_to_dict(chain: AttackChainORM) -> Dict[str, Any]:
    return {
        "id": chain.id,
        "scan_id": chain.scan_id,
        "asset_id": chain.asset_id,
        "status": chain.status,
        "confidence": chain.confidence,
        "created_at": _timestamp(chain.created_at),
        "steps": [
            {
                "id": step.id,
                "step_number": step.step_number,
                "finding_id": step.finding_id,
                "technique_id": step.technique_id,
                "capability": step.capability,
            }
            for step in sorted(chain.steps, key=lambda item: item.step_number)
        ],
    }
