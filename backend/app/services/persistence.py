"""Adapters that persist existing deterministic pipeline domain outputs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Sequence

from sqlalchemy.orm import Session

from app.db.repository import PersistenceRepository
from app.models.attack_chain import AttackChain
from app.models.finding import Finding
from app.models.validation import ValidationResult


@dataclass(frozen=True)
class ValidationPersistenceRecord:
    """Candidate, separate validation result, and enriched mapping view."""

    candidate: Finding
    validation: ValidationResult
    enriched: Finding


@dataclass(frozen=True)
class ServicePersistenceRecord:
    """Optional recon service observation associated with the same scan."""

    asset_id: str
    port: Optional[int] = None
    protocol: Optional[str] = None
    service_name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    state: Optional[str] = None
    source: Optional[str] = None
    service_id: Optional[str] = None


def persist_validation_run(
    session: Session,
    *,
    target_url: str,
    authorized: bool,
    findings: Sequence[Finding],
    validations: Sequence[ValidationPersistenceRecord],
    attack_chains: Sequence[AttackChain],
    services: Sequence[ServicePersistenceRecord] = (),
) -> str:
    """Persist one existing scan/validation/chain run atomically."""
    if not findings:
        raise ValueError("at least one finding is required")
    scan_ids = {finding.scan_id for finding in findings}
    if len(scan_ids) != 1:
        raise ValueError("all findings must belong to one scan")
    scan_id = next(iter(scan_ids))
    finding_by_id = {finding.finding_id: finding for finding in findings}
    if len(finding_by_id) != len(findings):
        raise ValueError("finding identifiers must be unique")

    for record in validations:
        if record.candidate.finding_id not in finding_by_id:
            raise ValueError("validated candidate must be included in findings")
        if record.enriched.finding_id != record.candidate.finding_id:
            raise ValueError("enriched finding identity must match its candidate")
        if record.candidate.scan_id != scan_id:
            raise ValueError("validation candidate belongs to a different scan")
    for chain in attack_chains:
        if chain.scan_id != scan_id:
            raise ValueError("attack chain belongs to a different scan")

    repository = PersistenceRepository(session)
    try:
        repository.create_scan(
            scan_id=scan_id,
            target_url=target_url,
            authorized=authorized,
            status="running",
        )

        assets = {}
        for finding in findings:
            existing = assets.get(finding.asset_id)
            if existing is None:
                assets[finding.asset_id] = repository.persist_asset(
                    scan_id=scan_id,
                    asset_id=finding.asset_id,
                    hostname=finding.host,
                    base_url=finding.target,
                )

        for service in services:
            if service.asset_id not in assets:
                raise ValueError("service asset must belong to the persisted scan")
            repository.persist_service(
                scan_id=scan_id,
                asset_id=service.asset_id,
                service_id=service.service_id,
                port=service.port,
                protocol=service.protocol,
                service_name=service.service_name,
                product=service.product,
                version=service.version,
                state=service.state,
                source=service.source,
            )

        for finding in findings:
            repository.persist_finding(finding)

        for record in validations:
            validation = repository.persist_validation(
                finding_id=record.candidate.finding_id,
                result=record.validation,
            )
            repository.persist_evidence(
                validation_id=validation.id,
                finding_id=record.candidate.finding_id,
                evidence_type="validation_result",
                evidence_json=dict(record.validation.evidence),
            )
            if record.enriched.mitre_technique_id:
                repository.persist_mitre_mapping(record.enriched)

        for chain in attack_chains:
            repository.persist_attack_chain(chain)

        repository.update_scan_status(scan_id, "completed")
        session.commit()
        return scan_id
    except Exception:
        session.rollback()
        raise
