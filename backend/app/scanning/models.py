"""Structured reconnaissance observations before canonical normalization."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class AssetObservation:
    asset_id: str
    hostname: str
    base_url: str
    ip_address: Optional[str] = None


@dataclass(frozen=True)
class ServiceObservation:
    asset_id: str
    port: Optional[int]
    protocol: Optional[str]
    service_name: Optional[str]
    product: Optional[str] = None
    version: Optional[str] = None
    state: Optional[str] = None
    source: Optional[str] = None


@dataclass(frozen=True)
class ScannerCandidateRecord:
    record_id: str
    scan_id: str
    asset_id: str
    target: str
    scanner_name: str
    scanner_template_id: str
    vulnerability_type: str
    severity: str = "unknown"
    endpoint: Optional[str] = None
    http_method: Optional[str] = None
    parameter_name: Optional[str] = None
    parameter_location: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    evidence_refs: List[str] = field(default_factory=list)
    observed_at: Optional[str] = None
