"""Typed output contracts for deterministic attack-chain analysis."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.models.finding import validate_confidence


@dataclass
class AttackChainStep:
    """One evidence-backed finding participating in an attack chain."""

    step_number: int
    finding_id: str
    scan_id: str
    asset_id: str
    target: str
    vulnerability_type: str
    validation_status: str
    validation_confidence: float
    requires_all: List[str] = field(default_factory=list)
    requires_any: List[str] = field(default_factory=list)
    requires: List[str] = field(default_factory=list)
    provides: List[str] = field(default_factory=list)
    mitre_tactic: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    evidence_refs: List[str] = field(default_factory=list)
    step_type: str = "finding"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttackChain:
    """A deterministic, same-scan and same-asset attack chain."""

    chain_id: str
    scan_id: str
    asset_id: str
    target: str
    status: str
    confidence: float
    steps: List[AttackChainStep]
    capabilities_gained: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    evidence_refs: List[str] = field(default_factory=list)
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def __post_init__(self) -> None:
        if self.status not in {"confirmed", "potential"}:
            raise ValueError("attack-chain status must be confirmed or potential")
        self.confidence = validate_confidence(
            self.confidence,
            "chain confidence",
        )
        if not self.steps:
            raise ValueError("an attack chain must contain at least one step")
        if not all(isinstance(step, AttackChainStep) for step in self.steps):
            raise TypeError("steps must contain AttackChainStep objects")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
