"""Policy-enforced adapter from agent tools to canonical validators."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from app.agent.models import (
    AgentAction,
    AgentExecutionStatus,
    AgentObservation,
    AgentState,
)
from app.agent.policy import AgentPolicyGate, PolicyDecision
from app.agent.tools import AgentToolRegistry
from app.attack_chain.mitre_mapping import enrich_finding_model
from app.models.finding import Finding, ValidationStatus
from app.models.validation import ValidationResult
from app.validation.dispatcher import apply_validation_result, dispatch


@dataclass(frozen=True)
class AgentExecution:
    observation: AgentObservation
    policy: PolicyDecision
    updated_finding: Optional[Finding] = None
    validation_result: Optional[ValidationResult] = None


class AgentToolExecutor:
    """Always applies policy before invoking an existing dispatcher handler."""

    def __init__(
        self,
        registry: AgentToolRegistry,
        policy_gate: AgentPolicyGate,
    ) -> None:
        if not isinstance(registry, AgentToolRegistry):
            raise TypeError("registry must be an AgentToolRegistry")
        if not isinstance(policy_gate, AgentPolicyGate):
            raise TypeError("policy_gate must be an AgentPolicyGate")
        if policy_gate.registry is not registry:
            raise ValueError("executor registry and policy registry must match")
        self.registry = registry
        self.policy_gate = policy_gate

    def execute(
        self,
        action: AgentAction,
        state: AgentState,
        *,
        session: Any = None,
    ) -> AgentExecution:
        policy = self.policy_gate.evaluate(action, state)
        if not policy.allowed:
            return AgentExecution(
                policy=policy,
                observation=AgentObservation(
                    action_id=action.action_id,
                    tool_id=action.tool_id,
                    finding_id=action.finding_id,
                    policy_decision=policy.code,
                    policy_allowed=False,
                    execution_status=AgentExecutionStatus.BLOCKED,
                    summary=policy.reason,
                    error_category=policy.code,
                ),
            )

        finding = state.finding_by_id(action.finding_id)
        if finding is None:  # Defensive; policy already checks this.
            raise RuntimeError("policy allowed an unavailable finding")
        try:
            validation = dispatch(finding, session=session)
            updated = enrich_finding_model(
                apply_validation_result(finding, validation)
            )
        except Exception:
            return AgentExecution(
                policy=policy,
                observation=AgentObservation(
                    action_id=action.action_id,
                    tool_id=action.tool_id,
                    finding_id=action.finding_id,
                    policy_decision=policy.code,
                    policy_allowed=True,
                    execution_status=AgentExecutionStatus.FAILED,
                    summary="The deterministic validator could not complete safely.",
                    error_category="validator_execution_error",
                ),
            )

        capabilities = ()
        if validation.status == ValidationStatus.CONFIRMED:
            capabilities = tuple(
                capability
                for capability in updated.provides
                if capability not in state.capabilities
            )
        error_category = (
            "validator_reported_error" if validation.error else None
        )
        return AgentExecution(
            policy=policy,
            updated_finding=updated,
            validation_result=validation,
            observation=AgentObservation(
                action_id=action.action_id,
                tool_id=action.tool_id,
                finding_id=action.finding_id,
                policy_decision=policy.code,
                policy_allowed=True,
                execution_status=AgentExecutionStatus.COMPLETED,
                validation_status=validation.status,
                capabilities_gained=capabilities,
                summary=(
                    "Deterministic validation completed with status "
                    f"{validation.status}."
                ),
                error_category=error_category,
            ),
        )
