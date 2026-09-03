"""Deterministic PoC and generalized technical business-impact presentation.

This module explains existing domain output. It does not validate targets,
generate payloads, change ATT&CK mappings, or execute any action.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict, Iterable, Mapping, Sequence
from urllib.parse import urlencode

from app.validation.command_execution import (
    BASELINE_DIAGNOSTIC_TOKEN,
    CONTROL_PROBE_TOKEN,
    EXECUTION_PROBE_TOKEN,
)
from app.validation.sql_injection import (
    _CONTROL_VALUE as SQL_CONTROL_VALUE,
    _FALSE_PROBE_VALUE as SQL_FALSE_VALUE,
    _TRUE_PROBE_VALUE as SQL_TRUE_VALUE,
)


GENERALIZED_RISK_NOTICE = (
    "Generalized technical business-impact rating; not an estimate of a "
    "specific organization's actual loss."
)
ENVIRONMENTAL_TYPES = frozenset({
    "service_scan", "port_scan", "network_scan", "nmap_scan", "nuclei_scan",
})
TYPE_ALIASES = {
    "sqli": "sql_injection",
    "cross_site_scripting": "reflected_xss",
    "reflected_cross_site_scripting": "reflected_xss",
    "sensitive_data_exposure": "information_disclosure",
    "debug_resource_exposure": "information_disclosure",
    "directory_resource_disclosure": "information_disclosure",
}

RISK_PROFILES: Dict[str, Dict[str, Any]] = {
    "sql_injection": {
        "cia": {"confidentiality": "High", "integrity": "High", "availability": "Moderate"},
        "technical_impact": [
            "Backend query manipulation",
            "Potential unauthorized database interaction",
            "Application compromise",
            "Possible database access",
        ],
        "business": {
            "confidentiality": "Potential exposure of application or database information.",
            "integrity": "Potential unauthorized manipulation of application-backed records.",
            "availability": "Poorly constrained database operations can potentially affect service operation.",
            "consequences": [
                "Data exposure", "Data-integrity issues", "Operational disruption",
                "Regulatory or compliance exposure where protected data is involved",
                "Reputational impact",
            ],
        },
    },
    "command_execution": {
        "cia": {"confidentiality": "High", "integrity": "High", "availability": "High"},
        "technical_impact": ["Command-execution capability", "Execution-stage compromise"],
        "business": {
            "confidentiality": "A genuine command-execution flaw may expose data available to the affected application context.",
            "integrity": "Commands could potentially modify files, configuration, or data within that execution context.",
            "availability": "Command execution could potentially interrupt services or application processes.",
            "consequences": [
                "Application takeover", "Data compromise", "Service disruption",
                "Wider compromise depending on privileges and environment",
            ],
        },
    },
    "reflected_xss": {
        "cia": {"confidentiality": "Moderate", "integrity": "Moderate", "availability": "Low"},
        "technical_impact": ["Unencoded reflection in an HTML response context"],
        "business": {
            "confidentiality": "A real exploitable browser context could expose user-accessible information.",
            "integrity": "A real exploit could alter content presented in an affected user's session.",
            "availability": "Direct service-availability impact is generally limited.",
            "consequences": ["User-session exposure", "Unauthorized browser-side actions", "Loss of user trust"],
        },
    },
    "information_disclosure": {
        "cia": {"confidentiality": "High", "integrity": "Low", "availability": "Low"},
        "technical_impact": ["Accessible sensitive or diagnostic resource", "Information exposure"],
        "business": {
            "confidentiality": "Exposed configuration or diagnostic information may reveal sensitive application details.",
            "integrity": "Direct modification is not established by this finding.",
            "availability": "Direct service interruption is not established by this finding.",
            "consequences": ["Sensitive information exposure", "Reduced security through disclosed configuration"],
        },
    },
}

SEVERITY_RATING = {
    "info": "Low", "informational": "Low", "low": "Low",
    "medium": "Medium", "moderate": "Medium", "high": "High", "critical": "Critical",
}
RATING_ORDER = {"Not rated": -1, "Low": 0, "Medium": 1, "High": 2, "Critical": 3}


def _type(value: Any) -> str:
    normalized = str(value or "unknown").lower().replace("-", "_").replace(" ", "_")
    return TYPE_ALIASES.get(normalized, normalized)


def _validation_evidence(validation: Mapping[str, Any]) -> Dict[str, Any]:
    evidence = validation.get("evidence")
    if isinstance(evidence, dict):
        return dict(evidence)
    if isinstance(evidence, list) and evidence:
        latest = evidence[-1]
        if isinstance(latest, dict) and isinstance(latest.get("evidence_json"), dict):
            return dict(latest["evidence_json"])
    return {}


def _safe_observed_evidence(vulnerability_type: str, evidence: Mapping[str, Any]) -> Dict[str, Any]:
    keys = {
        "sql_injection": (
            "baseline_status", "true_probe_status", "false_probe_status",
            "baseline_length", "injected_length", "baseline_result_count",
            "injected_result_count",
            "baseline_true_similarity", "baseline_false_similarity",
            "true_false_similarity", "similarity_delta", "reason", "decision",
        ),
        "command_execution": (
            "baseline_status", "probe_status", "control_status",
            "baseline_marker_present", "execution_marker_present",
            "control_marker_present", "reason", "decision",
        ),
        "reflected_xss": (
            "baseline_status", "response_status", "response_content_type",
            "marker_reflected", "raw_probe_reflected", "marker_present_in_baseline",
            "response_context", "reason", "decision",
        ),
        "information_disclosure": (
            "response_status", "response_content_type", "classification_signals",
            "reason", "decision",
        ),
    }.get(vulnerability_type, ("reason", "decision"))
    return {key: evidence[key] for key in keys if key in evidence}


def _request_form(method: str, endpoint: str, parameter: str, value: str, location: str) -> str:
    encoded = urlencode({parameter: value})
    if method == "GET" and location == "query":
        return f"GET {endpoint}?{encoded}"
    if method == "POST" and location == "form":
        return f"POST {endpoint}\nContent-Type: application/x-www-form-urlencoded\n\n{encoded}"
    return f"{method} {endpoint}"


def _poc(
    vulnerability_type: str,
    finding: Mapping[str, Any],
    validation: Mapping[str, Any],
    *,
    controlled_lab: bool,
) -> Dict[str, Any]:
    evidence = _validation_evidence(validation)
    status = validation.get("status") or finding.get("validation_status") or finding.get("status")
    confirmed = status == "confirmed"
    endpoint = str(finding.get("endpoint") or evidence.get("endpoint") or "")
    method = str(finding.get("http_method") or evidence.get("http_method") or "")
    parameter = str(finding.get("parameter_name") or evidence.get("parameter_name") or "")
    location = str(finding.get("parameter_location") or evidence.get("parameter_location") or "")
    controlled_execution = controlled_lab and evidence.get("fixture") is not True
    common = {
        "available": confirmed and bool(evidence),
        "label": "Controlled Lab" if controlled_execution and confirmed else "Evidence Only" if confirmed and evidence else "Unavailable",
        "subtitle": "Evidence and steps used to reproduce this finding.",
        "verification_method": validation.get("method"),
        "requests": [],
        "observed_evidence": _safe_observed_evidence(vulnerability_type, evidence),
        "controlled_lab": controlled_lab,
    }
    if vulnerability_type == "sql_injection":
        generic_differential = (
            validation.get("validator") == "generic_http_sqli"
            or validation.get("method") == "boolean-response-differential SQLi"
        )
        if generic_differential:
            common.update({
                "verification_method": "Boolean-response differential",
                "steps": [
                    "Establish a normal baseline response.",
                    "Submit the validator's logically TRUE condition through the identified parameter.",
                    "Submit the validator's logically FALSE control condition.",
                    "Compare the three application responses.",
                    "Confirm only when the configured differential thresholds are satisfied.",
                ],
                "interpretation": (
                    "The normal and TRUE-condition responses were effectively equivalent while "
                    "the FALSE-condition response changed substantially. This is consistent with "
                    "the identified input influencing a backend SQL condition."
                    if confirmed else "The observed response differential did not confirm SQL injection."
                ),
            })
        else:
            common.update({
                "verification_method": validation.get("method") or "Observed SQL-result differential",
                "steps": [
                    "Establish the validator's normal baseline response.",
                    "Submit the validator's fixed lab-specific injection request.",
                    "Compare the number of server-generated database-result records.",
                    "Confirm only when the injected response returns more records than the non-empty baseline.",
                ],
                "interpretation": (
                    "The injected lab response returned more server-generated database-result "
                    "records than the non-empty baseline."
                    if confirmed else "The observed database-result count did not confirm SQL injection."
                ),
            })
        if generic_differential and controlled_execution and confirmed and endpoint and method and parameter and location:
            common["requests"] = [
                {"label": "Baseline", "request": _request_form(method, endpoint, parameter, SQL_CONTROL_VALUE, location)},
                {"label": "TRUE-condition test", "request": _request_form(method, endpoint, parameter, SQL_TRUE_VALUE, location)},
                {"label": "FALSE control", "request": _request_form(method, endpoint, parameter, SQL_FALSE_VALUE, location)},
            ]
    elif vulnerability_type == "command_execution":
        common.update({
            "verification_method": "Synthetic execution-marker differential",
            "steps": [
                "Send the fixed baseline token.",
                "Send the fixed controlled execution probe.",
                "Send the fixed false-control token.",
                "Compare the three responses.",
                "Confirm only when the synthetic marker uniquely appears for the controlled probe.",
            ],
            "interpretation": (
                "The controlled probe caused the fixture's synthetic execution marker to appear, "
                "while neither the baseline nor false-control request produced it."
                if confirmed else "The synthetic marker evidence did not confirm the controlled condition."
            ),
            "safety_note": (
                "This demonstrates command-execution validation and attack-chain logic. "
                "No arbitrary operating-system command or interactive shell was executed."
            ),
        })
        if controlled_execution and confirmed and endpoint and parameter:
            common["requests"] = [
                {"label": "Baseline", "request": _request_form("POST", endpoint, parameter, BASELINE_DIAGNOSTIC_TOKEN, "form")},
                {"label": "Controlled execution probe", "request": _request_form("POST", endpoint, parameter, EXECUTION_PROBE_TOKEN, "form")},
                {"label": "False control", "request": _request_form("POST", endpoint, parameter, CONTROL_PROBE_TOKEN, "form")},
            ]
    elif vulnerability_type == "reflected_xss":
        common.update({
            "verification_method": "Inert HTML reflection",
            "steps": ["Send an inert HTML reflection marker.", "Compare it with the baseline response.", "Confirm only when the inert marker is returned unencoded in HTML context."],
            "interpretation": "An inert HTML test marker was returned unencoded in an HTML context and was absent from the baseline response." if confirmed else "The inert reflection evidence did not confirm reflected XSS.",
        })
    elif vulnerability_type == "information_disclosure":
        common.update({
            "verification_method": "Sensitive-resource response classification",
            "steps": ["Request the scanner-identified resource.", "Check accessibility and content type.", "Classify only configured sensitive-resource signals."],
            "interpretation": "The resource was accessible and exposed content matching configured sensitive-resource classification signals." if confirmed else "The resource evidence did not confirm sensitive information disclosure.",
        })
    if confirmed and not common["requests"]:
        common["request_note"] = "Detailed PoC request not available from the observed evidence."
    return common


def _risk(
    vulnerability_type: str,
    finding: Mapping[str, Any],
    validation: Mapping[str, Any],
) -> Dict[str, Any]:
    profile = RISK_PROFILES.get(vulnerability_type)
    status = validation.get("status") or finding.get("validation_status") or finding.get("status")
    confidence = validation.get("confidence", finding.get("validation_confidence"))
    severity = str(finding.get("severity") or "unknown").lower()
    capabilities = list(finding.get("provides") or [])
    if status != "confirmed" or profile is None:
        return {
            "rating": "Not rated", "cia": profile["cia"] if profile else None,
            "technical_impact": profile["technical_impact"] if profile else [],
            "business": profile["business"] if profile else None,
            "rationale": "Business impact is rated only for confirmed supported findings.",
            "notice": GENERALIZED_RISK_NOTICE, "cvss": "Not supplied",
        }
    rating = SEVERITY_RATING.get(severity, "Medium")
    if vulnerability_type == "command_execution" or "command_execution" in capabilities:
        rating = "Critical"
    elif vulnerability_type == "sql_injection" and "application_compromise" in capabilities:
        rating = "High" if rating != "Critical" else rating
    rationale = (
        f"Confirmed {severity}-severity {vulnerability_type.replace('_', ' ')}"
        f" at {round(float(confidence) * 100)}% confidence"
        f" providing {', '.join(capabilities) or 'the documented technical impact'}."
    )
    return {
        "rating": rating, "cia": profile["cia"],
        "technical_impact": profile["technical_impact"],
        "business": profile["business"], "rationale": rationale,
        "notice": GENERALIZED_RISK_NOTICE, "cvss": "Not supplied",
        "scope_note": "Potential impact of a real confirmed command-execution vulnerability" if vulnerability_type == "command_execution" else None,
    }


def present_finding(
    finding: Mapping[str, Any],
    validation: Mapping[str, Any],
    *,
    controlled_lab: bool,
) -> Dict[str, Any]:
    vulnerability_type = _type(finding.get("vulnerability_type"))
    mapping = {
        "technique_id": finding.get("mitre_technique_id"),
        "technique_name": finding.get("mitre_technique_name"),
        "tactic": finding.get("mitre_tactic"),
    }
    if not mapping["technique_id"] and isinstance(finding.get("mitre_mappings"), list) and finding["mitre_mappings"]:
        persisted = finding["mitre_mappings"][0]
        mapping = {
            "technique_id": persisted.get("technique_id"),
            "technique_name": persisted.get("technique_name"),
            "tactic": persisted.get("tactic"),
        }
    return {
        "finding_id": finding.get("finding_id") or finding.get("id"),
        "vulnerability_type": vulnerability_type,
        "location": {
            "target": finding.get("target"), "endpoint": finding.get("endpoint"),
            "http_method": finding.get("http_method"), "parameter_name": finding.get("parameter_name"),
            "parameter_location": finding.get("parameter_location"),
        },
        "validation": {
            "status": validation.get("status") or finding.get("validation_status") or finding.get("status"),
            "confidence": validation.get("confidence", finding.get("validation_confidence")),
            "validator": validation.get("validator") or validation.get("validator_id"),
            "method": validation.get("method"),
            "reason": _validation_evidence(validation).get("reason") or validation.get("decision_reason"),
        },
        "mitre": mapping if mapping["technique_id"] else None,
        "requires_all": list(finding.get("requires_all") or []),
        "requires_any": list(finding.get("requires_any") or finding.get("requires") or []),
        "provides": list(finding.get("provides") or []),
        "poc": _poc(vulnerability_type, finding, validation, controlled_lab=controlled_lab),
        "risk": _risk(vulnerability_type, finding, validation),
    }


def _pairs(data: Mapping[str, Any]) -> Iterable[tuple[Mapping[str, Any], Mapping[str, Any]]]:
    if isinstance(data.get("finding"), dict):
        finding = dict(data["finding"])
        technique = data.get("technique") if isinstance(data.get("technique"), dict) else {}
        for field in ("technique_id", "technique_name", "tactic"):
            finding_key = f"mitre_{field}"
            if not finding.get(finding_key):
                finding[finding_key] = technique.get(field)
        yield finding, data.get("validation_result") or {}
        return
    validations = data.get("validations")
    if isinstance(validations, dict):
        for item in validations.values():
            yield item.get("finding") or {}, item.get("validation_result") or {}
        return
    findings = data.get("findings") if isinstance(data.get("findings"), list) else []
    results = validations if isinstance(validations, list) else []
    for index, finding in enumerate(findings):
        yield finding, results[index] if index < len(results) else {}


def _path_presentations(
    chains: Sequence[Mapping[str, Any]],
    presentations: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    by_id = {item["finding_id"]: item for item in presentations}
    multi_stage, standalone = [], []
    for chain in chains:
        raw_steps = sorted(chain.get("steps") or [], key=lambda step: step.get("step_number", 0))
        action_steps = [step for step in raw_steps if _type(step.get("vulnerability_type")) not in ENVIRONMENTAL_TYPES]
        dependencies = []
        for current, following in zip(raw_steps, raw_steps[1:]):
            provided = set(current.get("provides") or [])
            required_all = set(following.get("requires_all") or [])
            required_any = set(following.get("requires_any") or following.get("requires") or [])
            for capability in sorted(provided & (required_all | required_any)):
                dependencies.append({
                    "provider_finding_id": current.get("finding_id"),
                    "consumer_finding_id": following.get("finding_id"),
                    "capability": capability,
                    "requirement": "requires_all" if capability in required_all else "requires_any",
                })
        step_views = []
        ratings = []
        cumulative_capabilities = []
        for step in raw_steps:
            detail = by_id.get(step.get("finding_id"), {})
            risk = detail.get("risk") or {}
            ratings.append(risk.get("rating", "Not rated"))
            cumulative_capabilities.extend(step.get("provides") or [])
            step_views.append({**step, "finding_presentation": detail})
        cumulative_rating = max(ratings, key=lambda rating: RATING_ORDER.get(rating, -1), default="Not rated")
        impact = []
        capability_impacts = {
            "application_compromise": "Unauthorized application access",
            "possible_database_access": "Potential data exposure or manipulation",
            "command_execution": "Potential service disruption or wider compromise within the affected execution context",
        }
        for capability in dict.fromkeys(cumulative_capabilities):
            if capability in capability_impacts:
                impact.append(capability_impacts[capability])
        if len(action_steps) > 1:
            earlier_capabilities = list(dict.fromkeys(
                capability
                for step in action_steps[:-1]
                for capability in step.get("provides") or []
            ))
            final_capabilities = list(dict.fromkeys(action_steps[-1].get("provides") or []))
            impact_summary = (
                "Individually, the earlier confirmed stage establishes "
                f"{', '.join(earlier_capabilities) or 'its documented capabilities'}. "
                "When combined with the later confirmed stage, the potential impact "
                f"increases to {', '.join(final_capabilities) or 'the documented downstream capabilities'}."
            )
        else:
            impact_summary = (
                "This is a standalone confirmed finding; it is not presented as a "
                "multi-stage attack progression."
            )
        view = {
            "chain_id": chain.get("chain_id") or chain.get("id"),
            "status": chain.get("status"), "confidence": chain.get("confidence"),
            "steps": step_views, "dependencies": dependencies,
            "cumulative_risk": cumulative_rating,
            "cumulative_capabilities": list(dict.fromkeys(cumulative_capabilities)),
            "potential_business_impact": impact,
            "impact_summary": impact_summary,
            "notice": GENERALIZED_RISK_NOTICE,
        }
        (multi_stage if len(action_steps) > 1 else standalone).append(view)
    return {"multi_stage_paths": multi_stage, "standalone_findings": standalone}


def decorate_pipeline_response(data: Mapping[str, Any], *, controlled_lab: bool) -> Dict[str, Any]:
    """Add presentation-only fields without changing existing response fields."""
    decorated = deepcopy(dict(data))
    presentations = [
        present_finding(finding, validation, controlled_lab=controlled_lab)
        for finding, validation in _pairs(decorated)
    ]
    chains = decorated.get("chains")
    if not isinstance(chains, list):
        chains = (decorated.get("chain_result") or {}).get("chains") or []
    decorated["finding_presentations"] = presentations
    decorated["attack_flow"] = _path_presentations(chains, presentations)
    decorated["presentation_mode"] = "controlled_lab" if controlled_lab else "real_scan"
    return decorated
