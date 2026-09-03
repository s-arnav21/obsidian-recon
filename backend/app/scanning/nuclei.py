"""Nuclei JSONL candidate adapter; detection is not validation."""

from __future__ import annotations

import json
from typing import Any, Callable, Dict, List
from urllib.parse import urlsplit

from app.scanning.models import ScannerCandidateRecord
from app.scanning.scope import AuthorizedTarget, ReconScopeError
from app.scanning.tool_runner import ScannerOutputError, run_scanner_tool


def _same_origin(url: str, target: AuthorizedTarget) -> bool:
    try:
        parsed = urlsplit(url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return False
    return (
        parsed.scheme.lower(),
        (parsed.hostname or "").lower(),
        port,
    ) == (target.scheme, target.hostname, target.port)


def _optional_metadata(metadata: Dict[str, Any], name: str) -> str | None:
    value = metadata.get(name)
    return value.strip() if isinstance(value, str) and value.strip() else None


def _evidence_references(info: Dict[str, Any]) -> List[str]:
    references = info.get("reference", [])
    if isinstance(references, str):
        references = [references]
    if not isinstance(references, list):
        return []
    return [
        reference.strip()
        for reference in references
        if isinstance(reference, str) and reference.strip()
    ]


def parse_nuclei_jsonl(
    output: str,
    *,
    target: AuthorizedTarget,
    scan_id: str,
    asset_id: str,
    maximum_output_bytes: int = 2_000_000,
) -> List[ScannerCandidateRecord]:
    if not isinstance(output, str):
        raise TypeError("Nuclei output must be text")
    if len(output.encode("utf-8")) > maximum_output_bytes:
        raise ScannerOutputError("Nuclei output exceeded the configured limit")

    candidates: List[ScannerCandidateRecord] = []
    for line_number, line in enumerate(output.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ScannerOutputError(
                f"Nuclei returned malformed JSONL at line {line_number}"
            ) from exc
        if not isinstance(item, dict):
            raise ScannerOutputError("Nuclei JSONL records must be objects")

        matched_at = item.get("matched-at") or item.get("matched_at")
        if not isinstance(matched_at, str) or not _same_origin(matched_at, target):
            raise ReconScopeError("Nuclei candidate is outside the authorized origin")
        parsed_match = urlsplit(matched_at)
        endpoint = parsed_match.path or "/"
        info = item.get("info") if isinstance(item.get("info"), dict) else {}
        metadata = (
            info.get("metadata")
            if isinstance(info.get("metadata"), dict)
            else {}
        )
        template_id = item.get("template-id") or item.get("template_id")
        if not isinstance(template_id, str) or not template_id.strip():
            raise ScannerOutputError("Nuclei candidate is missing template-id")

        candidates.append(ScannerCandidateRecord(
            record_id=f"nuclei-{scan_id}-{line_number}",
            scan_id=scan_id,
            asset_id=asset_id,
            target=target.origin,
            scanner_name="nuclei",
            scanner_template_id=template_id.strip(),
            vulnerability_type=(
                _optional_metadata(metadata, "obsidian-vulnerability-type")
                or "nuclei_candidate"
            ),
            severity=str(info.get("severity") or "unknown").lower(),
            endpoint=endpoint,
            http_method=_optional_metadata(metadata, "obsidian-http-method"),
            parameter_name=_optional_metadata(metadata, "obsidian-parameter-name"),
            parameter_location=_optional_metadata(
                metadata,
                "obsidian-parameter-location",
            ),
            evidence={
                "scanner": "nuclei",
                "template_id": template_id.strip(),
                "template_name": info.get("name"),
                "matched_at": matched_at,
                "matcher_name": item.get("matcher-name"),
            },
            evidence_refs=_evidence_references(info),
            observed_at=(
                item["timestamp"].strip()
                if isinstance(item.get("timestamp"), str)
                and item["timestamp"].strip()
                else None
            ),
        ))
    return candidates


class NucleiScanner:
    def __init__(
        self,
        binary_path: str = "nuclei",
        *,
        timeout_seconds: float = 60.0,
        runner: Callable[..., str] = run_scanner_tool,
    ) -> None:
        self.binary_path = binary_path
        self.timeout_seconds = timeout_seconds
        self.runner = runner

    def scan(
        self,
        target: AuthorizedTarget,
        *,
        scan_id: str,
        asset_id: str,
    ) -> List[ScannerCandidateRecord]:
        output = self.runner(
            [
                self.binary_path,
                "-u",
                target.origin,
                "-jsonl",
                "-silent",
                "-no-color",
                "-disable-redirects",
                "-no-interactsh",
            ],
            timeout_seconds=self.timeout_seconds,
        )
        return parse_nuclei_jsonl(
            output,
            target=target,
            scan_id=scan_id,
            asset_id=asset_id,
        )
