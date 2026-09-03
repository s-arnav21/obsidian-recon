"""Nmap service-discovery adapter with bounded XML parsing."""

from __future__ import annotations

import re
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass
from typing import Callable, List

from app.scanning.models import ServiceObservation
from app.scanning.scope import AuthorizedTarget
from app.scanning.tool_runner import ScannerOutputError, run_scanner_tool


@dataclass(frozen=True)
class NmapDiscovery:
    ip_addresses: tuple[str, ...]
    services: tuple[ServiceObservation, ...]


_STANDARD_NMAP_DOCTYPE = re.compile(
    r"^[ \t]*<!DOCTYPE[ \t]+nmaprun[ \t]*>[ \t]*(?:\r?\n|$)",
    flags=re.IGNORECASE | re.MULTILINE,
)


def _remove_standard_nmap_doctype(output: str) -> str:
    """Remove Nmap's fixed empty DOCTYPE without allowing DTD processing."""
    matches = list(_STANDARD_NMAP_DOCTYPE.finditer(output))
    if len(matches) > 1:
        raise ScannerOutputError("Nmap XML contains an unsafe DTD declaration")
    sanitized = _STANDARD_NMAP_DOCTYPE.sub("", output, count=1)
    upper = sanitized.upper()
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
        raise ScannerOutputError("Nmap XML contains an unsafe DTD declaration")
    return sanitized


def parse_nmap_discovery(
    output: str,
    *,
    asset_id: str,
    maximum_output_bytes: int = 2_000_000,
) -> NmapDiscovery:
    if not isinstance(output, str):
        raise TypeError("Nmap output must be text")
    if len(output.encode("utf-8")) > maximum_output_bytes:
        raise ScannerOutputError("Nmap output exceeded the configured limit")
    sanitized_output = _remove_standard_nmap_doctype(output)
    try:
        root = ElementTree.fromstring(sanitized_output)
    except ElementTree.ParseError as exc:
        raise ScannerOutputError("Nmap returned malformed XML") from exc

    ip_addresses = tuple(
        address
        for element in root.findall("./host/address")
        if element.get("addrtype") in {"ipv4", "ipv6"}
        for address in [element.get("addr")]
        if address
    )
    observations: List[ServiceObservation] = []
    for port_element in root.findall("./host/ports/port"):
        state = port_element.find("state")
        if state is None or state.get("state") != "open":
            continue
        try:
            port = int(port_element.get("portid", ""))
        except ValueError as exc:
            raise ScannerOutputError("Nmap returned an invalid port") from exc
        service = port_element.find("service")
        observations.append(ServiceObservation(
            asset_id=asset_id,
            port=port,
            protocol=port_element.get("protocol"),
            service_name=service.get("name") if service is not None else None,
            product=service.get("product") if service is not None else None,
            version=service.get("version") if service is not None else None,
            state="open",
            source="nmap",
        ))
    return NmapDiscovery(
        ip_addresses=ip_addresses,
        services=tuple(observations),
    )


def parse_nmap_xml(
    output: str,
    *,
    asset_id: str,
    maximum_output_bytes: int = 2_000_000,
) -> List[ServiceObservation]:
    """Compatibility view returning only open services."""
    return list(parse_nmap_discovery(
        output,
        asset_id=asset_id,
        maximum_output_bytes=maximum_output_bytes,
    ).services)


class NmapScanner:
    def __init__(
        self,
        binary_path: str = "nmap",
        *,
        timeout_seconds: float = 30.0,
        runner: Callable[..., str] = run_scanner_tool,
    ) -> None:
        self.binary_path = binary_path
        self.timeout_seconds = timeout_seconds
        self.runner = runner

    def scan(
        self,
        target: AuthorizedTarget,
        *,
        asset_id: str,
    ) -> NmapDiscovery:
        output = self.runner(
            [
                self.binary_path,
                "-Pn",
                "-sV",
                "--version-light",
                "--max-retries",
                "1",
                "--host-timeout",
                "20s",
                "-p",
                str(target.port),
                "-oX",
                "-",
                (
                    target.resolved_addresses[0]
                    if target.resolved_addresses
                    else target.hostname
                ),
            ],
            timeout_seconds=self.timeout_seconds,
            scanner_name="nmap",
        )
        return parse_nmap_discovery(output, asset_id=asset_id)
