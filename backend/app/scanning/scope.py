"""Explicit authorization and exact-origin controls for reconnaissance."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlsplit, urlunsplit


class ReconAuthorizationError(ValueError):
    pass


class ReconScopeError(ValueError):
    pass


@dataclass(frozen=True)
class AuthorizedTarget:
    origin: str
    hostname: str
    port: int
    scheme: str


def _is_loopback(hostname: str) -> bool:
    if hostname == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def normalize_origin(value: str) -> AuthorizedTarget:
    if not isinstance(value, str) or not value.strip():
        raise ReconScopeError("target_url must be a non-empty URL")
    try:
        parsed = urlsplit(value.strip())
        explicit_port = parsed.port
    except ValueError as exc:
        raise ReconScopeError("target_url contains an invalid port") from exc
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.hostname:
        raise ReconScopeError("target_url must be an HTTP origin")
    if parsed.username is not None or parsed.password is not None:
        raise ReconScopeError("target_url must not contain credentials")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ReconScopeError("target_url must be an origin without path or query")

    hostname = parsed.hostname.lower()
    port = explicit_port or (443 if scheme == "https" else 80)
    default_port = 443 if scheme == "https" else 80
    display_host = f"[{hostname}]" if ":" in hostname else hostname
    netloc = display_host if port == default_port else f"{display_host}:{port}"
    return AuthorizedTarget(
        origin=urlunsplit((scheme, netloc, "", "", "")),
        hostname=hostname,
        port=port,
        scheme=scheme,
    )


def authorize_target(
    target_url: str,
    *,
    authorized: bool,
    allowed_origins: Iterable[str] = (),
) -> AuthorizedTarget:
    if authorized is not True:
        raise ReconAuthorizationError(
            "explicit authorization confirmation is required"
        )
    target = normalize_origin(target_url)
    allowed = {normalize_origin(origin).origin for origin in allowed_origins}
    if not _is_loopback(target.hostname) and target.origin not in allowed:
        raise ReconScopeError(
            "reconnaissance target must be loopback or explicitly allowlisted"
        )
    return target
