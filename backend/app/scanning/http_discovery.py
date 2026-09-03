"""Minimal exact-origin HTTP reachability discovery."""

from __future__ import annotations

from typing import Any, Dict, Optional
from urllib.parse import urljoin, urlsplit

import httpx

from app.scanning.models import ServiceObservation
from app.scanning.scope import AuthorizedTarget, ReconScopeError


class ScopedReconHttpClient:
    """HTTP client that can communicate with one authorized origin only."""

    def __init__(self, target: AuthorizedTarget, *, timeout_seconds: float = 3.0):
        self.target = target
        self._client = httpx.Client(
            follow_redirects=False,
            timeout=timeout_seconds,
            trust_env=False,
        )

    def _scoped_url(self, url: str) -> str:
        resolved = urljoin(f"{self.target.origin}/", url)
        parsed = urlsplit(resolved)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if (
            parsed.scheme.lower(),
            (parsed.hostname or "").lower(),
            port,
        ) != (self.target.scheme, self.target.hostname, self.target.port):
            raise ReconScopeError("request URL is outside the authorized origin")
        return resolved

    def get(self, url: str, params: Optional[Dict[str, str]] = None) -> Any:
        return self._client.get(self._scoped_url(url), params=params)

    def post(self, url: str, data: Optional[Dict[str, str]] = None) -> Any:
        return self._client.post(self._scoped_url(url), data=data)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "ScopedReconHttpClient":
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()


def discover_http_service(
    target: AuthorizedTarget,
    *,
    asset_id: str,
    client: ScopedReconHttpClient,
) -> tuple[ServiceObservation, Dict[str, Any]]:
    response = client.get("/")
    service = ServiceObservation(
        asset_id=asset_id,
        port=target.port,
        protocol="tcp",
        service_name=target.scheme,
        state="open",
        source="http_discovery",
    )
    return service, {
        "status_code": response.status_code,
        "content_type": response.headers.get("content-type"),
    }
