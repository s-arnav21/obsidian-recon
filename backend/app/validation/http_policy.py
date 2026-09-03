"""Shared conservative policy for mutable HTTP header validation."""

from __future__ import annotations

import re
from typing import Optional


SAFE_MUTATION_HEADERS = frozenset({
    "user-agent",
    "referer",
    "x-forwarded-for",
})
SENSITIVE_HEADERS = frozenset({
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
})
HEADER_NAME_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


def header_mutation_error(header_name: str) -> Optional[str]:
    """Return a stable reason when a header is unsafe or unsupported."""
    normalized = header_name.strip().lower()
    if normalized in SENSITIVE_HEADERS:
        return "sensitive_header_not_allowed"
    if (
        normalized not in SAFE_MUTATION_HEADERS
        or not HEADER_NAME_RE.fullmatch(header_name.strip())
    ):
        return "unsupported_header_parameter"
    return None
