"""Bounded DNS lookups used by ownership and target-address policy."""

from __future__ import annotations

from typing import Any, Tuple

import dns.exception
import dns.resolver


class DnsLookupError(RuntimeError):
    """A sanitized DNS resolution failure."""


class BoundedDnsResolver:
    """Resolve TXT/A/AAAA records with fixed time and retry bounds."""

    def __init__(
        self,
        *,
        resolver: Any = None,
        timeout_seconds: float = 1.5,
        lifetime_seconds: float = 2.0,
        attempts: int = 2,
    ) -> None:
        if timeout_seconds <= 0 or lifetime_seconds <= 0:
            raise ValueError("DNS timeouts must be positive")
        if attempts < 1 or attempts > 3:
            raise ValueError("DNS attempts must be between 1 and 3")
        self.resolver = resolver or dns.resolver.Resolver(configure=True)
        self.resolver.timeout = timeout_seconds
        self.timeout_seconds = timeout_seconds
        self.lifetime_seconds = lifetime_seconds
        self.attempts = attempts

    def _resolve(self, name: str, record_type: str) -> Tuple[Any, ...]:
        for attempt in range(self.attempts):
            try:
                answer = self.resolver.resolve(
                    name,
                    record_type,
                    search=False,
                    lifetime=self.lifetime_seconds,
                )
                return tuple(answer)
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                return ()
            except (dns.exception.Timeout, dns.resolver.LifetimeTimeout):
                if attempt + 1 == self.attempts:
                    raise DnsLookupError("DNS lookup timed out") from None
            except (dns.resolver.NoNameservers, dns.resolver.YXDOMAIN):
                raise DnsLookupError("DNS lookup failed") from None
            except dns.exception.DNSException:
                raise DnsLookupError("DNS lookup failed") from None
        return ()

    def resolve_txt(self, name: str) -> Tuple[str, ...]:
        values = []
        for record in self._resolve(name, "TXT"):
            segments = getattr(record, "strings", None)
            if not isinstance(segments, (tuple, list)):
                continue
            try:
                value = b"".join(segments).decode("utf-8", errors="strict")
            except (TypeError, UnicodeDecodeError):
                continue
            if value:
                values.append(value)
        return tuple(values)

    def resolve_addresses(self, hostname: str) -> Tuple[str, ...]:
        addresses = []
        for record_type in ("A", "AAAA"):
            for record in self._resolve(hostname, record_type):
                address = getattr(record, "address", None)
                if isinstance(address, str) and address:
                    addresses.append(address)
        return tuple(dict.fromkeys(addresses))
