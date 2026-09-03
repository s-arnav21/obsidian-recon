"""Persisted exact-origin DNS TXT proof-of-control workflow."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Optional

from sqlalchemy.orm import Session

from app.db.models import TargetVerificationORM
from app.db.repository import PersistenceRepository
from app.scanning.dns import BoundedDnsResolver, DnsLookupError
from app.scanning.scope import ReconScopeError, normalize_origin


PENDING = "pending"
VERIFIED = "verified"
VERIFICATION_FAILED = "verification_failed"
EXPIRED = "expired"
TOKEN_PREFIX = "obsidian-recon-verification="
TXT_LABEL = "_obsidian-recon"
DEFAULT_CHALLENGE_LIFETIME = timedelta(hours=24)


class TargetVerificationNotFoundError(LookupError):
    pass


@dataclass(frozen=True)
class TargetVerificationView:
    id: str
    canonical_origin: str
    hostname: str
    status: str
    txt_record_name: str
    txt_record_value: Optional[str]
    expires_at: str
    verified_at: Optional[str]
    last_checked_at: Optional[str]
    message: str

    def to_dict(self) -> Dict[str, Any]:
        return dict(self.__dict__)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _timestamp(value: Optional[datetime]) -> Optional[str]:
    return _aware(value).isoformat() if value is not None else None


def txt_record_name(hostname: str) -> str:
    return f"{TXT_LABEL}.{hostname}"


def _record_value(token: str) -> str:
    return f"{TOKEN_PREFIX}{token}"


def _token_digest(record_value: str) -> str:
    return hashlib.sha256(record_value.encode("utf-8")).hexdigest()


def _message(status: str, failure_code: Optional[str]) -> str:
    if status == VERIFIED:
        return "DNS ownership verified for this exact target origin."
    if status == EXPIRED:
        return "The DNS verification challenge expired. Create a new challenge."
    if status == VERIFICATION_FAILED:
        if failure_code == "record_not_found":
            return "The required DNS TXT record was not found yet."
        if failure_code == "record_mismatch":
            return "DNS TXT records were found, but none matched this challenge."
        return "DNS verification could not be completed. Try again shortly."
    return "Add the exact DNS TXT record shown, then verify the challenge."


class TargetVerificationService:
    """Issue, check, and authorize exact-origin DNS challenges."""

    def __init__(
        self,
        *,
        dns_resolver: Any = None,
        token_factory: Callable[[int], str] = secrets.token_urlsafe,
        clock: Callable[[], datetime] = _utc_now,
        challenge_lifetime: timedelta = DEFAULT_CHALLENGE_LIFETIME,
    ) -> None:
        if challenge_lifetime <= timedelta(0):
            raise ValueError("challenge lifetime must be positive")
        self.dns_resolver = dns_resolver or BoundedDnsResolver()
        self.token_factory = token_factory
        self.clock = clock
        self.challenge_lifetime = challenge_lifetime

    def _now(self) -> datetime:
        return _aware(self.clock())

    def _expire_if_needed(
        self,
        record: TargetVerificationORM,
    ) -> TargetVerificationORM:
        if record.status != VERIFIED and _aware(record.expires_at) <= self._now():
            record.status = EXPIRED
            record.challenge_token = None
            record.failure_code = "challenge_expired"
        return record

    def _view(self, record: TargetVerificationORM) -> TargetVerificationView:
        token = record.challenge_token if record.status in {
            PENDING,
            VERIFICATION_FAILED,
        } else None
        return TargetVerificationView(
            id=record.id,
            canonical_origin=record.origin,
            hostname=record.hostname,
            status=record.status,
            txt_record_name=txt_record_name(record.hostname),
            txt_record_value=_record_value(token) if token else None,
            expires_at=_timestamp(record.expires_at) or "",
            verified_at=_timestamp(record.verified_at),
            last_checked_at=_timestamp(record.last_checked_at),
            message=_message(record.status, record.failure_code),
        )

    @staticmethod
    def _verification_target(target_url: str):
        target = normalize_origin(target_url)
        try:
            ipaddress.ip_address(target.hostname)
        except ValueError:
            pass
        else:
            raise ReconScopeError(
                "DNS ownership verification requires a domain hostname"
            )
        if target.hostname == "localhost":
            raise ReconScopeError(
                "DNS ownership verification is not required for loopback targets"
            )
        if len(txt_record_name(target.hostname)) > 253:
            raise ReconScopeError(
                "target hostname is too long for DNS verification"
            )
        if target.scheme != "https":
            raise ReconScopeError(
                "external target verification requires an HTTPS origin"
            )
        return target

    def create_challenge(
        self,
        session: Session,
        *,
        target_url: str,
    ) -> TargetVerificationView:
        target = self._verification_target(target_url)
        repository = PersistenceRepository(session)
        verified = repository.verified_target_verification(target.origin)
        if verified is not None:
            return self._view(verified)

        existing = repository.latest_target_verification(target.origin)
        if existing is not None:
            self._expire_if_needed(existing)
            if existing.status in {PENDING, VERIFICATION_FAILED}:
                return self._view(existing)

        token = self.token_factory(32)
        if not isinstance(token, str) or len(token) < 32:
            raise RuntimeError("verification token generation failed")
        value = _record_value(token)
        if existing is None:
            record = repository.create_target_verification(
                origin=target.origin,
                hostname=target.hostname,
                token_digest=_token_digest(value),
                challenge_token=token,
                expires_at=self._now() + self.challenge_lifetime,
            )
        else:
            record = existing
            now = self._now()
            record.token_digest = _token_digest(value)
            record.challenge_token = token
            record.status = PENDING
            record.created_at = now
            record.expires_at = now + self.challenge_lifetime
            record.verified_at = None
            record.last_checked_at = None
            record.failure_code = None
            session.flush()
        return self._view(record)

    def get_challenge(
        self,
        session: Session,
        verification_id: str,
    ) -> TargetVerificationView:
        record = PersistenceRepository(session).get_target_verification(
            verification_id
        )
        if record is None:
            raise TargetVerificationNotFoundError("target verification not found")
        self._expire_if_needed(record)
        session.flush()
        return self._view(record)

    def verify_challenge(
        self,
        session: Session,
        verification_id: str,
    ) -> TargetVerificationView:
        record = PersistenceRepository(session).get_target_verification(
            verification_id
        )
        if record is None:
            raise TargetVerificationNotFoundError("target verification not found")
        self._expire_if_needed(record)
        if record.status in {VERIFIED, EXPIRED}:
            session.flush()
            return self._view(record)

        now = self._now()
        record.last_checked_at = now
        try:
            values = self.dns_resolver.resolve_txt(
                txt_record_name(record.hostname)
            )
        except DnsLookupError:
            record.status = VERIFICATION_FAILED
            record.failure_code = "dns_lookup_failed"
            session.flush()
            return self._view(record)

        matched = any(
            isinstance(value, str)
            and hmac.compare_digest(_token_digest(value), record.token_digest)
            for value in values
        )
        if matched:
            record.status = VERIFIED
            record.verified_at = now
            record.failure_code = None
            record.challenge_token = None
        else:
            record.status = VERIFICATION_FAILED
            record.failure_code = (
                "record_mismatch" if values else "record_not_found"
            )
        session.flush()
        return self._view(record)

    def is_origin_verified(self, session: Session, origin: str) -> bool:
        return (
            PersistenceRepository(session).verified_target_verification(origin)
            is not None
        )

    def resolve_addresses(self, hostname: str) -> tuple[str, ...]:
        return tuple(self.dns_resolver.resolve_addresses(hostname))
