"""Minimal session preparation for an explicitly configured local DVWA lab."""

from __future__ import annotations

import os
from contextlib import contextmanager
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any, Callable, Iterator, Optional

import httpx


DVWA_BASE_URL_ENV = "DVWA_BASE_URL"
DVWA_USERNAME_ENV = "DVWA_USERNAME"
DVWA_PASSWORD_ENV = "DVWA_PASSWORD"
DVWA_TIMEOUT_ENV = "DVWA_TIMEOUT_SECONDS"
DEFAULT_TIMEOUT_SECONDS = 10.0
DVWA_SECURITY_LEVEL = "low"


class DVWALabError(RuntimeError):
    """Base error for the disposable DVWA development adapter."""


class DVWALabConfigurationError(DVWALabError):
    """Raised when required local-lab settings are absent or invalid."""


class DVWALabConnectionError(DVWALabError):
    """Raised when the configured lab cannot be reached successfully."""


class DVWALabSetupError(DVWALabError):
    """Raised when login or session preparation does not succeed."""


@dataclass(frozen=True)
class DVWALabConfig:
    """Environment-backed settings for one replaceable DVWA test target."""

    base_url: str
    username: str
    password: str = field(repr=False)
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS

    def __post_init__(self) -> None:
        for field_name in ("base_url", "username", "password"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise DVWALabConfigurationError(
                    f"{field_name} must be configured for local_lab mode"
                )
        if not 0.1 <= self.timeout_seconds <= 60.0:
            raise DVWALabConfigurationError(
                "DVWA_TIMEOUT_SECONDS must be between 0.1 and 60"
            )

    @classmethod
    def from_environment(cls) -> "DVWALabConfig":
        values = {
            "base_url": os.getenv(DVWA_BASE_URL_ENV, "").strip(),
            "username": os.getenv(DVWA_USERNAME_ENV, "").strip(),
            "password": os.getenv(DVWA_PASSWORD_ENV, ""),
        }
        missing = [
            env_name
            for field_name, env_name in (
                ("base_url", DVWA_BASE_URL_ENV),
                ("username", DVWA_USERNAME_ENV),
                ("password", DVWA_PASSWORD_ENV),
            )
            if not values[field_name]
        ]
        if missing:
            raise DVWALabConfigurationError(
                "missing local-lab configuration: " + ", ".join(missing)
            )

        timeout_raw = os.getenv(
            DVWA_TIMEOUT_ENV,
            str(DEFAULT_TIMEOUT_SECONDS),
        )
        try:
            timeout = float(timeout_raw)
        except ValueError as exc:
            raise DVWALabConfigurationError(
                "DVWA_TIMEOUT_SECONDS must be numeric"
            ) from exc

        return cls(timeout_seconds=timeout, **values)


class _UserTokenParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.token: Optional[str] = None
        self.input_names: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        if tag.lower() != "input":
            return
        attributes = dict(attrs)
        name = attributes.get("name")
        if name:
            self.input_names.add(name)
        if attributes.get("name") == "user_token":
            self.token = attributes.get("value")


def _extract_user_token(html: str) -> Optional[str]:
    parser = _UserTokenParser()
    parser.feed(html)
    return parser.token


def _contains_input(html: str, input_name: str) -> bool:
    parser = _UserTokenParser()
    parser.feed(html)
    return input_name in parser.input_names


def _raise_for_status(response: Any) -> None:
    method = getattr(response, "raise_for_status", None)
    if callable(method):
        method()


class DVWALabAdapter:
    """Create a prepared HTTP session solely for the existing DVWA validator."""

    def __init__(
        self,
        config: DVWALabConfig,
        *,
        client_factory: Callable[..., Any] = httpx.Client,
    ) -> None:
        if not isinstance(config, DVWALabConfig):
            raise TypeError("config must be a DVWALabConfig")
        if not callable(client_factory):
            raise TypeError("client_factory must be callable")
        self.config = config
        self._client_factory = client_factory

    @classmethod
    def from_environment(cls) -> "DVWALabAdapter":
        return cls(DVWALabConfig.from_environment())

    @property
    def base_url(self) -> str:
        return self.config.base_url.rstrip("/")

    def _url(self, path: str) -> str:
        return f"{self.base_url}/{path.lstrip('/')}"

    def _prepare_session(self, client: Any) -> None:
        login_url = self._url("login.php")
        login_page = client.get(login_url)
        _raise_for_status(login_page)

        form = {
            "username": self.config.username,
            "password": self.config.password,
            "Login": "Login",
        }
        token = _extract_user_token(getattr(login_page, "text", ""))
        if token:
            form["user_token"] = token

        login_response = client.post(login_url, data=form)
        _raise_for_status(login_response)
        response_text = getattr(login_response, "text", "").lower()
        response_url = str(getattr(login_response, "url", "")).lower()
        if "setup.php" in response_url:
            raise DVWALabSetupError(
                "DVWA setup is incomplete; initialize the local lab database"
            )
        if "login failed" in response_text or (
            "login.php" in response_url
            and _contains_input(response_text, "username")
        ):
            raise DVWALabSetupError(
                "DVWA login failed; verify the configured lab credentials"
            )

        cookies = getattr(client, "cookies", None)
        if cookies is None or not callable(getattr(cookies, "set", None)):
            raise DVWALabSetupError(
                "DVWA session does not expose a writable cookie jar"
            )
        # Remove ALL existing security cookies before setting ours.
        # httpx raises CookieConflict if duplicates exist.
        for c in list(client.cookies.jar):
            if c.name == "security":
                client.cookies.jar.clear(c.domain, c.path, c.name)
        cookies.set("security", DVWA_SECURITY_LEVEL, domain="127.0.0.1", path="/")

    @contextmanager
    def session(self) -> Iterator[Any]:
        client = None
        try:
            client = self._client_factory(
                follow_redirects=True,
                timeout=self.config.timeout_seconds,
            )
            self._prepare_session(client)
            yield client
        except DVWALabError:
            raise
        except (httpx.HTTPError, OSError, TimeoutError) as exc:
            raise DVWALabConnectionError(
                "could not complete the configured DVWA lab request"
            ) from exc
        finally:
            if client is not None:
                close = getattr(client, "close", None)
                if callable(close):
                    close()
