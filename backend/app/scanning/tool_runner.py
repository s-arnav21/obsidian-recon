"""Bounded subprocess execution for explicitly configured scanner binaries."""

from __future__ import annotations

import subprocess
from typing import Sequence


class ScannerToolError(RuntimeError):
    pass


class ScannerToolUnavailableError(ScannerToolError):
    pass


class ScannerToolTimeoutError(ScannerToolError):
    pass


class ScannerOutputError(ScannerToolError):
    pass


def run_scanner_tool(
    arguments: Sequence[str],
    *,
    timeout_seconds: float,
    maximum_output_bytes: int = 2_000_000,
) -> str:
    if not arguments or not all(isinstance(value, str) and value for value in arguments):
        raise ValueError("scanner arguments must be non-empty strings")
    try:
        completed = subprocess.run(
            list(arguments),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
    except FileNotFoundError as exc:
        raise ScannerToolUnavailableError("configured scanner is unavailable") from exc
    except subprocess.TimeoutExpired as exc:
        raise ScannerToolTimeoutError("scanner exceeded its configured timeout") from exc

    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    if len(stdout.encode("utf-8")) > maximum_output_bytes:
        raise ScannerOutputError("scanner output exceeded the configured limit")
    if completed.returncode != 0:
        raise ScannerToolError(
            f"scanner failed with exit code {completed.returncode}; "
            f"stderr_bytes={len(stderr.encode('utf-8'))}"
        )
    return stdout
