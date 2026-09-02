"""Deliberately vulnerable loopback-only application for integration tests."""

from __future__ import annotations

import socket
import threading
import time
from typing import Optional

import uvicorn
from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, PlainTextResponse


app = FastAPI(title="Obsidian Recon Local Integration Fixture")
MANUAL_HOST = "127.0.0.1"
MANUAL_PORT = 8090
MANUAL_TARGET_URL = f"http://{MANUAL_HOST}:{MANUAL_PORT}"

_SQLI_BASELINE_BODY = (
    "<html><body>synthetic item available "
    + ("A" * 500)
    + "</body></html>"
)
_SQLI_FALSE_BODY = (
    "<html><body>synthetic item denied "
    + ("Z" * 500)
    + "</body></html>"
)
SYNTHETIC_EXPOSURE_BODY = (
    "APP_MODE=synthetic-integration-test\n"
    "SERVICE_TOKEN=FAKE-NOT-A-REAL-SECRET\n"
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ready"}


@app.get("/items", response_class=HTMLResponse)
def items(item_id: str = Query(alias="id")) -> HTMLResponse:
    """Simulate deterministic boolean-response SQL injection behavior."""
    if item_id in {"1", "1 AND 1=1"}:
        return HTMLResponse(_SQLI_BASELINE_BODY)
    if item_id == "1 AND 1=2":
        return HTMLResponse(_SQLI_FALSE_BODY)
    return HTMLResponse("<html><body>synthetic item lookup</body></html>")


@app.get("/search", response_class=HTMLResponse)
def search(q: str) -> HTMLResponse:
    """Deliberately reflect only the supplied test value without encoding."""
    return HTMLResponse(f"<html><body>{q}</body></html>")


@app.get("/debug-config", response_class=PlainTextResponse)
def debug_config() -> PlainTextResponse:
    """Return static synthetic classifier data; never read host environment."""
    return PlainTextResponse(SYNTHETIC_EXPOSURE_BODY)


class LocalVulnerableAppServer:
    """Start and stop the fixture on a pre-bound ephemeral loopback socket."""

    def __init__(self) -> None:
        self._socket: Optional[socket.socket] = None
        self._server: Optional[uvicorn.Server] = None
        self._thread: Optional[threading.Thread] = None
        self.origin: Optional[str] = None

    @property
    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self) -> str:
        if self.is_running:
            raise RuntimeError("local vulnerable app is already running")

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(("127.0.0.1", 0))
            server_socket.listen(128)
        except Exception:
            server_socket.close()
            raise
        port = server_socket.getsockname()[1]

        config = uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            log_level="error",
            access_log=False,
            lifespan="off",
        )
        server = uvicorn.Server(config)
        thread = threading.Thread(
            target=server.run,
            kwargs={"sockets": [server_socket]},
            name="obsidian-local-vulnerable-app",
            daemon=True,
        )

        self._socket = server_socket
        self._server = server
        self._thread = thread
        self.origin = f"http://127.0.0.1:{port}"
        thread.start()

        deadline = time.monotonic() + 5.0
        while not server.started:
            if not thread.is_alive():
                self.stop()
                raise RuntimeError("local vulnerable app failed to start")
            if time.monotonic() >= deadline:
                self.stop()
                raise TimeoutError("local vulnerable app startup timed out")
            time.sleep(0.01)
        return self.origin

    def stop(self) -> None:
        if self._server is not None:
            self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            if self._thread.is_alive() and self._server is not None:
                self._server.force_exit = True
                self._thread.join(timeout=1.0)
        if self._socket is not None:
            self._socket.close()

        self._socket = None
        self._server = None
        self._thread = None
        self.origin = None

    def __enter__(self) -> "LocalVulnerableAppServer":
        self.start()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.stop()


def run_manual_server() -> None:
    """Run the fixed developer fixture until interrupted with Ctrl+C."""
    print(f"Obsidian Recon local fixture target: {MANUAL_TARGET_URL}", flush=True)
    uvicorn.run(
        app,
        host=MANUAL_HOST,
        port=MANUAL_PORT,
        log_level="info",
        access_log=False,
        lifespan="off",
    )


if __name__ == "__main__":
    run_manual_server()
