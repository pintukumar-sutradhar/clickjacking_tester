from __future__ import annotations
import asyncio
import socket
import threading
from typing import Optional
import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse, PlainTextResponse
from app.core.models import ServerState, ServerStatus


def is_port_available(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
            return True
        except OSError:
            return False


def find_random_available_port(host: str = "127.0.0.1") -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]


class PoCServer:

    def __init__(self) -> None:
        self._app = FastAPI(
            title="Clickjacking Tester Local Server", docs_url=None, redoc_url=None
        )
        self._filename: str = "poc.html"
        self._content: str = "<html><body>No PoC generated yet.</body></html>"
        self._lock = threading.Lock()
        self._server: Optional[uvicorn.Server] = None
        self._thread: Optional[threading.Thread] = None
        self.status = ServerStatus()
        self._register_routes()

    def _register_routes(self) -> None:

        @self._app.get("/health", response_class=PlainTextResponse)
        async def health() -> str:
            return "ok"

        @self._app.get("/{path_name:path}", response_class=HTMLResponse)
        async def serve_poc(path_name: str) -> HTMLResponse:
            with self._lock:
                if path_name in ("", self._filename):
                    return HTMLResponse(content=self._content, status_code=200)
            return HTMLResponse(content="<h1>404 Not Found</h1>", status_code=404)

    def set_content(self, filename: str, html: str) -> None:
        with self._lock:
            self._filename = filename
            self._content = html
        self.status.filename = filename

    def start(self, host: str = "127.0.0.1", port: int = 8765) -> ServerStatus:
        if self.status.state == ServerState.RUNNING:
            return self.status
        if not is_port_available(port, host):
            self.status = ServerStatus(
                state=ServerState.ERROR,
                host=host,
                port=port,
                filename=self._filename,
                message=f"Port {port} is already in use.",
            )
            return self.status
        self.status = ServerStatus(
            state=ServerState.STARTING, host=host, port=port, filename=self._filename
        )
        config = uvicorn.Config(
            self._app, host=host, port=port, log_level="warning", loop="asyncio"
        )
        self._server = uvicorn.Server(config)

        def _run() -> None:
            asyncio.run(self._server.serve())

        self._thread = threading.Thread(target=_run, daemon=True)
        self._thread.start()
        self._wait_until_bound(host, port)
        self.status = ServerStatus(
            state=ServerState.RUNNING,
            host=host,
            port=port,
            filename=self._filename,
            message="Server running.",
        )
        return self.status

    def _wait_until_bound(self, host: str, port: int, timeout: float = 3.0) -> None:
        import time as _time

        deadline = _time.monotonic() + timeout
        while _time.monotonic() < deadline:
            if not is_port_available(port, host):
                _time.sleep(0.15)
                return
            _time.sleep(0.05)

    def stop(self) -> ServerStatus:
        if self._server is not None:
            self._server.should_exit = True
        if self._thread is not None:
            self._thread.join(timeout=5)
        self._server = None
        self._thread = None
        self.status = ServerStatus(
            state=ServerState.STOPPED,
            host=self.status.host,
            port=None,
            filename=self._filename,
            message="Server stopped.",
        )
        return self.status

    def restart(
        self, host: str = "127.0.0.1", port: Optional[int] = None
    ) -> ServerStatus:
        use_port = port if port is not None else self.status.port or 8765
        self.stop()
        return self.start(host=host, port=use_port)
