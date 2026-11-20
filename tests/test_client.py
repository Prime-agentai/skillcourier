"""Protocol behaviour against the dev server over both transports and both eras."""

from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest

from skillcourier.devserver import SkillDirServer, serve_http_background
from skillcourier.mcp import AuthRequired, Endpoint, McpClient, TransportError
from skillcourier.spec import parse_entry, verify_bytes


def http(url: str) -> Endpoint:
    return Endpoint("dev", "http", url=url)


def stdio(skills_dir: Path, *extra: str) -> Endpoint:
    return Endpoint(
        "dev", "stdio", command=sys.executable, args=["-m", "skillcourier", "dev-server", str(skills_dir), *extra],
        env={"PYTHONPATH": str(Path(__file__).resolve().parent.parent / "src")},
    )


def roundtrip(client: McpClient) -> None:
    """List, then fetch and verify every file of every skill, including the non-ASCII and binary ones."""
    assert client.info is not None and client.info.skills
    entries = [parse_entry(raw) for raw in client.list_skills()]
    assert sorted("/".join(e.path_segments) for e in entries) == [
        "acme/billing/refunds", "acme/support/refunds", "db-migrate", "release-notes",
    ]
    for e in entries:
        for f in e.files or ():
            verify_bytes(client.read_resource(f.uri), f)


@pytest.mark.parametrize("sse", [False, True])
def test_modern_http_with_header_validation(skills_dir: Path, sse: bool) -> None:
    server = SkillDirServer(skills_dir, page_size=1)  # forces pagination
    httpd, url = serve_http_background(server, sse=sse)
    try:
        with McpClient(http(url)) as c:
            assert c.info is not None and c.info.era == "modern"
            roundtrip(c)
        # every request carried matching MCP-Protocol-Version / Mcp-Method / Mcp-Name headers,
        # or the server would have answered -32020 and roundtrip() would have raised
        assert server.calls.count("skills/list") == 4
        assert "initialize" not in server.calls
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_legacy_http_falls_back_to_initialize(skills_dir: Path) -> None:
    server = SkillDirServer(skills_dir, era="legacy")
    httpd, url = serve_http_background(server)
    try:
        with McpClient(http(url)) as c:
            assert c.info is not None and c.info.era == "legacy" and c.info.protocol == "2025-11-25"
            roundtrip(c)
        assert server.calls[:2] == ["server/discover", "initialize"]
    finally:
        httpd.shutdown()
        httpd.server_close()


@pytest.mark.parametrize(("extra", "era"), [((), "modern"), (("--legacy",), "legacy")])
def test_stdio_both_eras(skills_dir: Path, extra: tuple[str, ...], era: str) -> None:
    with McpClient(stdio(skills_dir, *extra), timeout=20) as c:
        assert c.info is not None and c.info.era == era
        roundtrip(c)


def test_stdio_process_that_dies_reports_stderr() -> None:
    ep = Endpoint("dead", "stdio", command=sys.executable, args=["-c", "import sys; sys.stderr.write('boom'); sys.exit(3)"])
    with pytest.raises(TransportError, match="boom"):
        McpClient(ep, timeout=5).connect()


def test_missing_command_is_a_transport_error() -> None:
    with pytest.raises(TransportError, match="cannot start"):
        McpClient(Endpoint("x", "stdio", command="/nonexistent/skillcourier-test-binary")).connect()


class _Canned(BaseHTTPRequestHandler):
    status = 401
    body: dict[str, Any] | None = None

    def log_message(self, *_: Any) -> None:
        pass

    def do_POST(self) -> None:  # noqa: N802
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        raw = json.dumps(self.body).encode() if self.body else b""
        self.send_response(self.status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def canned(status: int, body: dict[str, Any] | None) -> tuple[ThreadingHTTPServer, str]:
    handler = type("H", (_Canned,), {"status": status, "body": body})
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}/mcp"


def test_401_is_auth_required_not_a_fallback() -> None:
    httpd, url = canned(401, None)
    try:
        with pytest.raises(AuthRequired, match="OAuth"):
            McpClient(http(url)).connect()
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_modern_version_error_does_not_fall_back_to_initialize() -> None:
    body = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32022, "message": "nope", "data": {"supported": ["2027-01-01"], "requested": "2026-07-28"}}}
    httpd, url = canned(400, body)
    try:
        with pytest.raises(TransportError, match="not falling back"):
            McpClient(http(url)).connect()
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_unreachable_server() -> None:
    with pytest.raises(TransportError, match="cannot reach"):
        McpClient(http("http://127.0.0.1:9/mcp"), timeout=2).connect()
