"""A small SEP-2640 server for a local skills folder: preview what an import will look like before
you publish skills from your own server, and the fixture skillcourier's tests and demo run on.

    skillcourier dev-server ./skills              # stdio, modern + legacy handshake
    skillcourier dev-server ./skills --http 8765  # Streamable HTTP on 127.0.0.1:8765/mcp
"""

from __future__ import annotations

import base64
import json
import sys
import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Literal

from .mcp import LEGACY_PROTOCOL, PROTOCOL, SKILLS_EXT, as_obj
from .spec import sha256, split_frontmatter

Era = Literal["dual", "modern", "legacy"]
JsonObj = dict[str, Any]


class RpcError(Exception):
    def __init__(self, code: int, message: str, http: int = 200) -> None:
        super().__init__(message)
        self.code, self.message, self.http = code, message, http


class SkillDirServer:
    """Protocol logic only; transports wrap :meth:`handle`. Tests poke the ``tamper_*`` hooks."""

    def __init__(self, root: Path, era: Era = "dual", page_size: int = 50) -> None:
        self.root = root.resolve()
        self.era = era
        self.page_size = page_size
        self.initialized = False
        self.tamper_content: dict[str, bytes] = {}  # uri -> bytes served instead of the file
        self.tamper_entry: Callable[[JsonObj], JsonObj] | None = None
        self.calls: list[str] = []

    def skills(self) -> list[tuple[str, Path]]:
        """(skill path, directory) for every SKILL.md under root, nested ones included."""
        out = []
        for md in sorted(self.root.rglob("SKILL.md")):
            rel = md.parent.relative_to(self.root).as_posix()
            if rel != ".":
                out.append((rel, md.parent))
        return out

    def entry(self, rel: str, d: Path) -> JsonObj:
        base = f"skill://{rel}"
        resources = []
        for p in sorted(x for x in d.rglob("*") if x.is_file()):
            data = p.read_bytes()
            uri = f"{base}/{p.relative_to(d).as_posix()}"
            resources.append({"uri": uri, "digest": sha256(data), "size": len(data)})
        fm, _ = split_frontmatter((d / "SKILL.md").read_bytes())
        entry: JsonObj = {"uri": f"{base}/SKILL.md", "frontmatter": fm, "resources": resources}
        return self.tamper_entry(entry) if self.tamper_entry else entry

    def _file_for(self, uri: str) -> bytes:
        if uri in self.tamper_content:
            return self.tamper_content[uri]
        if not uri.startswith("skill://"):
            raise RpcError(-32602, f"unknown resource {uri}")
        path = (self.root / uri[len("skill://"):]).resolve()
        if not path.is_relative_to(self.root) or not path.is_file():
            raise RpcError(-32602, f"unknown resource {uri}")
        return path.read_bytes()

    def capabilities(self) -> JsonObj:
        return {"resources": {}, "extensions": {SKILLS_EXT: {}}}

    def handle(self, msg: JsonObj) -> JsonObj | None:
        return self.handle_http(msg)[0]

    def handle_http(self, msg: JsonObj) -> tuple[JsonObj | None, int]:
        """(reply, HTTP status). Notifications get no reply."""
        method = msg.get("method")
        mid = msg.get("id")
        if "id" not in msg:
            return None, 202
        self.calls.append(str(method))
        try:
            result = self._dispatch(str(method), msg.get("params") or {})
        except RpcError as e:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": e.code, "message": e.message}}, e.http
        return {"jsonrpc": "2.0", "id": mid, "result": result}, 200

    def _dispatch(self, method: str, params: JsonObj) -> JsonObj:
        meta = as_obj(params.get("_meta"))
        modern = "io.modelcontextprotocol/protocolVersion" in meta
        if method == "initialize":
            if self.era == "modern":
                raise RpcError(-32601, "Method not found: initialize")
            self.initialized = True
            return {
                "protocolVersion": LEGACY_PROTOCOL,
                "capabilities": self.capabilities(),
                "serverInfo": {"name": "skillcourier-dev-server", "version": "0"},
            }
        if self.era == "legacy" and not self.initialized:
            raise RpcError(-32000, "Bad Request: Server not initialized", http=400)
        if not modern and not self.initialized:
            raise RpcError(-32020, "missing required request _meta", http=400)
        if modern and meta.get("io.modelcontextprotocol/protocolVersion") != PROTOCOL:
            raise RpcError(-32022, "unsupported protocol version", http=400)
        cache: JsonObj = {"resultType": "complete", "ttlMs": 60000, "cacheScope": "public"}
        if method == "server/discover":
            if self.era == "legacy":  # never reached over HTTP: the not-initialized check fires first
                raise RpcError(-32601, "Method not found")
            return {
                **cache,
                "supportedVersions": [PROTOCOL],
                "capabilities": self.capabilities(),
                "_meta": {"io.modelcontextprotocol/serverInfo": {"name": "skillcourier-dev-server", "version": "0"}},
            }
        if method == "ping":
            return {}
        if method == "skills/list":
            entries = [self.entry(rel, d) for rel, d in self.skills()]
            start = int(params.get("cursor") or 0)
            page = entries[start : start + self.page_size]
            res: JsonObj = {**cache, "skills": page}
            if start + self.page_size < len(entries):
                res["nextCursor"] = str(start + self.page_size)
            return res
        if method == "skills/get":
            uri = params.get("uri")
            for rel, d in self.skills():
                if uri == f"skill://{rel}/SKILL.md":
                    return {**cache, "skill": self.entry(rel, d)}
            raise RpcError(-32602, f"unknown skill {uri}")
        if method == "resources/read":
            uri = str(params.get("uri"))
            data = self._file_for(uri)
            try:
                content: JsonObj = {"uri": uri, "text": data.decode("utf-8")}
            except UnicodeDecodeError:
                content = {"uri": uri, "blob": base64.b64encode(data).decode("ascii")}
            return {**cache, "contents": [content]}
        raise RpcError(-32601, f"Method not found: {method}")


def serve_stdio(server: SkillDirServer) -> None:
    for line in sys.stdin:
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        reply = server.handle(msg) if isinstance(msg, dict) else None
        if reply is not None:
            sys.stdout.write(json.dumps(reply) + "\n")
            sys.stdout.flush()


def _decode_header(v: str | None) -> str | None:
    if v and v.startswith("=?base64?") and v.endswith("?="):
        return base64.b64decode(v[9:-2]).decode("utf-8")
    return v


def make_http_server(server: SkillDirServer, port: int = 0, sse: bool = False) -> ThreadingHTTPServer:
    """Streamable HTTP at /mcp. Validates the request headers the 2026-07-28 transport requires."""

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_: Any) -> None:
            pass

        def do_POST(self) -> None:  # noqa: N802 (http.server API)
            if self.path != "/mcp":
                self._send(404, None)
                return
            try:
                msg = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
            except ValueError:
                self._send(400, None)
                return
            if "id" not in msg:
                self._send(202, None)
                return
            params = msg.get("params") or {}
            meta = params.get("_meta") or {}
            ver = meta.get("io.modelcontextprotocol/protocolVersion")
            if ver is not None:
                want = {"MCP-Protocol-Version": ver, "Mcp-Method": msg.get("method")}
                if msg.get("method") == "resources/read":
                    want["Mcp-Name"] = params.get("uri")
                for h, v in want.items():
                    got = _decode_header(self.headers.get(h))
                    if got != v:
                        err = {"code": -32020, "message": f"header {h} {got!r} != body {v!r}"}
                        self._send(400, {"jsonrpc": "2.0", "id": msg.get("id"), "error": err})
                        return
            reply, status = server.handle_http(msg)
            if msg.get("method") == "initialize" and reply and "result" in reply:
                self.send_response(200)
                self.send_header("Mcp-Session-Id", "dev-session")
                self._body(reply, sse)
                return
            self._send(status, reply, sse)

        def _send(self, status: int, body: JsonObj | None, use_sse: bool = False) -> None:
            self.send_response(status)
            if body is None:
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self._body(body, use_sse)

        def _body(self, body: JsonObj, use_sse: bool) -> None:
            if use_sse:
                note = {"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progress": 1}}
                raw = (f"event: message\ndata: {json.dumps(note)}\n\n" f"data: {json.dumps(body)}\n\n").encode()
                self.send_header("Content-Type", "text/event-stream")
            else:
                raw = json.dumps(body).encode()
                self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    return ThreadingHTTPServer(("127.0.0.1", port), Handler)


def serve_http_background(server: SkillDirServer, sse: bool = False) -> tuple[ThreadingHTTPServer, str]:
    httpd = make_http_server(server, 0, sse)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}/mcp"
