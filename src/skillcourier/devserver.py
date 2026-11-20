"""A small SEP-2640 server for a local skills folder: preview what an import will look like before
you publish skills from your own server, and the fixture skillcourier's tests and demo run on.

    skillcourier dev-server ./skills              # stdio, modern + legacy handshake
    skillcourier dev-server ./skills --http 8765  # Streamable HTTP on 127.0.0.1:8765/mcp
    skillcourier dev-server ./skills --http 8765 --oauth  # ... behind a mock OAuth server
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import sys
import threading
import time
import urllib.parse
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


class MockAuthServer:
    """A strict, auto-approving OAuth 2.1 authorization server for the dev server and the tests.

    Strict where a client could be sloppy: exact redirect URIs, PKCE S256 only, the ``resource``
    indicator on both legs, audience-bound tokens, refresh token rotation, ``iss`` in the callback.
    The knobs on the instance let tests break one rule at a time.
    """

    def __init__(self, scope: str = "skills:read", token_ttl: int = 3600) -> None:
        self.scope = scope
        self.token_ttl = token_ttl
        self.base = ""  # set once the HTTP server knows its port
        self.clients: dict[str, JsonObj] = {}
        self.codes: dict[str, JsonObj] = {}
        self.access: dict[str, JsonObj] = {}
        self.refresh: dict[str, JsonObj] = {}
        self.revoked: list[str] = []
        self.registrations = 0
        self.grant_scope: str | None = None  # grant this instead of what was asked (step-up tests)
        self.iss_override: str | None = None  # send a wrong iss (mix-up tests)
        self.prm_resource_override: str | None = None  # wrong resource in metadata
        self.s256 = True  # advertise S256
        self.seen_auth: list[str | None] = []  # Authorization header of every /mcp request

    @property
    def resource(self) -> str:
        return f"{self.base}/mcp"

    def prm(self) -> JsonObj:
        return {
            "resource": self.prm_resource_override or self.resource,
            "authorization_servers": [self.base],
            "scopes_supported": self.scope.split(),
            "bearer_methods_supported": ["header"],
            "resource_name": "skillcourier dev server",
        }

    def as_meta(self) -> JsonObj:
        return {
            "issuer": self.base,
            "authorization_endpoint": f"{self.base}/authorize",
            "token_endpoint": f"{self.base}/token",
            "registration_endpoint": f"{self.base}/register",
            "revocation_endpoint": f"{self.base}/revoke",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": ["none"],
            "code_challenge_methods_supported": ["S256"] if self.s256 else ["plain"],
            "authorization_response_iss_parameter_supported": True,
        }

    def www(self, error: str | None = None) -> str:
        meta = f"{self.base}/.well-known/oauth-protected-resource/mcp"
        out = f'Bearer resource_metadata="{meta}", scope="{self.scope}"'
        return out + (f', error="{error}"' if error else "")

    def check_bearer(self, header: str | None) -> tuple[int, str | None]:
        """(200|401|403, error) for an /mcp request."""
        self.seen_auth.append(header)
        if not header or not header.startswith("Bearer "):
            return 401, None
        tok = self.access.get(header[7:])
        if tok is None or tok["exp"] < time.time() or tok["resource"] != self.resource:
            return 401, "invalid_token"
        if not set(self.scope.split()) <= set(tok["scope"].split()):
            return 403, "insufficient_scope"
        return 200, None

    def register(self, req: JsonObj) -> tuple[int, JsonObj]:
        uris = req.get("redirect_uris")
        if not isinstance(uris, list) or not uris:
            return 400, {"error": "invalid_redirect_uri"}
        self.registrations += 1
        cid = f"dev-client-{self.registrations}"
        self.clients[cid] = {"redirect_uris": uris}
        return 201, {"client_id": cid, "redirect_uris": uris, "token_endpoint_auth_method": "none"}

    def authorize(self, q: dict[str, str]) -> tuple[int, str]:
        """Auto-approve. Returns (status, Location or error text)."""
        client = self.clients.get(q.get("client_id", ""))
        if client is None:
            return 400, "unknown client_id"
        redirect = q.get("redirect_uri", "")
        if redirect not in client["redirect_uris"]:
            return 400, "redirect_uri not registered"
        if q.get("code_challenge_method") != "S256" or not q.get("code_challenge"):
            return 400, "PKCE S256 required"
        if q.get("resource") != self.resource:
            return 400, f"resource must be {self.resource}"
        code = secrets.token_urlsafe(16)
        self.codes[code] = {
            "client_id": q["client_id"],
            "redirect_uri": redirect,
            "challenge": q["code_challenge"],
            "scope": self.grant_scope if self.grant_scope is not None else q.get("scope", ""),
        }
        back = {"code": code, "state": q.get("state", ""), "iss": self.iss_override or self.base}
        return 302, redirect + "?" + urllib.parse.urlencode(back)

    def _issue(self, client_id: str, scope: str) -> JsonObj:
        at, rt = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        self.access[at] = {"exp": time.time() + self.token_ttl, "resource": self.resource, "scope": scope}
        self.refresh[rt] = {"client_id": client_id, "scope": scope}
        return {"access_token": at, "token_type": "Bearer", "expires_in": self.token_ttl,
                "refresh_token": rt, "scope": scope}

    def token(self, f: dict[str, str]) -> tuple[int, JsonObj]:
        if f.get("resource") != self.resource:
            return 400, {"error": "invalid_target"}
        if f.get("grant_type") == "authorization_code":
            c = self.codes.pop(f.get("code", ""), None)
            if c is None or c["client_id"] != f.get("client_id") or c["redirect_uri"] != f.get("redirect_uri"):
                return 400, {"error": "invalid_grant"}
            digest = hashlib.sha256(f.get("code_verifier", "").encode()).digest()
            if base64.urlsafe_b64encode(digest).rstrip(b"=").decode() != c["challenge"]:
                return 400, {"error": "invalid_grant", "error_description": "PKCE verifier mismatch"}
            return 200, self._issue(c["client_id"], c["scope"])
        if f.get("grant_type") == "refresh_token":
            r = self.refresh.pop(f.get("refresh_token", ""), None)  # rotation: single use
            if r is None or r["client_id"] != f.get("client_id"):
                return 400, {"error": "invalid_grant"}
            return 200, self._issue(r["client_id"], r["scope"])
        return 400, {"error": "unsupported_grant_type"}

    def expire_all(self) -> None:
        for t in self.access.values():
            t["exp"] = 0


def make_http_server(
    server: SkillDirServer, port: int = 0, sse: bool = False, oauth: MockAuthServer | None = None
) -> ThreadingHTTPServer:
    """Streamable HTTP at /mcp. Validates the request headers the 2026-07-28 transport requires.

    With ``oauth``, /mcp requires a bearer token and the same port serves the OAuth endpoints.
    """

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_: Any) -> None:
            pass

        def _json(self, status: int, doc: JsonObj, extra: dict[str, str] | None = None) -> None:
            raw = json.dumps(doc).encode()
            self.send_response(status)
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:  # noqa: N802 (http.server API)
            parts = urllib.parse.urlsplit(self.path)
            if oauth is None:
                self._send(404, None)
            elif parts.path == "/.well-known/oauth-protected-resource/mcp":
                self._json(200, oauth.prm())
            elif parts.path == "/.well-known/oauth-authorization-server":
                self._json(200, oauth.as_meta())
            elif parts.path == "/authorize":
                q = {k: v[0] for k, v in urllib.parse.parse_qs(parts.query).items()}
                status, where = oauth.authorize(q)
                if status == 302:
                    self.send_response(302)
                    self.send_header("Location", where)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                else:
                    self._json(status, {"error": "invalid_request", "error_description": where})
            else:
                self._send(404, None)

        def _form(self) -> dict[str, str]:
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode()
            return {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}

        def do_POST(self) -> None:  # noqa: N802 (http.server API)
            if oauth is not None and self.path in ("/register", "/token", "/revoke"):
                if self.path == "/register":
                    self._json(*oauth.register(json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))))
                elif self.path == "/token":
                    self._json(*oauth.token(self._form()))
                else:
                    oauth.revoked.append(self._form().get("token", ""))
                    self._json(200, {})
                return
            if self.path != "/mcp":
                self._send(404, None)
                return
            if oauth is not None:
                status, error = oauth.check_bearer(self.headers.get("Authorization"))
                if status != 200:
                    self.rfile.read(int(self.headers.get("Content-Length", "0")))
                    self._json(status, {"error": error or "unauthorized"}, {"WWW-Authenticate": oauth.www(error)})
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

    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    if oauth is not None:
        oauth.base = f"http://127.0.0.1:{httpd.server_address[1]}"
    return httpd


def serve_http_background(
    server: SkillDirServer, sse: bool = False, oauth: MockAuthServer | None = None
) -> tuple[ThreadingHTTPServer, str]:
    httpd = make_http_server(server, 0, sse, oauth)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}/mcp"
