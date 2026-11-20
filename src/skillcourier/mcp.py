"""A small, dependency-free MCP client: just enough protocol to read served skills.

Speaks the modern protocol (2026-07-28: per-request ``_meta``, ``server/discover``) and falls back
to the legacy ``initialize`` handshake exactly as the base spec's backward-compatibility sections
describe, over stdio and Streamable HTTP.
"""

from __future__ import annotations

import base64
import json
import os
import queue
import subprocess
import tempfile
import threading
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import IO, TYPE_CHECKING, Any, Literal

from . import __version__
from .oauth import Challenge, OAuthError, parse_www_authenticate

if TYPE_CHECKING:
    from .oauth import OAuthProvider

PROTOCOL = "2026-07-28"
LEGACY_PROTOCOL = "2025-11-25"
SKILLS_EXT = "io.modelcontextprotocol/skills"
# Errors only a modern (per-request metadata) server sends: header mismatch, missing client
# capability, unsupported protocol version. Seeing one means "modern, do not fall back".
MODERN_ERROR_CODES = frozenset({-32020, -32021, -32022})
CLIENT_INFO = {"name": "skillcourier", "version": __version__}
CLIENT_CAPS: dict[str, Any] = {"extensions": {SKILLS_EXT: {}}}

JsonObj = dict[str, Any]


class McpError(Exception):
    """A JSON-RPC error returned by the server."""

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(f"{message} (code {code})")
        self.code = code
        self.message = message
        self.data = data


class TransportError(Exception):
    """The server could not be reached, crashed, timed out or answered with garbage."""


class AuthRequired(TransportError):
    """HTTP 401/403 that neither a refresh nor a login resolved."""

    def __init__(self, message: str, challenge: Challenge | None = None) -> None:
        super().__init__(message)
        self.challenge = challenge


@dataclass
class Endpoint:
    """How to reach one server. ``label`` is the host-assigned identity the spec requires."""

    label: str
    kind: Literal["http", "stdio"]
    url: str | None = None
    headers: dict[str, str] = field(default_factory=dict)
    command: str | None = None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    cwd: str | None = None
    source: str = "command line"

    def describe(self) -> str:
        """A display string that never includes header or env values (they may hold secrets)."""
        if self.kind == "http":
            return str(self.url)
        return " ".join([str(self.command), *self.args])


@dataclass
class ServerInfo:
    era: Literal["modern", "legacy"]
    protocol: str
    capabilities: JsonObj
    name: str | None
    version: str | None

    @property
    def skills(self) -> bool:
        ext = self.capabilities.get("extensions")
        return isinstance(ext, dict) and isinstance(ext.get(SKILLS_EXT), dict)

    @property
    def directory_read(self) -> bool:
        ext = self.capabilities.get("extensions")
        cfg = ext.get(SKILLS_EXT) if isinstance(ext, dict) else None
        return isinstance(cfg, dict) and cfg.get("directoryRead") is True


def header_value(value: str) -> str:
    """Encode a header value per the Streamable HTTP "Value Encoding" rules."""
    plain = (
        value != ""
        and all(0x20 <= ord(c) <= 0x7E or c == "\t" for c in value)
        and value == value.strip()
        and not (value.startswith("=?base64?") and value.endswith("?="))
    )
    if plain:
        return value
    return "=?base64?" + base64.b64encode(value.encode("utf-8")).decode("ascii") + "?="


def as_obj(value: Any) -> JsonObj:
    """``value`` if it is a JSON object, else an empty one."""
    return value if isinstance(value, dict) else {}


def _is_modern_error(msg: JsonObj | None) -> bool:
    err = msg.get("error") if isinstance(msg, dict) else None
    return isinstance(err, dict) and err.get("code") in MODERN_ERROR_CODES


def _raise_for_error(msg: JsonObj) -> JsonObj:
    err = msg.get("error")
    if isinstance(err, dict):
        raise McpError(int(err.get("code", 0)), str(err.get("message", "")), err.get("data"))
    result = msg.get("result")
    if not isinstance(result, dict):
        raise TransportError("response carries neither a result object nor an error")
    rtype = result.get("resultType", "complete")
    if rtype != "complete":
        raise TransportError(f"server asked for more input (resultType {rtype!r}); not supported")
    return result


def parse_sse(raw: str, want_id: Any) -> JsonObj | None:
    """Return the JSON-RPC response with id ``want_id`` from an SSE body, skipping notifications."""
    data: list[str] = []
    for line in raw.splitlines() + [""]:
        if line == "":
            if data:
                try:
                    msg = json.loads("\n".join(data))
                except json.JSONDecodeError:
                    msg = None
                data = []
                if isinstance(msg, dict) and msg.get("id") == want_id and "method" not in msg:
                    return msg
            continue
        if line.startswith("data:"):
            data.append(line[5:][1:] if line[5:6] == " " else line[5:])
    return None


def has_auth_header(headers: dict[str, str]) -> bool:
    return any(k.lower() == "authorization" for k in headers)


class _Http:
    def __init__(
        self, url: str, headers: dict[str, str], timeout: float, auth: OAuthProvider | None = None
    ) -> None:
        self.url = url
        self.headers = headers
        self.timeout = timeout
        # A configured Authorization header wins: the user chose static credentials.
        self.auth = None if has_auth_header(headers) else auth
        self.session_id: str | None = None

    def post(self, body: JsonObj, extra: dict[str, str]) -> tuple[int, JsonObj | None]:
        for _ in range(3):
            token = self.auth.authorization() if self.auth is not None else None
            status, raw, ctype, www = self._post_once(body, extra, token)
            if status not in (401, 403):
                return self._decode(body, status, raw, ctype)
            challenge = parse_www_authenticate(www, status)
            if self.auth is None:
                break
            try:
                retry = self.auth.handle(challenge, sent_token=token is not None)
            except OAuthError as e:
                raise AuthRequired(f"{self.url}: OAuth login failed: {e}", challenge) from e
            if not retry:
                break
        raise AuthRequired(self._auth_message(status, challenge), challenge)

    def _auth_message(self, status: int, ch: Challenge) -> str:
        if self.auth is None and has_auth_header(self.headers):
            return f"{self.url} answered HTTP {status} to the configured Authorization header"
        if status == 403 and ch.error != "insufficient_scope":
            return f"{self.url} answered HTTP 403 (forbidden{': ' + ch.error if ch.error else ''})"
        need = f" (needs scope {ch.scope})" if ch.scope else ""
        return (
            f"{self.url} needs an OAuth login{need}. Run `skillcourier auth login {self.url}` "
            "once (it opens a browser), or set an Authorization header."
        )

    def _post_once(
        self, body: JsonObj, extra: dict[str, str], token: str | None
    ) -> tuple[int, bytes, str, str | None]:
        hdrs = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "User-Agent": f"skillcourier/{__version__}",
            **self.headers,
            **extra,
        }
        if token is not None:
            hdrs["Authorization"] = token
        if self.session_id:
            hdrs["Mcp-Session-Id"] = self.session_id
        req = urllib.request.Request(
            self.url, data=json.dumps(body).encode("utf-8"), headers=hdrs, method="POST"
        )
        www: str | None = None
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status, ctype, raw = resp.status, resp.headers.get("Content-Type", ""), resp.read()
                sid = resp.headers.get("Mcp-Session-Id")
        except urllib.error.HTTPError as e:
            status, ctype, raw = e.code, e.headers.get("Content-Type", ""), e.read()
            www = e.headers.get("WWW-Authenticate")
            sid = None
        except (urllib.error.URLError, OSError, TimeoutError) as e:
            raise TransportError(f"cannot reach {self.url}: {e}") from e
        if sid:
            self.session_id = sid
        return status, raw, ctype, www

    def _decode(self, body: JsonObj, status: int, raw: bytes, ctype: str) -> tuple[int, JsonObj | None]:
        text = raw.decode("utf-8", errors="replace")
        if "id" not in body:
            return status, None
        if ctype.startswith("text/event-stream"):
            return status, parse_sse(text, body["id"])
        try:
            msg = json.loads(text) if text.strip() else None
        except json.JSONDecodeError:
            msg = None
        return status, msg if isinstance(msg, dict) else None


class _Stdio:
    def __init__(self, ep: Endpoint) -> None:
        env = dict(os.environ)
        env.update(ep.env)
        self._stderr: IO[bytes] = tempfile.TemporaryFile()
        try:
            self.proc = subprocess.Popen(
                [str(ep.command), *ep.args],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=self._stderr,
                env=env,
                cwd=ep.cwd,
            )
        except OSError as e:
            raise TransportError(f"cannot start {ep.describe()}: {e}") from e
        self._pending: dict[Any, queue.Queue[JsonObj | None]] = {}
        self._lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()

    def _read(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            try:
                msg = json.loads(line)
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            if not isinstance(msg, dict):
                continue
            if "method" in msg:
                if "id" in msg:  # a server->client request: we offer no client features
                    if msg["method"] == "ping":
                        self._write({"jsonrpc": "2.0", "id": msg["id"], "result": {}})
                    else:
                        err = {"code": -32601, "message": "method not supported by skillcourier"}
                        self._write({"jsonrpc": "2.0", "id": msg["id"], "error": err})
                continue
            with self._lock:
                q = self._pending.get(msg.get("id"))
            if q is not None:
                q.put(msg)
        with self._lock:
            for q in self._pending.values():
                q.put(None)

    def _write(self, msg: JsonObj) -> None:
        assert self.proc.stdin is not None
        data = (json.dumps(msg, separators=(",", ":")) + "\n").encode("utf-8")
        with self._write_lock:
            try:
                self.proc.stdin.write(data)
                self.proc.stdin.flush()
            except (BrokenPipeError, OSError, ValueError) as e:
                raise TransportError(f"server process closed its input: {self.stderr_tail()}") from e

    def stderr_tail(self, n: int = 600) -> str:
        try:
            self._stderr.seek(0)
            return self._stderr.read().decode("utf-8", errors="replace")[-n:].strip()
        except (OSError, ValueError):
            return ""

    def request(self, body: JsonObj, timeout: float) -> JsonObj:
        q: queue.Queue[JsonObj | None] = queue.Queue()
        with self._lock:
            self._pending[body["id"]] = q
        try:
            self._write(body)
            try:
                msg = q.get(timeout=timeout)
            except queue.Empty:
                raise TransportError(f"no answer to {body['method']} within {timeout:g}s") from None
        finally:
            with self._lock:
                self._pending.pop(body["id"], None)
        if msg is None:
            tail = self.stderr_tail()
            raise TransportError("server process exited" + (f": {tail}" if tail else ""))
        return msg

    def notify(self, body: JsonObj) -> None:
        self._write(body)

    def close(self) -> None:
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
            self.proc.wait(timeout=3)
        except (subprocess.TimeoutExpired, OSError):
            self.proc.kill()
            self.proc.wait(timeout=3)
        finally:
            if self.proc.stdout:
                self.proc.stdout.close()
            self._stderr.close()


class McpClient:
    """One connection to one server. Use as a context manager."""

    def __init__(
        self, endpoint: Endpoint, timeout: float = 30.0, auth: OAuthProvider | None = None
    ) -> None:
        self.endpoint = endpoint
        self.timeout = timeout
        self.auth = auth
        self.info: ServerInfo | None = None
        self._next_id = 0
        self._http: _Http | None = None
        self._stdio: _Stdio | None = None

    def __enter__(self) -> McpClient:
        self.connect()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        if self._stdio is not None:
            self._stdio.close()
            self._stdio = None

    def _id(self) -> int:
        self._next_id += 1
        return self._next_id

    def _modern_params(self, params: JsonObj | None) -> JsonObj:
        meta = {
            "io.modelcontextprotocol/protocolVersion": PROTOCOL,
            "io.modelcontextprotocol/clientInfo": CLIENT_INFO,
            "io.modelcontextprotocol/clientCapabilities": CLIENT_CAPS,
        }
        return {**(params or {}), "_meta": meta}

    def _exchange(self, method: str, params: JsonObj | None, era: str) -> tuple[int, JsonObj | None]:
        body: JsonObj = {"jsonrpc": "2.0", "id": self._id(), "method": method}
        body["params"] = self._modern_params(params) if era == "modern" else (params or {})
        if self._stdio is not None:
            return 200, self._stdio.request(body, self.timeout)
        assert self._http is not None
        extra = {"Mcp-Method": method}
        if era == "modern":
            extra["MCP-Protocol-Version"] = PROTOCOL
        elif self.info is not None:
            extra["MCP-Protocol-Version"] = self.info.protocol
        if params and method in ("resources/read", "tools/call", "prompts/get"):
            name = params.get("uri", params.get("name"))
            if isinstance(name, str):
                extra["Mcp-Name"] = header_value(name)
        return self._http.post(body, extra)

    def connect(self) -> ServerInfo:
        ep = self.endpoint
        if ep.kind == "http":
            if not ep.url:
                raise TransportError(f"server {ep.label!r} has no url")
            self._http = _Http(ep.url, ep.headers, self.timeout, self.auth)
        else:
            if not ep.command:
                raise TransportError(f"server {ep.label!r} has no command")
            self._stdio = _Stdio(ep)
        try:
            status, msg = self._exchange("server/discover", None, "modern")
        except TransportError as e:
            if isinstance(e, AuthRequired) or self._stdio is None:
                raise
            if self._stdio.proc.poll() is not None:
                raise
            status, msg = 0, None  # stdio timeout: legacy servers may ignore pre-initialize calls
        if msg is not None and isinstance(msg.get("result"), dict):
            res = msg["result"]
            versions = res.get("supportedVersions")
            if isinstance(versions, list) and PROTOCOL not in versions:
                raise TransportError(
                    f"server speaks protocol {versions}, skillcourier speaks {PROTOCOL} (or legacy)"
                )
            caps = as_obj(res.get("capabilities"))
            sinfo = as_obj(as_obj(res.get("_meta")).get("io.modelcontextprotocol/serverInfo"))
            self.info = ServerInfo("modern", PROTOCOL, caps, sinfo.get("name"), sinfo.get("version"))
            return self.info
        if _is_modern_error(msg):
            assert msg is not None
            err = msg["error"]
            data = err.get("data") or {}
            raise TransportError(
                f"server rejected protocol {PROTOCOL}: {err.get('message')} "
                f"(supports {data.get('supported', '?')}); not falling back, per spec"
            )
        return self._legacy_connect(status)

    def _legacy_connect(self, probe_status: int) -> ServerInfo:
        params = {
            "protocolVersion": LEGACY_PROTOCOL,
            "capabilities": CLIENT_CAPS,
            "clientInfo": CLIENT_INFO,
        }
        status, msg = self._exchange("initialize", params, "legacy")
        if msg is None:
            raise TransportError(
                f"server answered neither server/discover nor initialize "
                f"(HTTP {probe_status} then {status})"
            )
        res = _raise_for_error(msg)
        caps = as_obj(res.get("capabilities"))
        sinfo = as_obj(res.get("serverInfo"))
        proto = str(res.get("protocolVersion", LEGACY_PROTOCOL))
        self.info = ServerInfo("legacy", proto, caps, sinfo.get("name"), sinfo.get("version"))
        note: JsonObj = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        if self._stdio is not None:
            self._stdio.notify(note)
        else:
            assert self._http is not None
            self._http.post(note, {"Mcp-Method": note["method"], "MCP-Protocol-Version": proto})
        return self.info

    def request(self, method: str, params: JsonObj | None = None) -> JsonObj:
        if self.info is None:
            self.connect()
        assert self.info is not None
        status, msg = self._exchange(method, params, self.info.era)
        if msg is None:
            raise TransportError(f"{method}: no JSON-RPC response (HTTP {status})")
        return _raise_for_error(msg)

    # --- skills extension -------------------------------------------------------------------

    def list_skills(self, max_pages: int = 100) -> list[JsonObj]:
        out: list[JsonObj] = []
        cursor: str | None = None
        for _ in range(max_pages):
            res = self.request("skills/list", {"cursor": cursor} if cursor else None)
            skills = res.get("skills")
            if not isinstance(skills, list):
                raise TransportError("skills/list result has no `skills` array")
            out.extend(s for s in skills if isinstance(s, dict))
            nxt = res.get("nextCursor")
            if not isinstance(nxt, str) or not nxt:
                return out
            cursor = nxt
        raise TransportError(f"skills/list still paginating after {max_pages} pages")

    def get_skill(self, uri: str) -> JsonObj:
        res = self.request("skills/get", {"uri": uri})
        skill = res.get("skill")
        if not isinstance(skill, dict):
            raise TransportError("skills/get result has no `skill` object")
        return skill

    def read_resource(self, uri: str) -> bytes:
        """Return the raw bytes of one resource (text is encoded as UTF-8, blobs base64-decoded)."""
        res = self.request("resources/read", {"uri": uri})
        contents = res.get("contents")
        if not isinstance(contents, list) or not contents:
            raise TransportError(f"resources/read {uri}: empty contents")
        items = [c for c in contents if isinstance(c, dict)]
        match = [c for c in items if c.get("uri") == uri] or items[:1]
        item = match[0]
        if isinstance(item.get("blob"), str):
            try:
                return base64.b64decode(item["blob"], validate=True)
            except ValueError as e:
                raise TransportError(f"resources/read {uri}: invalid base64 blob") from e
        if isinstance(item.get("text"), str):
            return str(item["text"]).encode("utf-8")
        raise TransportError(f"resources/read {uri}: content has neither text nor blob")
