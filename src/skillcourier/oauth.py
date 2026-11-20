"""OAuth 2.1 for MCP servers that require it, per the MCP authorization spec.

The flow, each step checked rather than trusted:

1. A ``401`` with ``WWW-Authenticate: Bearer resource_metadata=...`` (or the well-known fallback)
   leads to Protected Resource Metadata (RFC 9728). Its ``resource`` must name the server we asked.
2. The authorization server's metadata (RFC 8414, then OpenID discovery). Its ``issuer`` must match,
   and it must offer PKCE ``S256``; the spec says a client MUST refuse to proceed otherwise.
3. A client: a pre-registered ``--client-id``, a stored registration, or Dynamic Client
   Registration (RFC 7591) as a public native client.
4. Authorization code + PKCE over a loopback redirect (RFC 8252), with ``state``, the ``resource``
   indicator (RFC 8707) on both legs, and the ``iss`` response check (RFC 9207).
5. Tokens stored per resource in a ``0600`` file, sent only to that exact resource, refreshed
   (with rotation) before expiry or on a ``401``.

Standard library only. Tokens are never printed, logged or written to the lockfile.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

from . import __version__

JsonObj = dict[str, Any]
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})
REFRESH_MARGIN_S = 60
CLIENT_NAME = "skillcourier"
CLIENT_URI = "https://github.com/Prime-agentai/skillcourier"


class OAuthError(Exception):
    """Discovery, registration, authorization or token exchange failed or was unsafe."""


# --- WWW-Authenticate -------------------------------------------------------------------------

_PARAM = re.compile(r'\s*([A-Za-z0-9_.-]+)\s*=\s*("(?:[^"\\]|\\.)*"|[^\s,"]*)\s*(?:,|$)')


@dataclass
class Challenge:
    """The Bearer challenge of a 401/403 response."""

    status: int
    params: dict[str, str] = field(default_factory=dict)

    @property
    def resource_metadata(self) -> str | None:
        return self.params.get("resource_metadata")

    @property
    def scope(self) -> str | None:
        return self.params.get("scope")

    @property
    def error(self) -> str | None:
        return self.params.get("error")


def parse_www_authenticate(value: str | None, status: int = 401) -> Challenge:
    """Parse the ``Bearer`` challenge out of a WWW-Authenticate header (other schemes ignored)."""
    ch = Challenge(status)
    if not value:
        return ch
    m = re.search(r"(?:^|[\s,])Bearer(?:\s+|$)", value, flags=re.IGNORECASE)
    if not m:
        return ch
    rest = value[m.end():]
    pos = 0
    while pos < len(rest):
        pm = _PARAM.match(rest, pos)
        if not pm or pm.end() == pos:
            break  # next token is a new scheme, or garbage: stop
        key, raw = pm.group(1).lower(), pm.group(2)
        if raw.startswith('"'):
            raw = re.sub(r"\\(.)", r"\1", raw[1:-1])
        ch.params.setdefault(key, raw)
        pos = pm.end()
    return ch


# --- URLs -------------------------------------------------------------------------------------


def canonical_resource(url: str) -> str:
    """RFC 8707 canonical form: lowercase scheme and host, no default port, fragment or trailing /."""
    p = urllib.parse.urlsplit(url.strip())
    scheme, host = p.scheme.lower(), (p.hostname or "").lower()
    if ":" in host:
        host = f"[{host}]"
    port = p.port
    if port and not ((scheme == "https" and port == 443) or (scheme == "http" and port == 80)):
        host = f"{host}:{port}"
    path = p.path.rstrip("/")
    query = f"?{p.query}" if p.query else ""
    return f"{scheme}://{host}{path}{query}"


def _is_loopback(url: str) -> bool:
    return (urllib.parse.urlsplit(url).hostname or "").lower() in LOOPBACK_HOSTS


def require_secure(url: str, what: str) -> str:
    """Every authorization endpoint must be HTTPS. Plain HTTP is allowed only on loopback."""
    scheme = urllib.parse.urlsplit(url).scheme.lower()
    if scheme == "https" or (scheme == "http" and _is_loopback(url)):
        return url
    raise OAuthError(f"{what} {url!r} is not HTTPS; refusing to send credentials there")


def _origin(url: str) -> str:
    p = urllib.parse.urlsplit(url)
    return f"{p.scheme}://{p.netloc}"


# --- HTTP -------------------------------------------------------------------------------------


def _http(
    url: str,
    *,
    method: str = "GET",
    form: dict[str, str] | None = None,
    body: JsonObj | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 30.0,
) -> tuple[int, JsonObj | None]:
    hdrs = {"Accept": "application/json", "User-Agent": f"skillcourier/{__version__}", **(headers or {})}
    data: bytes | None = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode("ascii")
        hdrs["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        raise OAuthError(f"cannot reach {url}: {e}") from e
    try:
        doc = json.loads(raw.decode("utf-8")) if raw.strip() else None
    except (UnicodeDecodeError, json.JSONDecodeError):
        doc = None
    return status, doc if isinstance(doc, dict) else None


# --- discovery --------------------------------------------------------------------------------


def prm_candidates(resource_url: str, challenge: Challenge | None) -> list[str]:
    """Where to look for Protected Resource Metadata, in the order the MCP spec gives."""
    out: list[str] = []
    if challenge is not None and challenge.resource_metadata:
        out.append(challenge.resource_metadata)
    path = urllib.parse.urlsplit(resource_url).path.rstrip("/")
    base = _origin(resource_url)
    if path:
        out.append(f"{base}/.well-known/oauth-protected-resource{path}")
    out.append(f"{base}/.well-known/oauth-protected-resource")
    return list(dict.fromkeys(out))


def fetch_resource_metadata(resource_url: str, challenge: Challenge | None, timeout: float = 30.0) -> JsonObj:
    tried = []
    for url in prm_candidates(resource_url, challenge):
        require_secure(url, "resource metadata URL")
        status, doc = _http(url, timeout=timeout)
        tried.append(f"{url} -> HTTP {status}")
        if status != 200 or doc is None:
            continue
        named = doc.get("resource")
        if not isinstance(named, str) or canonical_resource(named) != canonical_resource(resource_url):
            raise OAuthError(
                f"resource metadata at {url} is for {named!r}, not {resource_url!r}; refusing it (RFC 9728 s3.3)"
            )
        servers = doc.get("authorization_servers")
        if not isinstance(servers, list) or not servers or not all(isinstance(s, str) for s in servers):
            raise OAuthError(f"resource metadata at {url} names no authorization server")
        return doc
    raise OAuthError("no protected resource metadata found: " + "; ".join(tried))


def as_metadata_candidates(issuer: str) -> list[str]:
    """RFC 8414 then OpenID discovery, with path insertion for issuers that have a path."""
    base, path = _origin(issuer), urllib.parse.urlsplit(issuer).path.rstrip("/")
    if path:
        return [
            f"{base}/.well-known/oauth-authorization-server{path}",
            f"{base}/.well-known/openid-configuration{path}",
            f"{base}{path}/.well-known/openid-configuration",
        ]
    return [f"{base}/.well-known/oauth-authorization-server", f"{base}/.well-known/openid-configuration"]


def fetch_as_metadata(issuer: str, timeout: float = 30.0) -> JsonObj:
    require_secure(issuer, "authorization server")
    tried = []
    for url in as_metadata_candidates(issuer):
        status, doc = _http(url, timeout=timeout)
        tried.append(f"{url} -> HTTP {status}")
        if status != 200 or doc is None:
            continue
        if str(doc.get("issuer", "")).rstrip("/") != issuer.rstrip("/"):
            raise OAuthError(f"metadata at {url} claims issuer {doc.get('issuer')!r}, expected {issuer!r} (RFC 8414 s3.3)")
        if "S256" not in (doc.get("code_challenge_methods_supported") or []):
            raise OAuthError(f"{issuer} does not advertise PKCE S256; the MCP spec forbids proceeding")
        for key in ("authorization_endpoint", "token_endpoint"):
            if not isinstance(doc.get(key), str):
                raise OAuthError(f"{issuer} metadata has no {key}")
            require_secure(doc[key], key)
        return doc
    raise OAuthError("no authorization server metadata found: " + "; ".join(tried))


# --- token store ------------------------------------------------------------------------------


def default_store_path() -> Path:
    if os.environ.get("SKILLCOURIER_AUTH_FILE"):
        return Path(os.environ["SKILLCOURIER_AUTH_FILE"])
    base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / "skillcourier" / "auth.json"


class TokenStore:
    """``{"resources": {canonical url: record}, "clients": {issuer|redirect: client}}`` in one 0600 file."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or default_store_path()

    def load(self) -> JsonObj:
        try:
            doc = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return {"resources": {}, "clients": {}}
        except (OSError, json.JSONDecodeError) as e:
            raise OAuthError(f"cannot read {self.path}: {e}") from e
        if not isinstance(doc, dict):
            return {"resources": {}, "clients": {}}
        doc.setdefault("resources", {})
        doc.setdefault("clients", {})
        return doc

    def save(self, doc: JsonObj) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, tmp = tempfile.mkstemp(prefix=".auth-", dir=self.path.parent)
        try:
            os.chmod(tmp, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(doc, f, indent=2, sort_keys=True)
            os.replace(tmp, self.path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    def get(self, resource: str) -> JsonObj | None:
        rec = self.load()["resources"].get(canonical_resource(resource))
        return rec if isinstance(rec, dict) else None

    def put(self, resource: str, rec: JsonObj) -> None:
        doc = self.load()
        doc["resources"][canonical_resource(resource)] = rec
        self.save(doc)

    def delete(self, resource: str) -> JsonObj | None:
        doc = self.load()
        rec = doc["resources"].pop(canonical_resource(resource), None)
        if rec is not None:
            self.save(doc)
        return rec if isinstance(rec, dict) else None

    def client(self, issuer: str, redirect_uri: str) -> JsonObj | None:
        c = self.load()["clients"].get(f"{issuer}|{redirect_uri}")
        return c if isinstance(c, dict) else None

    def clients_for(self, issuer: str) -> list[JsonObj]:
        return [c for k, c in self.load()["clients"].items() if k.startswith(f"{issuer}|") and isinstance(c, dict)]

    def put_client(self, issuer: str, redirect_uri: str, client: JsonObj) -> None:
        doc = self.load()
        doc["clients"][f"{issuer}|{redirect_uri}"] = client
        self.save(doc)


# --- loopback redirect ------------------------------------------------------------------------


class _Callback(HTTPServer):
    result: dict[str, str] | None = None


class _CallbackHandler(BaseHTTPRequestHandler):
    server: _Callback

    def log_message(self, *_: Any) -> None:
        pass

    def do_GET(self) -> None:  # noqa: N802 (http.server API)
        parts = urllib.parse.urlsplit(self.path)
        if parts.path != "/callback":
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        q = urllib.parse.parse_qs(parts.query, keep_blank_values=True)
        self.server.result = {k: v[0] for k, v in q.items()}
        ok = "code" in self.server.result
        page = (
            "<!doctype html><title>skillcourier</title><p>skillcourier: "
            + ("login complete. You can close this tab." if ok else "login failed. See your terminal.")
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(page)))
        self.end_headers()
        self.wfile.write(page)


def bind_loopback(port: int = 0) -> _Callback:
    """Listen on 127.0.0.1 only. Raises OSError if ``port`` is taken."""
    srv = _Callback(("127.0.0.1", port), _CallbackHandler)
    srv.timeout = 0.5
    return srv


# --- the flow ---------------------------------------------------------------------------------


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)[:96]
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode()
    return verifier, challenge


def register_client(as_meta: JsonObj, redirect_uri: str, scope: str | None, timeout: float = 30.0) -> JsonObj:
    endpoint = as_meta.get("registration_endpoint")
    if not isinstance(endpoint, str):
        raise OAuthError(
            f"{as_meta.get('issuer')} offers no dynamic client registration; "
            "register a client with the provider and pass --client-id"
        )
    require_secure(endpoint, "registration endpoint")
    req: JsonObj = {
        "client_name": CLIENT_NAME,
        "client_uri": CLIENT_URI,
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "application_type": "native",
    }
    if scope:
        req["scope"] = scope
    status, doc = _http(endpoint, method="POST", body=req, timeout=timeout)
    if status not in (200, 201) or doc is None or not isinstance(doc.get("client_id"), str):
        detail = (doc or {}).get("error_description") or (doc or {}).get("error") or f"HTTP {status}"
        raise OAuthError(f"dynamic client registration at {endpoint} failed: {detail}")
    return {
        "client_id": doc["client_id"],
        "client_secret": doc.get("client_secret") if isinstance(doc.get("client_secret"), str) else None,
        "auth_method": str(doc.get("token_endpoint_auth_method") or ("client_secret_basic" if doc.get("client_secret") else "none")),
        "redirect_uri": redirect_uri,
        "registered_at": int(time.time()),
    }


def _client_auth(client: JsonObj, form: dict[str, str]) -> dict[str, str]:
    """Add client authentication to a token request; return extra headers."""
    secret = client.get("client_secret")
    method = client.get("auth_method", "none")
    form["client_id"] = str(client["client_id"])
    if secret and method == "client_secret_basic":
        pair = f"{urllib.parse.quote(str(client['client_id']), safe='')}:{urllib.parse.quote(str(secret), safe='')}"
        return {"Authorization": "Basic " + base64.b64encode(pair.encode()).decode()}
    if secret:
        form["client_secret"] = str(secret)
    return {}


def _token_request(token_endpoint: str, client: JsonObj, form: dict[str, str], timeout: float) -> JsonObj:
    extra = _client_auth(client, form)
    status, doc = _http(token_endpoint, method="POST", form=form, headers=extra, timeout=timeout)
    if status != 200 or doc is None:
        code = (doc or {}).get("error", f"HTTP {status}")
        desc = (doc or {}).get("error_description")
        raise OAuthError(f"token endpoint refused the {form.get('grant_type')} grant: {code}" + (f" ({desc})" if desc else ""))
    if not isinstance(doc.get("access_token"), str) or str(doc.get("token_type", "")).lower() != "bearer":
        raise OAuthError("token endpoint returned no bearer access_token")
    return doc


def _record(resource: str, issuer: str, as_meta: JsonObj, client: JsonObj, tok: JsonObj, scope: str | None) -> JsonObj:
    now = int(time.time())
    expires = tok.get("expires_in")
    return {
        "resource": canonical_resource(resource),
        "issuer": issuer,
        "token_endpoint": as_meta["token_endpoint"],
        "revocation_endpoint": as_meta.get("revocation_endpoint"),
        "client": client,
        "access_token": tok["access_token"],
        "refresh_token": tok.get("refresh_token"),
        "expires_at": now + int(expires) if isinstance(expires, (int, float)) else None,
        "scope": str(tok.get("scope") or scope or ""),
        "obtained_at": now,
    }


Opener = Callable[[str], Any]
Announce = Callable[[str], None]


def login(
    resource_url: str,
    *,
    challenge: Challenge | None = None,
    scope: str | None = None,
    client_id: str | None = None,
    client_secret: str | None = None,
    port: int = 0,
    open_browser: Opener | None = None,
    announce: Announce = lambda _m: None,
    wait_s: float = 300.0,
    timeout: float = 30.0,
    store: TokenStore | None = None,
) -> JsonObj:
    """Run the full authorization code + PKCE flow and store the tokens. Returns the record."""
    store = store or TokenStore()
    prm = fetch_resource_metadata(resource_url, challenge, timeout)
    issuer = str(prm["authorization_servers"][0])
    as_meta = fetch_as_metadata(issuer, timeout)

    if scope is None:
        prior = store.get(resource_url)
        wanted = (challenge.scope if challenge else None) or " ".join(prm.get("scopes_supported") or []) or None
        if prior and prior.get("scope") and wanted:  # step-up keeps what was already granted
            wanted = " ".join(dict.fromkeys([*str(prior["scope"]).split(), *wanted.split()]))
        scope = wanted

    client: JsonObj | None = None
    if client_id:
        client = {"client_id": client_id, "client_secret": client_secret,
                  "auth_method": "client_secret_post" if client_secret else "none"}
    srv: _Callback | None = None
    if client is None and port == 0:  # reuse a registration whose loopback port is free
        for c in store.clients_for(issuer):
            rport = urllib.parse.urlsplit(str(c.get("redirect_uri", ""))).port
            if not rport:
                continue
            try:
                srv = bind_loopback(rport)
            except OSError:
                continue
            client = c
            break
    if srv is None:
        srv = bind_loopback(port)
    try:
        redirect_uri = f"http://127.0.0.1:{srv.server_address[1]}/callback"
        if client is None:
            client = register_client(as_meta, redirect_uri, scope, timeout)
            store.put_client(issuer, redirect_uri, client)
        else:
            client = {**client, "redirect_uri": redirect_uri}

        verifier, code_challenge = pkce_pair()
        state = secrets.token_urlsafe(24)
        q = {
            "response_type": "code",
            "client_id": client["client_id"],
            "redirect_uri": redirect_uri,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "resource": canonical_resource(resource_url),
        }
        if scope:
            q["scope"] = scope
        auth_ep = str(as_meta["authorization_endpoint"])
        url = auth_ep + ("&" if "?" in auth_ep else "?") + urllib.parse.urlencode(q)
        announce(f"Log in to {prm.get('resource_name') or resource_url} in your browser:\n  {url}")
        if open_browser is not None:
            try:
                open_browser(url)
            except Exception:  # a missing browser is fine: the URL is printed
                pass

        deadline = time.monotonic() + wait_s
        while srv.result is None and time.monotonic() < deadline:
            srv.handle_request()
        result = srv.result
    finally:
        srv.server_close()

    if result is None:
        raise OAuthError(f"no browser callback within {wait_s:g}s")
    if not secrets.compare_digest(result.get("state", ""), state):
        raise OAuthError("callback state does not match the request; possible CSRF, aborting")
    if "error" in result:
        raise OAuthError(f"authorization denied: {result['error']}" + (f" ({result['error_description']})" if result.get("error_description") else ""))
    if "iss" in result or as_meta.get("authorization_response_iss_parameter_supported") is True:
        if result.get("iss", "").rstrip("/") != issuer.rstrip("/"):
            raise OAuthError(f"callback iss {result.get('iss')!r} is not {issuer!r}; possible mix-up attack (RFC 9207)")
    code = result.get("code")
    if not code:
        raise OAuthError("callback carried no authorization code")

    tok = _token_request(
        str(as_meta["token_endpoint"]),
        client,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
            "resource": canonical_resource(resource_url),
        },
        timeout,
    )
    rec = _record(resource_url, issuer, as_meta, client, tok, scope)
    store.put(resource_url, rec)
    return rec


def refresh(resource_url: str, store: TokenStore, timeout: float = 30.0) -> JsonObj:
    """Use the stored refresh token. Keeps a rotated refresh token; drops the record if refused."""
    rec = store.get(resource_url)
    if not rec or not rec.get("refresh_token"):
        raise OAuthError("no refresh token stored")
    form = {
        "grant_type": "refresh_token",
        "refresh_token": str(rec["refresh_token"]),
        "resource": canonical_resource(resource_url),
    }
    try:
        tok = _token_request(str(rec["token_endpoint"]), as_client(rec), form, timeout)
    except OAuthError:
        store.delete(resource_url)
        raise
    now = int(time.time())
    rec.update(
        access_token=tok["access_token"],
        refresh_token=tok.get("refresh_token") or rec["refresh_token"],
        expires_at=now + int(tok["expires_in"]) if isinstance(tok.get("expires_in"), (int, float)) else None,
        scope=str(tok.get("scope") or rec.get("scope") or ""),
        obtained_at=now,
    )
    store.put(resource_url, rec)
    return rec


def as_client(rec: JsonObj) -> JsonObj:
    c = rec.get("client")
    if not isinstance(c, dict) or not isinstance(c.get("client_id"), str):
        raise OAuthError("stored record has no client")
    return c


def logout(resource_url: str, store: TokenStore, timeout: float = 10.0) -> bool:
    """Forget the tokens; revoke the refresh token first when the server offers revocation (RFC 7009)."""
    rec = store.delete(resource_url)
    if rec is None:
        return False
    ep = rec.get("revocation_endpoint")
    tok = rec.get("refresh_token") or rec.get("access_token")
    if isinstance(ep, str) and tok:
        try:
            require_secure(ep, "revocation endpoint")
            form = {"token": str(tok)}
            _http(ep, method="POST", form=form, headers=_client_auth(as_client(rec), form), timeout=timeout)
        except OAuthError:
            pass  # best effort: the local copy is gone either way
    return True


def probe(resource_url: str, timeout: float = 30.0) -> Challenge | None:
    """POST an unauthenticated ``server/discover``: the challenge if the server wants auth, else None."""
    body = {"jsonrpc": "2.0", "id": 0, "method": "server/discover", "params": {}}
    req = urllib.request.Request(
        resource_url,
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                 "User-Agent": f"skillcourier/{__version__}", "Mcp-Method": "server/discover"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout):
            return None
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            return parse_www_authenticate(e.headers.get("WWW-Authenticate"), e.code)
        return None
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        raise OAuthError(f"cannot reach {resource_url}: {e}") from e


# --- the transport's view ---------------------------------------------------------------------


class OAuthProvider:
    """Supplies a bearer token for one resource and reacts to 401/403. Never sends a token elsewhere."""

    def __init__(
        self,
        resource_url: str,
        *,
        store: TokenStore | None = None,
        interactive: bool = False,
        announce: Announce = lambda _m: None,
        open_browser: Opener | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.resource_url = resource_url
        self.store = store or TokenStore()
        self.interactive = interactive
        self.announce = announce
        self.open_browser = open_browser if open_browser is not None else (webbrowser.open if interactive else None)
        self.timeout = timeout
        self.refreshed = False
        self.logged_in = False

    def authorization(self) -> str | None:
        rec = self.store.get(self.resource_url)
        if not rec:
            return None
        exp = rec.get("expires_at")
        if isinstance(exp, (int, float)) and exp - REFRESH_MARGIN_S < time.time() and rec.get("refresh_token"):
            try:
                rec = refresh(self.resource_url, self.store, self.timeout)
            except OAuthError:
                return None
        return f"Bearer {rec['access_token']}"

    def handle(self, challenge: Challenge, sent_token: bool) -> bool:
        """React to a 401/403. True means: retry the request."""
        step_up = challenge.status == 403 and challenge.error == "insufficient_scope"
        if challenge.status == 403 and not step_up:
            return False
        if sent_token and not step_up and not self.refreshed:
            self.refreshed = True  # one refresh per client, then fall through to login
            rec = self.store.get(self.resource_url)
            if rec and rec.get("refresh_token"):
                try:
                    refresh(self.resource_url, self.store, self.timeout)
                    return True
                except OAuthError:
                    pass
        if not self.interactive or (self.logged_in and not step_up):
            return False
        login(
            self.resource_url,
            challenge=challenge,
            open_browser=self.open_browser,
            announce=self.announce,
            timeout=self.timeout,
            store=self.store,
        )
        self.logged_in = True
        return True
