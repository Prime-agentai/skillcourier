"""OAuth 2.1 end to end against the dev server's strict mock authorization server, over real sockets."""

from __future__ import annotations

import json
import stat
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from skillcourier import cli, oauth
from skillcourier.cli import main
from skillcourier.devserver import MockAuthServer, SkillDirServer, serve_http_background
from skillcourier.oauth import Challenge, OAuthError, TokenStore, canonical_resource, parse_www_authenticate


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_: Any, **__: Any) -> None:
        return None


def browser(tamper: Callable[[str], str] = lambda u: u, log: list[str] | None = None) -> Callable[[str], bool]:
    """A user who approves in the browser: follow the authorize URL, then hit the loopback callback.

    Runs in a thread, because login() starts serving the callback only after opening the browser.
    """

    def _open(url: str) -> bool:
        def go() -> None:
            opener = urllib.request.build_opener(_NoRedirect)
            try:
                opener.open(url, timeout=5)
                return
            except urllib.error.HTTPError as e:
                if e.code != 302:
                    if log is not None:
                        log.append(f"authorize refused: {e.read().decode()}")
                    return
                location = tamper(e.headers["Location"])
            if log is not None:
                log.append(location)
            urllib.request.urlopen(location, timeout=5).read()

        threading.Thread(target=go, daemon=True).start()
        return True

    return _open


@dataclass
class Protected:
    server: SkillDirServer
    auth: MockAuthServer
    url: str


@pytest.fixture(autouse=True)
def auth_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "cfg" / "skillcourier" / "auth.json"
    monkeypatch.setenv("SKILLCOURIER_AUTH_FILE", str(path))
    return path


@pytest.fixture
def protected(skills_dir: Path) -> Iterator[Protected]:
    server = SkillDirServer(skills_dir)
    mock = MockAuthServer()
    httpd, url = serve_http_background(server, oauth=mock)
    yield Protected(server, mock, url)
    httpd.shutdown()
    httpd.server_close()


@pytest.fixture
def approve(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    log: list[str] = []
    monkeypatch.setattr("webbrowser.open", browser(log=log))
    return log


def login(run: Any, url: str, *extra: str) -> Any:
    return run("auth", "login", url, "--wait", "10", *extra)


# --- parsing ----------------------------------------------------------------------------------


def test_parse_www_authenticate_variants() -> None:
    c = parse_www_authenticate('Bearer resource_metadata="https://x/.well-known/oauth-protected-resource/mcp", scope="a b"')
    assert c.resource_metadata == "https://x/.well-known/oauth-protected-resource/mcp"
    assert c.scope == "a b"
    c = parse_www_authenticate('Basic realm="x", Bearer error="insufficient_scope", scope="files:read"', 403)
    assert (c.status, c.error, c.scope) == (403, "insufficient_scope", "files:read")
    c = parse_www_authenticate('bearer realm=OAuth, error_description="say \\"hi\\""')
    assert c.params == {"realm": "OAuth", "error_description": 'say "hi"'}
    assert parse_www_authenticate("Basic realm=x").params == {}
    assert parse_www_authenticate(None).params == {}


def test_canonical_resource() -> None:
    assert canonical_resource("HTTPS://MCP.Example.com:443/mcp/") == "https://mcp.example.com/mcp"
    assert canonical_resource("http://127.0.0.1:8080/mcp") == "http://127.0.0.1:8080/mcp"
    assert canonical_resource("https://h/mcp#frag") == "https://h/mcp"


def test_refuses_plain_http_outside_loopback() -> None:
    with pytest.raises(OAuthError, match="not HTTPS"):
        oauth.require_secure("http://auth.example.com/token", "token_endpoint")
    assert oauth.require_secure("http://127.0.0.1:9/token", "x")


def test_prm_candidates_follow_spec_order() -> None:
    ch = Challenge(401, {"resource_metadata": "https://a/meta"})
    assert oauth.prm_candidates("https://a/v1/mcp", ch) == [
        "https://a/meta",
        "https://a/.well-known/oauth-protected-resource/v1/mcp",
        "https://a/.well-known/oauth-protected-resource",
    ]
    assert oauth.as_metadata_candidates("https://a/tenant") == [
        "https://a/.well-known/oauth-authorization-server/tenant",
        "https://a/.well-known/openid-configuration/tenant",
        "https://a/tenant/.well-known/openid-configuration",
    ]


# --- the flow ---------------------------------------------------------------------------------


def test_unauthenticated_ls_explains_how_to_log_in(run: Any, protected: Protected) -> None:
    r = run("ls", protected.url)
    assert r.rc == 2
    assert "needs an OAuth login" in r.err and f"skillcourier auth login {protected.url}" in r.err
    assert "scope skills:read" in r.err


def test_login_then_import(run: Any, protected: Protected, approve: list[str], auth_file: Path, project: Path) -> None:
    r = login(run, protected.url)
    assert r.rc == 0, r.err
    assert "Logged in" in r.out and "scope: skills:read" in r.out
    assert protected.auth.registrations == 1
    # the callback carried code, state and iss
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(approve[0]).query)
    assert set(q) == {"code", "state", "iss"}

    r = run("add", protected.url, "--all", "--yes")
    assert r.rc == 0, r.err
    assert (project / ".claude" / "skills").is_dir()

    # tokens: 0600, never in the lockfile, never printed
    assert stat.S_IMODE(auth_file.stat().st_mode) == 0o600
    token = json.loads(auth_file.read_text())["resources"][canonical_resource(protected.url)]["access_token"]
    lock = next(project.rglob("*.lock.json"), None) or next(project.rglob("*lock*"), None)
    assert lock is not None and token not in lock.read_text()
    assert token not in r.out and token not in r.err
    assert all(h == f"Bearer {token}" for h in protected.auth.seen_auth[-3:])


def test_status_and_logout_revoke(run: Any, protected: Protected, approve: list[str], capsys: pytest.CaptureFixture[str]) -> None:
    assert login(run, protected.url).rc == 0
    capsys.readouterr()
    assert main(["auth", "status", "--json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    (row,) = doc["logins"]
    assert row["resource"] == canonical_resource(protected.url) and row["refreshable"] is True
    assert "access_token" not in json.dumps(doc) and "refresh_token" not in json.dumps(doc)

    rt = TokenStore().get(protected.url)["refresh_token"]  # type: ignore[index]
    r = run("auth", "logout", protected.url)
    assert r.rc == 0 and "Logged out" in r.out
    assert protected.auth.revoked == [rt]
    assert run("ls", protected.url).rc == 2


def test_expired_token_is_refreshed_with_rotation(run: Any, protected: Protected, approve: list[str]) -> None:
    assert login(run, protected.url).rc == 0
    before = TokenStore().get(protected.url)
    assert before is not None
    protected.auth.expire_all()  # server-side expiry the client cannot see: the 401 path
    r = run("ls", protected.url)
    assert r.rc == 0, r.err
    after = TokenStore().get(protected.url)
    assert after is not None
    assert after["access_token"] != before["access_token"]
    assert after["refresh_token"] != before["refresh_token"]  # rotated and kept
    assert protected.auth.registrations == 1


def test_proactive_refresh_before_expiry(run: Any, protected: Protected, approve: list[str]) -> None:
    assert login(run, protected.url).rc == 0
    store = TokenStore()
    rec = store.get(protected.url)
    assert rec is not None
    rec["expires_at"] = 0  # client-side clock says expired
    store.put(protected.url, rec)
    n = len(protected.auth.seen_auth)
    assert run("ls", protected.url).rc == 0
    assert all(h is not None for h in protected.auth.seen_auth[n:])  # no 401 round trip needed
    assert TokenStore().get(protected.url)["access_token"] != rec["access_token"]  # type: ignore[index]


def test_dead_refresh_token_needs_login_again(run: Any, protected: Protected, approve: list[str]) -> None:
    assert login(run, protected.url).rc == 0
    protected.auth.expire_all()
    protected.auth.refresh.clear()  # the server forgot every refresh token
    r = run("ls", protected.url)
    assert r.rc == 2 and "auth login" in r.err
    assert TokenStore().get(protected.url) is None  # a refused refresh token is dropped


def test_interactive_session_logs_in_on_demand(
    run: Any, protected: Protected, approve: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(cli, "interactive", lambda _args: True)
    r = run("ls", protected.url)
    assert r.rc == 0, r.err
    assert "Log in to skillcourier dev server" in r.err
    assert len(approve) == 1


def test_hook_mode_never_opens_a_browser(
    run: Any, protected: Protected, approve: list[str], monkeypatch: pytest.MonkeyPatch, project: Path
) -> None:
    assert login(run, protected.url).rc == 0
    assert run("add", protected.url, "--all", "--yes").rc == 0
    opened = len(approve)
    protected.auth.expire_all()
    protected.auth.refresh.clear()
    monkeypatch.setattr("sys.stdin.isatty", lambda: True)
    r = run("check", "--hook")
    assert r.rc == 0
    assert len(approve) == opened
    assert "auth login" in r.out


def test_reuses_registered_client(run: Any, protected: Protected, approve: list[str]) -> None:
    assert login(run, protected.url).rc == 0
    assert run("auth", "logout", protected.url).rc == 0
    assert login(run, protected.url).rc == 0
    assert protected.auth.registrations == 1


def test_token_is_never_sent_to_another_server(run: Any, protected: Protected, approve: list[str], skills_dir: Path) -> None:
    assert login(run, protected.url).rc == 0
    other_mock = MockAuthServer()
    httpd, other = serve_http_background(SkillDirServer(skills_dir), oauth=other_mock)
    try:
        assert run("ls", other).rc == 2
        assert other_mock.seen_auth and all(h is None for h in other_mock.seen_auth)
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_step_up_on_insufficient_scope(
    run: Any, protected: Protected, approve: list[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    protected.auth.grant_scope = "profile"  # the AS grants less than the resource needs
    assert login(run, protected.url, "--scope", "profile").rc == 0
    assert run("ls", protected.url).rc == 2  # 403 insufficient_scope, non-interactive
    protected.auth.grant_scope = None
    monkeypatch.setattr(cli, "interactive", lambda _args: True)
    r = run("ls", protected.url)
    assert r.rc == 0, r.err
    rec = TokenStore().get(protected.url)
    assert rec is not None and set(rec["scope"].split()) == {"profile", "skills:read"}


def test_static_authorization_header_wins(run: Any, protected: Protected, approve: list[str]) -> None:
    assert login(run, protected.url).rc == 0
    r = run("ls", protected.url, "--header", "Authorization: Bearer nope")
    assert r.rc == 2 and "configured Authorization header" in r.err
    assert protected.auth.seen_auth[-1] == "Bearer nope"


# --- what a client must refuse -----------------------------------------------------------------


def test_rejects_state_mismatch(run: Any, protected: Protected, monkeypatch: pytest.MonkeyPatch) -> None:
    def forge(loc: str) -> str:
        return loc.replace("state=", "state=forged")

    monkeypatch.setattr("webbrowser.open", browser(forge))
    r = login(run, protected.url)
    assert r.rc == 2 and "state does not match" in r.err
    assert TokenStore().get(protected.url) is None


def test_rejects_wrong_iss(run: Any, protected: Protected, approve: list[str]) -> None:
    protected.auth.iss_override = "https://evil.example"
    r = login(run, protected.url)
    assert r.rc == 2 and "mix-up" in r.err


def test_rejects_metadata_for_another_resource(run: Any, protected: Protected, approve: list[str]) -> None:
    protected.auth.prm_resource_override = "https://elsewhere.example/mcp"
    r = login(run, protected.url)
    assert r.rc == 2 and "refusing it" in r.err
    assert protected.auth.registrations == 0


def test_rejects_server_without_s256(run: Any, protected: Protected, approve: list[str]) -> None:
    protected.auth.s256 = False
    r = login(run, protected.url)
    assert r.rc == 2 and "S256" in r.err
    assert protected.auth.registrations == 0


def test_denied_authorization(run: Any, protected: Protected, monkeypatch: pytest.MonkeyPatch) -> None:
    def deny(loc: str) -> str:
        parts = urllib.parse.urlsplit(loc)
        q = urllib.parse.parse_qs(parts.query)
        back = {"error": "access_denied", "state": q["state"][0], "iss": q["iss"][0]}
        return f"{parts.scheme}://{parts.netloc}{parts.path}?" + urllib.parse.urlencode(back)

    monkeypatch.setattr("webbrowser.open", browser(deny))
    r = login(run, protected.url)
    assert r.rc == 2 and "access_denied" in r.err


def test_login_to_open_server_is_a_no_op(run: Any, served: Any) -> None:
    r = login(run, served.url)
    assert r.rc == 0 and "nothing to log in to" in r.out


def test_no_callback_times_out(run: Any, protected: Protected, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("webbrowser.open", lambda _u: True)  # user never finishes
    r = run("auth", "login", protected.url, "--wait", "1")
    assert r.rc == 2 and "no browser callback" in r.err
