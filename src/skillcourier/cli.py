"""skillcourier command line."""

from __future__ import annotations

import argparse
import difflib
import json
import os
import shlex
import shutil
import sys
import time
import webbrowser
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from . import __version__, oauth
from .config import Discovered, discover, label_for_url, slug
from .mcp import AuthRequired, Endpoint, McpClient, McpError, TransportError, has_auth_header
from .oauth import OAuthError, OAuthProvider, TokenStore, canonical_resource, probe
from .spec import SkillEntry, VerificationError, parse_entry, split_frontmatter
from .store import (
    Lock,
    endpoint_from_record,
    endpoint_record,
    fetch_verified,
    installed_name,
    local_state,
    lock_record,
    materialize,
    resolve_target,
    review,
    set_diff,
)

EXIT_OK, EXIT_ATTENTION, EXIT_ERROR = 0, 1, 2


class CliError(Exception):
    pass


def out(text: str = "") -> None:
    print(text)


def err(text: str) -> None:
    print(text, file=sys.stderr)


def human_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.1f} MB"


# --- server resolution -------------------------------------------------------------------------


def resolve_endpoint(args: argparse.Namespace, found: Discovered) -> Endpoint:
    server: str = args.server
    headers = {}
    for h in args.header or []:
        k, sep, v = h.partition(":")
        if not sep:
            raise CliError(f"--header expects 'Name: value', got {h!r}")
        headers[k.strip()] = v.strip()
    if args.cmd:
        parts = shlex.split(args.cmd)
        return Endpoint(slug(server), "stdio", command=parts[0], args=parts[1:], cwd=str(args.cwd))
    if server.startswith(("http://", "https://")):
        label = slug(args.label) if args.label else label_for_url(server)
        return Endpoint(label, "http", url=server, headers=headers)
    if server in found.endpoints:
        ep = found.endpoints[server]
        if found.missing_vars.get(server):
            err(f"warning: {server}: unset variables {', '.join(found.missing_vars[server])}")
        ep.headers.update(headers)
        return ep
    known = ", ".join(sorted(found.endpoints)) or "none found"
    raise CliError(f"no MCP server labelled {server!r} (configured: {known}). Pass a URL or --cmd.")


def interactive(args: argparse.Namespace) -> bool:
    """May we open a browser for an OAuth login? Never in hook mode, CI or a pipe."""
    if getattr(args, "hook", False) or getattr(args, "no_login", False):
        return False
    return sys.stdin.isatty() and sys.stderr.isatty()


def make_auth(ep: Endpoint, args: argparse.Namespace, allow_login: bool = True) -> OAuthProvider | None:
    """OAuth for HTTP servers without a configured Authorization header."""
    if ep.kind != "http" or not ep.url or has_auth_header(ep.headers):
        return None
    return OAuthProvider(
        ep.url,
        interactive=allow_login and interactive(args),
        announce=err,
        timeout=args.timeout,
    )


def connect(ep: Endpoint, args: argparse.Namespace) -> McpClient:
    client = McpClient(ep, timeout=args.timeout, auth=make_auth(ep, args))
    try:
        info = client.connect()
    except BaseException:
        client.close()
        raise
    if not info.skills:
        client.close()
        raise CliError(
            f"{ep.label} ({ep.describe()}) does not declare the io.modelcontextprotocol/skills "
            "extension, so it serves no skills (per spec, skills/list is not called)."
        )
    return client


def load_listing(client: McpClient) -> tuple[list[SkillEntry], list[tuple[str, str]]]:
    good: list[SkillEntry] = []
    bad: list[tuple[str, str]] = []
    for raw in client.list_skills():
        try:
            good.append(parse_entry(raw))
        except VerificationError as e:
            bad.append((str(raw.get("uri", "?")), str(e)))
    return good, bad


def select(entries: list[SkillEntry], wanted: list[str], client: McpClient) -> list[SkillEntry]:
    """Pick entries by name, skill path or SKILL.md URI. Ambiguous names are refused, not guessed."""
    picked: list[SkillEntry] = []
    for w in wanted:
        if "://" in w:
            hit = [e for e in entries if e.uri == w]
            # A listing may be partial; the spec requires skills/get to work for any served skill.
            picked.append(hit[0] if hit else parse_entry(client.get_skill(w)))
            continue
        hit = [e for e in entries if "/".join(e.path_segments) == w.strip("/")] or [
            e for e in entries if e.name == w
        ]
        if not hit:
            raise CliError(f"no skill {w!r} on this server (try `skillcourier ls`)")
        if len(hit) > 1:
            paths = ", ".join("/".join(e.path_segments) for e in hit)
            raise CliError(f"{w!r} is ambiguous on this server: {paths}. Name the path instead.")
        picked.append(hit[0])
    return picked


def local_names(dirs: list[Path]) -> dict[str, Path]:
    """name -> SKILL.md for filesystem skills an agent would also see."""
    found: dict[str, Path] = {}
    for d in dirs:
        if not d.is_dir():
            continue
        for md in sorted(d.glob("*/SKILL.md")):
            try:
                fm, _ = split_frontmatter(md.read_bytes())
                name = str(fm.get("name") or md.parent.name)
            except (OSError, VerificationError):
                name = md.parent.name
            found.setdefault(name, md)
    return found


# --- commands ----------------------------------------------------------------------------------


def cmd_servers(args: argparse.Namespace) -> int:
    found = discover(args.cwd)
    rows = []
    for label, ep in found.endpoints.items():
        row: dict[str, Any] = {"label": label, "endpoint": ep.describe(), "source": ep.source}
        if found.missing_vars.get(label):
            row["missing_vars"] = found.missing_vars[label]
        if not args.no_probe:
            try:
                with McpClient(ep, timeout=args.timeout, auth=make_auth(ep, args, allow_login=False)) as c:
                    assert c.info is not None
                    row.update(era=c.info.era, skills=c.info.skills)
                    if c.info.skills:
                        row["skill_count"] = len(c.list_skills())
            except (TransportError, McpError, OSError) as e:
                row["error"] = str(e)
        rows.append(row)
    if args.json:
        out(json.dumps({"servers": rows, "skipped": found.skipped}, indent=2))
        return EXIT_OK
    if not rows:
        out("No MCP servers configured for this directory (checked ~/.claude.json, .mcp.json, ~/.codex/config.toml).")
    for r in rows:
        if "error" in r:
            state = f"unreachable: {r['error']}"
        elif args.no_probe:
            state = "not probed"
        elif r.get("skills"):
            state = f"serves {r['skill_count']} skills ({r['era']} protocol)"
        else:
            state = f"no skills extension ({r['era']} protocol)"
        out(f"{r['label']:<20} {state}")
        out(f"{'':<20} {r['endpoint']}  [{r['source']}]")
    for s in found.skipped:
        out(f"skipped: {s}")
    return EXIT_OK


def cmd_ls(args: argparse.Namespace) -> int:
    ep = resolve_endpoint(args, discover(args.cwd))
    target = resolve_target(args.to, args.cwd)
    lock = Lock(target)
    with connect(ep, args) as client:
        entries, bad = load_listing(client)
    counts = Counter(e.name for e in entries)
    locals_ = local_names([target, resolve_target("claude", args.cwd), resolve_target("claude-user", args.cwd)])
    rows: list[dict[str, Any]] = []
    for e in entries:
        rv = review(e, ep.label, grant=False)
        imported = lock.find(ep.label, e.uri)
        rows.append(
            {
                "name": e.name,
                "uri": e.uri,
                "installs_as": imported or installed_name(ep.label, e, counts[e.name] > 1),
                "imported": imported is not None,
                "files": None if e.dynamic else len(e.files or ()),
                "bytes": None if e.dynamic else e.total_size,
                "dynamic": e.dynamic,
                "requests_grants": rv.stripped,
                "exec_files": len(rv.exec_files),
                "same_name_local_skill": str(locals_[e.name]) if e.name in locals_ else None,
                "description": e.description,
            }
        )
    if args.json:
        out(json.dumps({"server": ep.label, "skills": rows, "invalid": [{"uri": u, "error": m} for u, m in bad]}, indent=2))
        return EXIT_OK
    out(f"{ep.label}: {len(entries)} skills ({ep.describe()})")
    for r in rows:
        flags = []
        if r["imported"]:
            flags.append("imported")
        if r["dynamic"]:
            flags.append("dynamic: cannot be pinned")
        if r["requests_grants"]:
            flags.append("asks for " + "+".join(r["requests_grants"]))
        if r["exec_files"]:
            flags.append(f"{r['exec_files']} script files")
        if r["same_name_local_skill"]:
            flags.append(f"same name as local {r['same_name_local_skill']}")
        size = "dynamic" if r["dynamic"] else f"{r['files']} files, {human_size(r['bytes'])}"
        out(f"  {r['name']:<34} {size:<22} -> {r['installs_as']}" + (f"  [{'; '.join(flags)}]" if flags else ""))
        if args.long:
            out(f"      {r['description'][:200]}")
    for uri, msg in bad:
        out(f"  INVALID {uri}: {msg}")
    return EXIT_OK


def cmd_show(args: argparse.Namespace) -> int:
    ep = resolve_endpoint(args, discover(args.cwd))
    with connect(ep, args) as client:
        entries, _ = load_listing(client)
        (entry,) = select(entries, [args.skill], client)
        if entry.files is None:
            raise CliError(f"{entry.uri} is dynamic: nothing to verify it against, so it is not shown")
        rel = args.file or "SKILL.md"
        f = next((x for x in entry.files if x.relpath == rel), None)
        if f is None:
            raise CliError(f"{rel} is not in {entry.uri}'s manifest (an unlisted file is a verification failure)")
        data = client.read_resource(f.uri)
    from .spec import verify_bytes, verify_skill_md

    if rel == "SKILL.md":
        verify_skill_md(data, entry)
    else:
        verify_bytes(data, f)
    err(f"# {f.uri} from server '{ep.label}' ({len(data)} bytes, digest verified)")
    sys.stdout.buffer.write(data)
    return EXIT_OK


def confirm(question: str, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        err("Not a terminal: re-run with --yes to approve.")
        return False
    return input(f"{question} [y/N] ").strip().lower() in ("y", "yes")


def cmd_add(args: argparse.Namespace) -> int:
    ep = resolve_endpoint(args, discover(args.cwd))
    target = resolve_target(args.to, args.cwd)
    lock = Lock(target)
    with connect(ep, args) as client:
        entries, bad = load_listing(client)
        counts = Counter(e.name for e in entries)
        if args.all:
            chosen = [e for e in entries if not e.dynamic and not lock.find(ep.label, e.uri)]
        elif args.skills:
            chosen = select(entries, args.skills, client)
        else:
            raise CliError("name one or more skills, or pass --all")
        plan: list[tuple[SkillEntry, str]] = []
        for e in chosen:
            if e.dynamic:
                raise CliError(f"{e.uri}: resources are \"dynamic\", so there are no digests to pin. Not imported.")
            existing = lock.find(ep.label, e.uri)
            if existing:
                out(f"= {existing}: already imported from {ep.label}; `skillcourier sync` updates it")
                continue
            name = installed_name(ep.label, e, counts[e.name] > 1)
            if (target / name).exists() or name in lock.skills:
                raise CliError(f"{target / name} already exists and was not imported from this origin; refusing to overwrite")
            plan.append((e, name))
        if not plan:
            return EXIT_OK
        out(f"Import from '{ep.label}' ({ep.describe()}) into {target}:")
        for e, name in plan:
            rv = review(e, ep.label, args.grant_tools)
            out(f"  {name}   <- {e.uri}  ({len(e.files or ())} files, {human_size(e.total_size)})")
            if rv.stripped:
                out(f"      strips {', '.join(rv.stripped)} (pass --grant-tools to keep)")
            if rv.granted:
                out(f"      GRANTS {', '.join(rv.granted)} as written by the server")
            if rv.exec_files:
                out(f"      script files (the skill may ask the agent to run them): {', '.join(rv.exec_files[:6])}")
            if rv.nested_skills:
                out(f"      nested SKILL.md files kept as plain supporting files: {', '.join(rv.nested_skills)}")
            if rv.truncated_description:
                out("      description cut to 1024 characters after the origin tag")
        if args.dry_run:
            return EXIT_OK
        if not confirm(f"Import {len(plan)} skill(s)?", args.yes):
            return EXIT_ATTENTION
        for e, name in plan:
            fm, body, files = fetch_verified(client, e)
            written = materialize(target, name, ep.label, e, fm, body, files, args.grant_tools)
            lock.skills[name] = lock_record(ep, client, e, written, review(e, ep.label, args.grant_tools))
            lock.save()
            out(f"+ {name}  ({len(files)} files verified)")
    for uri, msg in bad:
        err(f"skipped invalid entry {uri}: {msg}")
    return EXIT_OK


def _group_by_origin(lock: Lock, only: list[str]) -> dict[str, list[str]]:
    groups: dict[str, list[str]] = defaultdict(list)
    for name, rec in lock.skills.items():
        if not only or name in only:
            groups[rec["origin"]["label"]].append(name)
    missing = [n for n in only if n not in lock.skills]
    if missing:
        raise CliError(f"not in {lock.path}: {', '.join(missing)}")
    return groups


def _endpoint_for(label: str, rec: dict[str, Any], found: Discovered) -> Endpoint | None:
    return found.endpoints.get(label) or endpoint_from_record(rec["origin"])


def origin_moved(rec: dict[str, Any], ep: Endpoint | None) -> str | None:
    """Approval is bound to (server identity, uri). A label now pointing somewhere else is a new
    origin, so the old approval does not carry over."""
    if ep is None:
        return None
    now = endpoint_record(ep)
    was = rec["origin"]
    for key in ("kind", "url", "command"):
        if key in was and was.get(key) != now.get(key) and not (key == "command" and "command" not in now):
            return f"! server '{was['label']}' {key} changed: {was.get(key)} -> {now.get(key)}"
    return None


def inspect(args: argparse.Namespace, lock: Lock) -> list[dict[str, Any]]:
    """One status row per locked skill. Contacts each origin once; never fetches file content."""
    found = discover(args.cwd)
    rows: list[dict[str, Any]] = []
    for label, names in _group_by_origin(lock, args.names).items():
        ep = next((e for n in names if (e := _endpoint_for(label, lock.skills[n], found))), None)
        client: McpClient | None = None
        problem = None
        needs_login: str | None = None
        if ep is None:
            problem = f"server '{label}' is not configured here and the lockfile cannot reach it on its own"
        elif not getattr(args, "offline", False):
            try:
                client = connect(ep, args)
            except AuthRequired as e:
                problem = f"cannot reach '{label}': {e}"
                needs_login = ep.url
            except (TransportError, McpError, CliError, OSError) as e:
                problem = f"cannot reach '{label}': {e}"
        try:
            for name in names:
                rec = lock.skills[name]
                row: dict[str, Any] = {"name": name, "origin": label, "uri": rec["uri"]}
                lstate, lproblems = local_state(lock.target, name, rec)
                row["local"] = lstate
                if needs_login:
                    row["needs_login"] = needs_login
                if lproblems:
                    row["local_problems"] = lproblems
                if client is None:
                    row["upstream"] = "offline" if getattr(args, "offline", False) else "unreachable"
                    if problem:
                        row["error"] = problem
                else:
                    try:
                        entry = parse_entry(client.get_skill(rec["uri"]))
                        moved = origin_moved(rec, ep)
                        if moved:
                            row["upstream"] = "changed"
                            row["changes"] = [moved, *set_diff(rec["resources"], entry)]
                            row["_entry"] = entry
                        elif entry.resource_set() == rec["resources"]:
                            row["upstream"] = "same"
                        else:
                            row["upstream"] = "changed"
                            row["changes"] = set_diff(rec["resources"], entry)
                            row["_entry"] = entry
                    except McpError as e:
                        row["upstream"] = "gone" if e.code == -32602 else "error"
                        row["error"] = str(e)
                    except (VerificationError, TransportError) as e:
                        row["upstream"] = "invalid"
                        row["error"] = str(e)
                if ep is not None:
                    row["_ep"] = ep
                rows.append(row)
        finally:
            if client is not None:
                client.close()
    return rows


def row_ok(r: dict[str, Any]) -> bool:
    return r["local"] == "ok" and r["upstream"] in ("same", "offline")


def public(r: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in r.items() if not k.startswith("_")}


def describe_row(r: dict[str, Any]) -> str:
    bits = []
    if r["upstream"] == "changed":
        bits.append("CHANGED upstream: approval revoked until you re-approve")
    elif r["upstream"] == "gone":
        bits.append("no longer served by its server")
    elif r["upstream"] in ("unreachable", "invalid", "error"):
        bits.append(f"{r['upstream']}: {r.get('error', '')}")
    if r["local"] == "missing":
        bits.append("missing on disk")
    elif r["local"] == "modified":
        bits.append("modified on disk (" + ", ".join(r.get("local_problems", [])[:4]) + ")")
    return f"{r['name']}: " + ("; ".join(bits) if bits else "ok")


def cmd_check(args: argparse.Namespace) -> int:
    target = resolve_target(args.to, args.cwd)
    lock = Lock(target)
    if args.hook:
        try:
            rows = inspect(args, lock)
        except Exception as e:  # a SessionStart hook must never break the session
            print(json.dumps({"systemMessage": f"skillcourier check failed: {e}"}))
            return EXIT_OK
        bad = [r for r in rows if not row_ok(r)]
        if bad:
            names = ", ".join(r["name"] for r in bad[:5]) + (" ..." if len(bad) > 5 else "")
            msg = f"skillcourier: {len(bad)} imported MCP skill(s) need attention ({names}). Run `skillcourier check`."
            logins = sorted({str(r["needs_login"]) for r in bad if r.get("needs_login")})
            if logins:
                msg += " Log in first: " + "; ".join(f"`skillcourier auth login {u}`" for u in logins) + "."
            print(json.dumps({"systemMessage": msg}))
        return EXIT_OK
    rows = inspect(args, lock)
    if args.json:
        out(json.dumps({"target": str(target), "skills": [public(r) for r in rows]}, indent=2))
    else:
        if not rows:
            out(f"No imported skills in {target}.")
        for r in rows:
            out(describe_row(r))
            for c in r.get("changes", []):
                out(f"    {c}")
    return EXIT_OK if all(row_ok(r) for r in rows) else EXIT_ATTENTION


def cmd_sync(args: argparse.Namespace) -> int:
    target = resolve_target(args.to, args.cwd)
    lock = Lock(target)
    rows = inspect(args, lock)
    status = EXIT_OK
    for r in rows:
        name, rec = r["name"], lock.skills[r["name"]]
        ep: Endpoint | None = r.get("_ep")
        if r["upstream"] == "same" and r["local"] == "ok":
            out(f"= {name}")
            continue
        if r["upstream"] in ("unreachable", "invalid", "error", "gone") or ep is None:
            out(describe_row(r))
            status = EXIT_ATTENTION
            continue
        if r["upstream"] == "same" and r["local"] == "modified" and not args.restore:
            out(describe_row(r) + "  (pass --restore to put back the pinned content)")
            status = EXIT_ATTENTION
            continue
        with connect(ep, args) as client:
            entry = r.get("_entry") or parse_entry(client.get_skill(rec["uri"]))
            fm, body, files = fetch_verified(client, entry)
            if r["upstream"] == "changed":
                out(f"~ {name}: the server changed this skill")
                for c in r.get("changes", []):
                    out(f"    {c}")
                old_md = target / name / "SKILL.md"
                old_body = split_frontmatter(old_md.read_bytes())[1] if old_md.exists() else b""
                diff = difflib.unified_diff(
                    old_body.decode("utf-8", "replace").splitlines(),
                    body.decode("utf-8", "replace").splitlines(),
                    "SKILL.md (approved)",
                    "SKILL.md (now served)",
                    lineterm="",
                    n=1,
                )
                for line in list(diff)[: args.diff_lines]:
                    out("    " + line)
                if not args.approve and not confirm(f"Approve the new content of {name}?", False):
                    out(f"  kept the approved version of {name}; re-run with --approve to accept")
                    status = EXIT_ATTENTION
                    continue
            grant = bool(rec.get("granted")) and r["upstream"] == "same"  # a changed set revokes grants
            written = materialize(target, name, rec["origin"]["label"], entry, fm, body, files, grant)
            rv = review(entry, rec["origin"]["label"], grant)
            new = lock_record(ep, client, entry, written, rv)
            if r["upstream"] == "same":
                new["approved_at"] = rec.get("approved_at", new["approved_at"])
                new["origin"] = rec["origin"]
            lock.skills[name] = new
            lock.save()
            verb = "updated" if r["upstream"] == "changed" else "restored"
            out(f"+ {name}: {verb} ({len(files)} files verified)")
    return status


def cmd_remove(args: argparse.Namespace) -> int:
    target = resolve_target(args.to, args.cwd)
    lock = Lock(target)
    for name in args.names:
        if name not in lock.skills:
            raise CliError(f"{name} is not an imported skill in {target}; refusing to delete it")
    for name in args.names:
        shutil.rmtree(target / name, ignore_errors=True)
        del lock.skills[name]
        lock.save()
        out(f"- {name}")
    return EXIT_OK


def _http_endpoint(args: argparse.Namespace) -> Endpoint:
    ep = resolve_endpoint(args, discover(args.cwd))
    if ep.kind != "http" or not ep.url:
        raise CliError(f"{ep.label} is a stdio server; OAuth applies only to HTTP servers")
    return ep


def cmd_auth_login(args: argparse.Namespace) -> int:
    ep = _http_endpoint(args)
    assert ep.url is not None
    if has_auth_header(ep.headers):
        err(f"note: {ep.label} has a configured Authorization header, which skillcourier sends instead of OAuth tokens")
    challenge = probe(ep.url, args.timeout)
    if challenge is None and not args.force:
        out(f"{ep.label} ({ep.url}) answered without asking for credentials; nothing to log in to (use --force to try anyway).")
        return EXIT_OK
    secret = None
    if args.client_secret_env:
        secret = os.environ.get(args.client_secret_env)
        if not secret:
            raise CliError(f"${args.client_secret_env} is empty")
    rec = oauth.login(
        ep.url,
        challenge=challenge,
        scope=args.scope,
        client_id=args.client_id,
        client_secret=secret,
        port=args.port,
        open_browser=None if args.no_browser else webbrowser.open,
        announce=err,
        wait_s=args.wait,
        timeout=args.timeout,
    )
    out(f"Logged in to {ep.label} ({rec['resource']}) via {rec['issuer']}; scope: {rec['scope'] or '(default)'}.")
    out(f"Tokens are stored in {TokenStore().path} (mode 0600) and sent only to {rec['resource']}.")
    return EXIT_OK


def _expiry(rec: dict[str, Any]) -> str:
    exp = rec.get("expires_at")
    if not isinstance(exp, (int, float)):
        return "no expiry given"
    left = int(exp - time.time())
    if left <= 0:
        return "expired" + (", will refresh" if rec.get("refresh_token") else ", needs login")
    return f"expires in {left // 3600}h{left % 3600 // 60:02d}m"


def cmd_auth_status(args: argparse.Namespace) -> int:
    store = TokenStore()
    recs = store.load()["resources"]
    rows = [
        {
            "resource": url,
            "issuer": r.get("issuer"),
            "scope": r.get("scope"),
            "refreshable": bool(r.get("refresh_token")),
            "expires_at": r.get("expires_at"),
            "client_id": (r.get("client") or {}).get("client_id"),
        }
        for url, r in sorted(recs.items())
        if isinstance(r, dict)
    ]
    if args.json:
        out(json.dumps({"file": str(store.path), "logins": rows}, indent=2))
        return EXIT_OK
    if not rows:
        out(f"No OAuth logins stored ({store.path}).")
        return EXIT_OK
    for url, r in sorted(recs.items()):
        out(f"{url}")
        out(f"    issuer {r.get('issuer')}; scope {r.get('scope') or '(default)'}; {_expiry(r)}")
    return EXIT_OK


def cmd_auth_logout(args: argparse.Namespace) -> int:
    ep = _http_endpoint(args)
    assert ep.url is not None
    if oauth.logout(ep.url, TokenStore(), timeout=args.timeout):
        out(f"Logged out of {canonical_resource(ep.url)} (tokens deleted; revoked where the server supports it).")
        return EXIT_OK
    out(f"No stored login for {canonical_resource(ep.url)}.")
    return EXIT_OK


def cmd_dev_server(args: argparse.Namespace) -> int:
    from .devserver import SkillDirServer, make_http_server, serve_stdio

    root = Path(args.dir)
    if not root.is_dir():
        raise CliError(f"{root} is not a directory")
    era = "legacy" if args.legacy else "dual"
    server = SkillDirServer(root, era=era)  # type: ignore[arg-type]
    if args.http is None:
        if args.oauth:
            raise CliError("--oauth needs --http PORT")
        serve_stdio(server)
        return EXIT_OK
    mock = None
    if args.oauth:
        from .devserver import MockAuthServer

        mock = MockAuthServer(scope=args.oauth_scope)
    httpd = make_http_server(server, args.http, oauth=mock)
    note = " behind a mock OAuth server (every login is auto-approved)" if mock else ""
    err(f"serving {len(server.skills())} skills from {root} at http://127.0.0.1:{httpd.server_address[1]}/mcp{note}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return EXIT_OK


# --- argument parsing --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="skillcourier",
        description="Import the Agent Skills your MCP servers serve (SEP-2640) into Claude Code, "
        "Codex or any SKILL.md agent: digest-verified, origin-labelled, pinned in a lockfile.",
    )
    p.add_argument("--version", action="version", version=f"skillcourier {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp: argparse.ArgumentParser, server: bool = False, target: bool = True) -> None:
        sp.add_argument("--cwd", type=Path, default=Path.cwd(), help="project directory (default: here)")
        sp.add_argument("--timeout", type=float, default=None, help="seconds per server request (default 30; 5 with --hook)")
        sp.add_argument("--no-login", action="store_true", help="never open a browser for an OAuth login")
        if target:
            sp.add_argument(
                "--to",
                default="claude",
                help="claude (./.claude/skills, default), claude-user (~/.claude/skills), agents "
                "(./.agents/skills), agents-user (~/.agents/skills), or a directory path",
            )
        if server:
            sp.add_argument("server", help="a configured server label, a server URL, or a label for --cmd")
            sp.add_argument("--cmd", help="launch a stdio server with this command line instead")
            sp.add_argument("--label", help="label for a URL server (default: derived from the host)")
            sp.add_argument("--header", action="append", help="extra HTTP header 'Name: value' (repeatable)")

    sp = sub.add_parser("servers", help="list configured MCP servers and whether they serve skills")
    common(sp, target=False)
    sp.add_argument("--no-probe", action="store_true", help="do not contact the servers")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_servers)

    sp = sub.add_parser("ls", help="list the skills a server serves")
    common(sp, server=True)
    sp.add_argument("--long", "-l", action="store_true", help="show descriptions")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_ls)

    sp = sub.add_parser("show", help="print a served skill's SKILL.md (or --file) after verifying it")
    common(sp, server=True, target=False)
    sp.add_argument("skill", help="skill name, path or SKILL.md URI")
    sp.add_argument("--file", help="a supporting file's path inside the skill")
    sp.set_defaults(func=cmd_show)

    sp = sub.add_parser("add", help="verify and import skills, pinning them in the lockfile")
    common(sp, server=True)
    sp.add_argument("skills", nargs="*", help="skill names, paths or SKILL.md URIs")
    sp.add_argument("--all", action="store_true", help="every pinnable skill not yet imported")
    sp.add_argument("--grant-tools", action="store_true", help="keep allowed-tools/hooks as the server wrote them")
    sp.add_argument("--yes", "-y", action="store_true", help="approve without prompting")
    sp.add_argument("--dry-run", action="store_true", help="show the plan, write nothing")
    sp.set_defaults(func=cmd_add)

    sp = sub.add_parser("check", help="compare imported skills with their servers and the disk")
    common(sp)
    sp.add_argument("names", nargs="*", help="only these imported skills")
    sp.add_argument("--offline", action="store_true", help="only verify files on disk against the lockfile")
    sp.add_argument("--hook", action="store_true", help="SessionStart hook mode: JSON systemMessage, always exit 0")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_check)

    sp = sub.add_parser("sync", help="restore missing skills; show and re-approve changed ones")
    common(sp)
    sp.add_argument("names", nargs="*", help="only these imported skills")
    sp.add_argument("--approve", action="store_true", help="accept upstream changes after showing them")
    sp.add_argument("--restore", action="store_true", help="overwrite local edits with the pinned content")
    sp.add_argument("--diff-lines", type=int, default=60, help="max SKILL.md diff lines to print")
    sp.set_defaults(func=cmd_sync)

    sp = sub.add_parser("remove", help="delete imported skills and their lockfile entries")
    common(sp)
    sp.add_argument("names", nargs="+")
    sp.set_defaults(func=cmd_remove)

    sp = sub.add_parser("dev-server", help="serve a local skills folder over MCP (stdio, or --http PORT)")
    sp.add_argument("dir")
    sp.add_argument("--http", type=int, help="serve Streamable HTTP on 127.0.0.1:PORT/mcp")
    sp.add_argument("--legacy", action="store_true", help="answer only the legacy initialize handshake")
    sp.add_argument("--oauth", action="store_true", help="require OAuth (mock authorization server, auto-approves)")
    sp.add_argument("--oauth-scope", default="skills:read", help="scope the mock server requires")
    sp.set_defaults(func=cmd_dev_server)

    auth = sub.add_parser("auth", help="OAuth logins for HTTP servers that require them")
    asub = auth.add_subparsers(dest="auth_command", required=True)
    sp = asub.add_parser("login", help="log in to a server (authorization code + PKCE, opens a browser)")
    common(sp, server=True, target=False)
    sp.add_argument("--scope", help="scopes to request (default: what the server asks for)")
    sp.add_argument("--client-id", help="a client registered with the provider (default: dynamic registration)")
    sp.add_argument("--client-secret-env", metavar="VAR", help="read that client's secret from $VAR")
    sp.add_argument("--port", type=int, default=0, help="loopback callback port (default: any free port)")
    sp.add_argument("--no-browser", action="store_true", help="only print the login URL")
    sp.add_argument("--wait", type=float, default=300.0, help="seconds to wait for the browser (default 300)")
    sp.add_argument("--force", action="store_true", help="log in even if the server did not ask")
    sp.set_defaults(func=cmd_auth_login)
    sp = asub.add_parser("status", help="list stored logins (never prints tokens)")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_auth_status)
    sp = asub.add_parser("logout", help="revoke and delete a stored login")
    common(sp, server=True, target=False)
    sp.set_defaults(func=cmd_auth_logout)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    # argparse stops filling a nargs="*" positional at the first option, so
    # `add hf --yes a b` would leave a and b unparsed. Collect them explicitly.
    args, extras = parser.parse_known_args(argv)
    list_dest = next((d for d in ("skills", "names") if isinstance(getattr(args, d, None), list)), None)
    if extras and (list_dest is None or any(x.startswith("-") for x in extras)):
        parser.error("unrecognized arguments: " + " ".join(extras))
    if list_dest and extras:
        getattr(args, list_dest).extend(extras)
    if hasattr(args, "cwd"):
        args.cwd = args.cwd.resolve()
    if not hasattr(args, "timeout"):
        args.timeout = 30.0
    if args.timeout is None:
        args.timeout = 5.0 if getattr(args, "hook", False) else 30.0
    if not hasattr(args, "names"):
        args.names = []
    try:
        rc: int = args.func(args)
        return rc
    except AuthRequired as e:
        err(f"skillcourier: {e}")
    except (CliError, VerificationError, TransportError, McpError, OAuthError) as e:
        err(f"skillcourier: {e}")
    except KeyboardInterrupt:
        err("interrupted")
    return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
