"""Find the MCP servers a user already configured, so `skillcourier ls hf` just works.

Sources, in Claude Code's precedence order: local scope (~/.claude.json projects[cwd]), project
scope (.mcp.json), user scope (~/.claude.json mcpServers), then Codex (~/.codex/config.toml).
The first definition of a label wins; later ones are reported as shadowed.
"""

from __future__ import annotations

import json
import os
import re
import tomllib
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .mcp import Endpoint

_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


@dataclass
class Discovered:
    endpoints: dict[str, Endpoint] = field(default_factory=dict)
    skipped: list[str] = field(default_factory=list)  # human-readable reasons
    missing_vars: dict[str, list[str]] = field(default_factory=dict)  # label -> unset ${VAR}s


def claude_config_dir() -> Path:
    env = os.environ.get("CLAUDE_CONFIG_DIR")
    return Path(env).expanduser() if env else Path.home() / ".claude"


def claude_json_path() -> Path:
    env = os.environ.get("CLAUDE_CONFIG_DIR")
    return Path(env).expanduser() / ".claude.json" if env else Path.home() / ".claude.json"


def codex_home() -> Path:
    env = os.environ.get("CODEX_HOME")
    return Path(env).expanduser() if env else Path.home() / ".codex"


def expand(value: str, missing: list[str]) -> str:
    """Claude Code's `${VAR}` / `${VAR:-default}` expansion. Unset vars are recorded, not guessed."""

    def sub(m: re.Match[str]) -> str:
        val = os.environ.get(m.group(1))
        if val is not None:
            return val
        if m.group(2) is not None:
            return m.group(2)
        missing.append(m.group(1))
        return ""

    return _VAR.sub(sub, value)


def _str_map(raw: Any) -> dict[str, str]:
    return {str(k): str(v) for k, v in raw.items()} if isinstance(raw, dict) else {}


def endpoint_from_claude(label: str, raw: Any, source: str, missing: list[str]) -> Endpoint | str:
    """One Claude Code `mcpServers` entry -> Endpoint, or a reason it cannot be used."""
    if not isinstance(raw, dict):
        return f"{label} ({source}): not an object"
    kind = raw.get("type") or ("http" if "url" in raw else "stdio")
    if kind in ("http", "streamable-http"):
        url = raw.get("url")
        if not isinstance(url, str):
            return f"{label} ({source}): http server without url"
        headers = {k: expand(v, missing) for k, v in _str_map(raw.get("headers")).items()}
        return Endpoint(label, "http", url=expand(url, missing), headers=headers, source=source)
    if kind == "stdio":
        cmd = raw.get("command")
        if not isinstance(cmd, str):
            return f"{label} ({source}): stdio server without command"
        args = [expand(str(a), missing) for a in raw.get("args") or []]
        env = {k: expand(v, missing) for k, v in _str_map(raw.get("env")).items()}
        return Endpoint(label, "stdio", command=expand(cmd, missing), args=args, env=env, source=source)
    return f"{label} ({source}): transport {kind!r} is not supported (use http or stdio)"


def endpoint_from_codex(label: str, raw: Any, missing: list[str]) -> Endpoint | str:
    source = "codex config.toml"
    if not isinstance(raw, dict):
        return f"{label} ({source}): not a table"
    if isinstance(raw.get("url"), str):
        headers = _str_map(raw.get("http_headers"))
        for hname, var in _str_map(raw.get("env_http_headers")).items():
            headers[hname] = expand("${" + var + "}", missing)
        tok_var = raw.get("bearer_token_env_var")
        if isinstance(tok_var, str):
            headers["Authorization"] = "Bearer " + expand("${" + tok_var + "}", missing)
        return Endpoint(label, "http", url=raw["url"], headers=headers, source=source)
    if isinstance(raw.get("command"), str):
        return Endpoint(
            label,
            "stdio",
            command=raw["command"],
            args=[str(a) for a in raw.get("args") or []],
            env=_str_map(raw.get("env")),
            cwd=raw.get("cwd") if isinstance(raw.get("cwd"), str) else None,
            source=source,
        )
    return f"{label} ({source}): neither url nor command"


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def discover(cwd: Path) -> Discovered:
    out = Discovered()

    def take(label: str, made: Endpoint | str, missing: list[str]) -> None:
        if isinstance(made, str):
            out.skipped.append(made)
        elif label in out.endpoints:
            out.skipped.append(f"{label} ({made.source}): shadowed by {out.endpoints[label].source}")
        else:
            out.endpoints[label] = made
            if missing:
                out.missing_vars[label] = sorted(set(missing))

    cj = _load_json(claude_json_path())
    if isinstance(cj, dict):
        projects = cj.get("projects")
        proj = projects.get(str(cwd.resolve())) if isinstance(projects, dict) else None
        if isinstance(proj, dict) and isinstance(proj.get("mcpServers"), dict):
            for label, raw in proj["mcpServers"].items():
                miss: list[str] = []
                take(label, endpoint_from_claude(label, raw, "claude local scope", miss), miss)
    mcp_json = _load_json(cwd / ".mcp.json")
    if isinstance(mcp_json, dict) and isinstance(mcp_json.get("mcpServers"), dict):
        for label, raw in mcp_json["mcpServers"].items():
            miss = []
            made = endpoint_from_claude(label, raw, "claude project .mcp.json", miss)
            if isinstance(made, Endpoint) and made.kind == "stdio":
                made.cwd = str(cwd)
            take(label, made, miss)
    if isinstance(cj, dict) and isinstance(cj.get("mcpServers"), dict):
        for label, raw in cj["mcpServers"].items():
            miss = []
            take(label, endpoint_from_claude(label, raw, "claude user scope", miss), miss)
    try:
        codex = tomllib.loads((codex_home() / "config.toml").read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        codex = {}
    servers = codex.get("mcp_servers")
    if isinstance(servers, dict):
        for label, raw in servers.items():
            miss = []
            take(label, endpoint_from_codex(label, raw, miss), miss)
    return out


def label_for_url(url: str) -> str:
    """A host-assigned label for an ad-hoc URL: huggingface.co/mcp -> huggingface."""
    host = urllib.parse.urlsplit(url).hostname or "server"
    parts = [p for p in host.split(".") if p not in ("www", "mcp", "api")]
    if len(parts) >= 2:
        parts = parts[:-1]  # drop the TLD
    return slug("-".join(parts) or "server")


def slug(text: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return re.sub(r"-{2,}", "-", s) or "x"
