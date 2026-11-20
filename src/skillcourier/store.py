"""Where imported skills live on disk, what the lockfile pins, and how drift is detected.

An import is an explicit user act that turns a served skill into a filesystem skill. Because the
result is discoverable by the agent, this module does what the spec asks of anything that
materializes served content: the directory and the skill name carry the origin, the description
says where it came from, permission-widening fields are stripped unless granted, and the lockfile
binds the approval to the exact `resources` set (every uri + digest) seen at approval time.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from . import __version__
from .config import claude_config_dir, slug
from .mcp import Endpoint, McpClient
from .spec import NAME_RE, SkillEntry, VerificationError, parse_entry, sha256, verify_bytes, verify_skill_md

LOCK_NAME = ".skillcourier-lock.json"
# Fields that widen what the model may do without asking. The spec: allowed-tools "MUST be
# ignored for MCP-origin skills unless the user has explicitly approved that grant"; declarative
# hooks are host-side execution and "MUST" be ignored or approval-gated.
GRANT_FIELDS = ("allowed-tools", "hooks")
EXEC_SUFFIXES = {
    ".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl", ".php",
    ".ps1", ".bat", ".cmd", ".exe", ".bin", ".so", ".dylib", ".dll", ".jar",
}
MAX_DESCRIPTION = 1024


def resolve_target(spec: str, cwd: Path) -> Path:
    named = {
        "claude": cwd / ".claude" / "skills",
        "claude-user": claude_config_dir() / "skills",
        "agents": cwd / ".agents" / "skills",
        "agents-user": Path.home() / ".agents" / "skills",
    }
    return named.get(spec, Path(spec).expanduser())


def installed_name(label: str, entry: SkillEntry, name_collides: bool) -> str:
    """`<label>-<name>`, or `<label>-<full skill path>` when two entries share a name.

    Valid under the Agent Skills naming rule (lowercase, digits, single hyphens, <= 64 chars), so
    the directory name and the frontmatter name can be the same string.
    """
    tail = "-".join(slug(s) for s in entry.path_segments) if name_collides else slug(entry.name)
    name = slug(f"{label}-{tail}")
    if len(name) > 64:
        h = hashlib.sha256(f"{label}\0{entry.uri}".encode()).hexdigest()[:8]
        name = name[:55].rstrip("-") + "-" + h
    if not NAME_RE.match(name):
        raise VerificationError(f"cannot derive a valid skill name from {label!r} + {entry.uri}")
    return name


@dataclass
class Review:
    """What a user should see before approving an import."""

    stripped: list[str] = field(default_factory=list)
    granted: list[str] = field(default_factory=list)
    exec_files: list[str] = field(default_factory=list)
    nested_skills: list[str] = field(default_factory=list)
    truncated_description: bool = False


def review(entry: SkillEntry, label: str, grant: bool) -> Review:
    r = Review()
    present = [k for k in GRANT_FIELDS if k in entry.frontmatter]
    if grant:
        r.granted = present
    else:
        r.stripped = present
    for f in entry.files or ():
        p = Path(f.relpath)
        if p.suffix.lower() in EXEC_SUFFIXES or (p.parts and p.parts[0] == "scripts"):
            r.exec_files.append(f.relpath)
        if f.relpath != "SKILL.md" and p.name == "SKILL.md":
            r.nested_skills.append(f.relpath)
    r.truncated_description = len(origin_tag(label)) + len(entry.description) > MAX_DESCRIPTION
    return r


def origin_tag(label: str) -> str:
    return f"[MCP skill from server '{label}'] "


def rewrite_skill_md(
    fm: dict[str, Any], body: bytes, installed: str, label: str, entry: SkillEntry, grant: bool
) -> bytes:
    """The materialized SKILL.md: same body bytes, frontmatter re-labelled with its origin."""
    desc = origin_tag(label) + str(fm["description"])
    if len(desc) > MAX_DESCRIPTION:
        desc = desc[: MAX_DESCRIPTION - 1] + "…"
    new: dict[str, Any] = {"name": installed, "description": desc}
    for k, v in fm.items():
        if k in ("name", "description") or (k in GRANT_FIELDS and not grant):
            continue
        new[k] = v
    meta = new.get("metadata")
    meta = dict(meta) if isinstance(meta, dict) else {}
    skill_md = next(f for f in entry.files or () if f.uri == entry.uri)
    meta.update(
        {
            "skillcourier.origin": label,
            "skillcourier.uri": entry.uri,
            "skillcourier.original-name": entry.name,
            "skillcourier.digest": skill_md.digest,
        }
    )
    new["metadata"] = meta
    dumped = yaml.safe_dump(new, sort_keys=False, allow_unicode=True, width=1_000_000)
    return b"---\n" + dumped.encode("utf-8") + b"---\n" + body


def endpoint_record(ep: Endpoint) -> dict[str, Any]:
    """What the lockfile may say about a server. Never header or env values (secrets); never a
    configured stdio command line (its args can carry keys) unless the user typed it ad hoc."""
    rec: dict[str, Any] = {"label": ep.label, "kind": ep.kind, "source": ep.source}
    if ep.kind == "http" and ep.url:
        parts = urllib.parse.urlsplit(ep.url)
        rec["url"] = urllib.parse.urlunsplit(parts._replace(query="", fragment=""))
        if parts.query:
            rec["url_had_query"] = True
    if ep.kind == "stdio" and ep.source in ("command line", "lockfile"):
        rec["command"] = ep.command
        rec["args"] = list(ep.args)
    return rec


def endpoint_from_record(rec: dict[str, Any]) -> Endpoint | None:
    if rec.get("kind") == "http" and isinstance(rec.get("url"), str) and not rec.get("url_had_query"):
        return Endpoint(str(rec["label"]), "http", url=rec["url"], source="lockfile")
    if rec.get("kind") == "stdio" and isinstance(rec.get("command"), str):
        args = [str(a) for a in rec.get("args") or []]
        return Endpoint(str(rec["label"]), "stdio", command=rec["command"], args=args, source="lockfile")
    return None


class Lock:
    def __init__(self, target: Path) -> None:
        self.target = target
        self.path = target / LOCK_NAME
        data: Any = None
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
            except ValueError as e:
                raise VerificationError(f"{self.path} is not valid JSON: {e}") from e
        self.skills: dict[str, dict[str, Any]] = dict(data.get("skills", {})) if isinstance(data, dict) else {}

    def find(self, label: str, uri: str) -> str | None:
        for name, rec in self.skills.items():
            if rec["origin"]["label"] == label and rec["uri"] == uri:
                return name
        return None

    def save(self) -> None:
        self.target.mkdir(parents=True, exist_ok=True)
        doc = {
            "lockfileVersion": 1,
            "generator": f"skillcourier {__version__}",
            "skills": dict(sorted(self.skills.items())),
        }
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, self.path)


def fetch_verified(client: McpClient, entry: SkillEntry) -> tuple[dict[str, Any], bytes, dict[str, bytes]]:
    """Fetch every listed file and verify it; return (frontmatter, SKILL.md body, files)."""
    if entry.files is None:
        raise VerificationError(f"{entry.uri}: resources are \"dynamic\"; no digests to bind an approval to")
    files: dict[str, bytes] = {}
    for f in entry.files:
        data = client.read_resource(f.uri)
        verify_bytes(data, f)
        files[f.relpath] = data
    fm, body = verify_skill_md(files["SKILL.md"], entry)
    return fm, body, files


def _write_file(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)  # never executable
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def materialize(
    target: Path,
    installed: str,
    label: str,
    entry: SkillEntry,
    fm: dict[str, Any],
    body: bytes,
    files: dict[str, bytes],
    grant: bool,
) -> dict[str, str]:
    """Write the skill atomically (temp dir + rename). Returns {relpath: sha256} as written."""
    target.mkdir(parents=True, exist_ok=True)
    final = target / installed
    tmp = target / f".skillcourier-tmp-{installed}-{os.getpid()}"
    shutil.rmtree(tmp, ignore_errors=True)
    written: dict[str, str] = {}
    try:
        for rel, data in files.items():
            out = rewrite_skill_md(fm, body, installed, label, entry, grant) if rel == "SKILL.md" else data
            dest = tmp.joinpath(*rel.split("/"))
            if not dest.resolve().is_relative_to(tmp.resolve()):
                raise VerificationError(f"{rel} escapes the skill directory")
            _write_file(dest, out)
            written[rel] = sha256(out)
        old = target / f".skillcourier-old-{installed}-{os.getpid()}"
        if final.exists():
            os.replace(final, old)
        os.replace(tmp, final)
        shutil.rmtree(old, ignore_errors=True)
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    return written


def lock_record(
    ep: Endpoint, client: McpClient, entry: SkillEntry, written: dict[str, str], rv: Review
) -> dict[str, Any]:
    info = client.info
    return {
        "origin": endpoint_record(ep),
        "uri": entry.uri,
        "name": entry.name,
        "resources": entry.resource_set(),
        "files": written,
        "granted": rv.granted,
        "stripped": rv.stripped,
        "approved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "server": {
            "name": info.name if info else None,
            "version": info.version if info else None,
            "protocol": info.protocol if info else None,
        },
    }


def local_state(target: Path, installed: str, rec: dict[str, Any]) -> tuple[str, list[str]]:
    """'ok', 'missing' or 'modified' (+ which files) for an imported skill on disk.

    Digests are recomputed from the bytes every time: a stored label or mtime is not verification.
    """
    root = target / installed
    if not root.is_dir():
        return "missing", []
    pinned: dict[str, str] = rec.get("files", {})
    problems: list[str] = []
    for rel, digest in pinned.items():
        p = root.joinpath(*rel.split("/"))
        try:
            if sha256(p.read_bytes()) != digest:
                problems.append(f"changed: {rel}")
        except OSError:
            problems.append(f"missing: {rel}")
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.relative_to(root).as_posix() not in pinned:
            problems.append(f"added: {p.relative_to(root).as_posix()}")
    return ("modified" if problems else "ok"), problems


def set_diff(old: list[dict[str, Any]], new: SkillEntry) -> list[str]:
    """Human-readable difference between a pinned resources set and a fresh entry."""
    o = {r["uri"]: r["digest"] for r in old}
    n = {f.uri: f.digest for f in new.files or ()}
    rel = {f.uri: f.relpath for f in new.files or ()}
    out = []
    for uri in sorted(set(o) | set(n)):
        name = rel.get(uri) or uri.rsplit("/", 1)[-1]
        if uri not in n:
            out.append(f"- removed  {uri}")
        elif uri not in o:
            out.append(f"+ added    {name}")
        elif o[uri] != n[uri]:
            out.append(f"~ changed  {name}")
    return out


def entry_from_get(client: McpClient, uri: str) -> SkillEntry:
    return parse_entry(client.get_skill(uri))
