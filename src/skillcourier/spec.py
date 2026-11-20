"""The SEP-2640 rules a host must enforce before it lets served skill content anywhere near a model.

Every function here is pure: entries and bytes in, a verdict out. Section names in the error
messages match `specification/beta/skills.mdx` in modelcontextprotocol/ext-skills.
"""

from __future__ import annotations

import hashlib
import re
import urllib.parse
from dataclasses import dataclass
from typing import Any

import yaml

MAX_RESOURCES = 512
MAX_TOTAL_BYTES = 16 * 1024 * 1024
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
NAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9]|-(?!-))*$")  # Agent Skills naming rule, max 64 chars


class VerificationError(Exception):
    """Content or entry that the spec says a host MUST NOT use."""


@dataclass(frozen=True)
class SkillFile:
    uri: str
    digest: str
    size: int
    relpath: str  # path inside the skill directory, '/'-separated, already proven safe


@dataclass(frozen=True)
class SkillEntry:
    uri: str
    root: str  # the skill directory URI (uri minus "/SKILL.md")
    name: str
    description: str
    frontmatter: dict[str, Any]
    files: tuple[SkillFile, ...] | None  # None means resources == "dynamic"
    path_segments: tuple[str, ...]  # skill path, e.g. ("acme", "billing", "refunds")

    @property
    def dynamic(self) -> bool:
        return self.files is None

    @property
    def total_size(self) -> int:
        return sum(f.size for f in self.files or ())

    def resource_set(self) -> list[dict[str, Any]]:
        """The approval-binding set: every uri, digest and size, in a stable order."""
        return [{"uri": f.uri, "digest": f.digest, "size": f.size} for f in self.files or ()]


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def safe_relpath(uri: str, root: str) -> str:
    """The path of ``uri`` inside the skill rooted at ``root``, or raise.

    "Each uri MUST be the skill's SKILL.md or a file within the skill's directory." This is also
    the line between a manifest entry and a write outside the target directory, so it is strict:
    no empty, '.', '..' or encoded-traversal segments, no backslashes, drive letters or NULs.
    """
    prefix = root + "/"
    if not uri.startswith(prefix):
        raise VerificationError(f"{uri} is not inside the skill directory {root}")
    rest = uri[len(prefix):]
    if "?" in rest or "#" in rest:
        raise VerificationError(f"{uri}: query or fragment in a skill file URI")
    segments = [urllib.parse.unquote(s) for s in rest.split("/")]
    for seg in segments:
        bad = (
            seg in ("", ".", "..")
            or "/" in seg
            or "\\" in seg
            or "\x00" in seg
            or ":" in seg
            or any(ord(c) < 0x20 for c in seg)
        )
        if bad:
            raise VerificationError(f"{uri}: unsafe path segment {seg!r}")
    return "/".join(segments)


def _skill_path(uri: str) -> tuple[str, tuple[str, ...]]:
    if not uri.endswith("/SKILL.md"):
        raise VerificationError(f"skill uri {uri!r} does not name a SKILL.md")
    root = uri[: -len("/SKILL.md")]
    parts = urllib.parse.urlsplit(root)
    if not parts.scheme:
        raise VerificationError(f"skill uri {uri!r} has no scheme")
    segs = [s for s in ([parts.netloc] + parts.path.split("/")) if s]
    if not segs:
        raise VerificationError(f"skill uri {uri!r} has an empty skill path")
    return root, tuple(urllib.parse.unquote(s) for s in segs)


def parse_entry(raw: Any) -> SkillEntry:
    """Validate one entry from skills/list or skills/get ("Skill Entries")."""
    if not isinstance(raw, dict):
        raise VerificationError("skill entry is not an object")
    uri = raw.get("uri")
    if not isinstance(uri, str):
        raise VerificationError("skill entry has no string `uri`")
    root, segs = _skill_path(uri)
    fm = raw.get("frontmatter")
    if not isinstance(fm, dict):
        raise VerificationError(f"{uri}: entry has no `frontmatter` object")
    name, desc = fm.get("name"), fm.get("description")
    if not isinstance(name, str) or not isinstance(desc, str):
        raise VerificationError(f"{uri}: frontmatter lacks string `name`/`description`")
    if segs[-1] != name:
        raise VerificationError(
            f"{uri}: final path segment {segs[-1]!r} != frontmatter name {name!r} (Resource Mapping)"
        )
    res = raw.get("resources")
    if res == "dynamic":
        return SkillEntry(uri, root, name, desc, fm, None, segs)
    if not isinstance(res, list):
        raise VerificationError(f"{uri}: `resources` must be an array or \"dynamic\"; MUST NOT load")
    if len(res) > MAX_RESOURCES:
        raise VerificationError(f"{uri}: {len(res)} files exceeds the {MAX_RESOURCES}-entry limit")
    files: list[SkillFile] = []
    seen: set[str] = set()
    seen_fold: set[str] = set()
    for r in res:
        if not isinstance(r, dict):
            raise VerificationError(f"{uri}: resource entry is not an object")
        ruri, digest, size = r.get("uri"), r.get("digest"), r.get("size")
        if not isinstance(ruri, str) or not isinstance(digest, str):
            raise VerificationError(f"{uri}: resource entry lacks `uri`/`digest`")
        if not DIGEST_RE.match(digest):
            raise VerificationError(f"{ruri}: digest {digest!r} is not sha256:<64 lowercase hex>")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise VerificationError(f"{ruri}: `size` must be a non-negative integer")
        if ruri in seen:
            raise VerificationError(f"{ruri}: listed twice (each file exactly once)")
        rel = safe_relpath(ruri, root)
        # Two names that collapse to one file on a case-insensitive filesystem would let the
        # second silently replace the first after verification.
        if rel.casefold() in seen_fold:
            raise VerificationError(f"{ruri}: collides case-insensitively with another file")
        seen.add(ruri)
        seen_fold.add(rel.casefold())
        files.append(SkillFile(ruri, digest, size, rel))
    if uri not in seen:
        raise VerificationError(f"{uri}: `resources` does not list SKILL.md itself (incomplete)")
    total = sum(f.size for f in files)
    if total > MAX_TOTAL_BYTES:
        raise VerificationError(f"{uri}: {total} bytes exceeds the 16 MiB per-skill limit")
    files.sort(key=lambda f: (f.relpath != "SKILL.md", f.relpath))
    return SkillEntry(uri, root, name, desc, fm, tuple(files), segs)


def verify_bytes(data: bytes, f: SkillFile) -> None:
    """Verification on Read: size first (cheap), then digest."""
    if len(data) != f.size:
        raise VerificationError(f"{f.uri}: got {len(data)} bytes, entry says {f.size}")
    got = sha256(data)
    if got != f.digest:
        raise VerificationError(f"{f.uri}: digest {got} != entry {f.digest}")


class _NoDatesLoader(yaml.SafeLoader):
    """SafeLoader without the timestamp resolver, so `date: 2026-01-01` stays the string the
    server's JSON rendering of the same frontmatter carries."""


_NoDatesLoader.yaml_implicit_resolvers = {
    k: [(tag, rx) for tag, rx in v if tag != "tag:yaml.org,2002:timestamp"]
    for k, v in yaml.SafeLoader.yaml_implicit_resolvers.items()
}

_FM_RE = re.compile(rb"\A(?:\xef\xbb\xbf)?---[ \t]*\r?\n(.*?)^---[ \t]*(?:\r?\n|\Z)", re.S | re.M)


def split_frontmatter(data: bytes) -> tuple[dict[str, Any], bytes]:
    """Parse SKILL.md into (frontmatter, body bytes). Body bytes are returned untouched."""
    m = _FM_RE.match(data)
    if not m:
        raise VerificationError("SKILL.md does not begin with a YAML frontmatter block")
    try:
        fm = yaml.load(m.group(1).decode("utf-8"), Loader=_NoDatesLoader)
    except (yaml.YAMLError, UnicodeDecodeError) as e:
        raise VerificationError(f"SKILL.md frontmatter is not valid YAML: {e}") from e
    if not isinstance(fm, dict):
        raise VerificationError("SKILL.md frontmatter is not a mapping")
    return fm, data[m.end():]


def frontmatter_diff(entry_fm: dict[str, Any], file_fm: dict[str, Any]) -> list[str]:
    """Field-by-field comparison ("Frontmatter Verification"). Empty list means identical."""
    out = []
    for key in sorted(set(entry_fm) | set(file_fm), key=str):
        if key not in file_fm:
            out.append(f"{key}: in entry, missing from SKILL.md")
        elif key not in entry_fm:
            out.append(f"{key}: in SKILL.md, missing from entry")
        elif not _same(entry_fm[key], file_fm[key]):
            out.append(f"{key}: entry {entry_fm[key]!r} != SKILL.md {file_fm[key]!r}")
    return out


def _same(a: Any, b: Any) -> bool:
    # JSON has no int/float distinction worth failing on (1 vs 1.0); everything else is exact.
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_same(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_same(x, y) for x, y in zip(a, b))
    return type(a) is type(b) and bool(a == b)


def verify_skill_md(data: bytes, entry: SkillEntry) -> tuple[dict[str, Any], bytes]:
    """Digest + frontmatter verification of a fetched SKILL.md against its entry."""
    if entry.files is not None:
        verify_bytes(data, next(f for f in entry.files if f.uri == entry.uri))
    fm, body = split_frontmatter(data)
    diff = frontmatter_diff(entry.frontmatter, fm)
    if diff:
        raise VerificationError(f"{entry.uri}: frontmatter differs from entry: " + "; ".join(diff))
    return fm, body
