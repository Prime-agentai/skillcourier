from __future__ import annotations

from typing import Any

import pytest

from skillcourier.mcp import header_value, parse_sse
from skillcourier.spec import (
    VerificationError,
    frontmatter_diff,
    parse_entry,
    safe_relpath,
    sha256,
    split_frontmatter,
    verify_bytes,
    verify_skill_md,
)

MD = b"---\nname: refunds\ndescription: Do refunds.\n---\n# Body\n"


def entry(**over: Any) -> dict[str, Any]:
    e: dict[str, Any] = {
        "uri": "skill://acme/billing/refunds/SKILL.md",
        "frontmatter": {"name": "refunds", "description": "Do refunds."},
        "resources": [
            {"uri": "skill://acme/billing/refunds/SKILL.md", "digest": sha256(MD), "size": len(MD)},
            {"uri": "skill://acme/billing/refunds/examples/email.md", "digest": sha256(b"hi"), "size": 2},
        ],
    }
    e.update(over)
    return e


def with_file(uri: str) -> dict[str, Any]:
    e = entry()
    e["resources"].append({"uri": uri, "digest": sha256(b""), "size": 0})
    return e


def test_valid_entry_parses() -> None:
    e = parse_entry(entry())
    assert e.name == "refunds" and e.path_segments == ("acme", "billing", "refunds")
    assert [f.relpath for f in e.files or ()] == ["SKILL.md", "examples/email.md"]
    assert e.total_size == len(MD) + 2


def test_spec_example_listing_entries_parse() -> None:
    # The first two entries of the spec's own skills/list response example.
    parse_entry(
        {
            "uri": "skill://git-workflow/SKILL.md",
            "frontmatter": {"name": "git-workflow", "description": "Follow this team's Git conventions"},
            "resources": [
                {
                    "uri": "skill://git-workflow/SKILL.md",
                    "digest": "sha256:b95a384300adeea2d902f7d19cd7c04b378ef58e09759107b9c7db4dcacbaa25",
                    "size": 190,
                }
            ],
        }
    )
    assert parse_entry(entry(resources="dynamic")).dynamic


@pytest.mark.parametrize(
    "bad",
    [
        "skill://acme/billing/refunds/../../../etc/passwd",
        "skill://acme/billing/refunds/%2e%2e/x",
        "skill://acme/billing/refunds/a//b",
        "skill://acme/billing/refunds/a\\..\\b",
        "skill://acme/billing/refunds/C:/x",
        "skill://acme/billing/refunds/x%00y",
        "skill://acme/billing/other/x.md",
        "skill://acme/billing/refundsX/x.md",
        "skill://acme/billing/refunds/x?y=1",
    ],
)
def test_unsafe_or_foreign_file_uris_reject_the_entry(bad: str) -> None:
    with pytest.raises(VerificationError):
        parse_entry(with_file(bad))


def test_percent_encoded_names_decode_to_safe_paths() -> None:
    assert safe_relpath("skill://s/refs/r%C3%A9f.md", "skill://s") == "refs/réf.md"


@pytest.mark.parametrize(
    "over",
    [
        {"resources": None},
        {"resources": "static"},
        {"frontmatter": {"name": "refunds"}},
        {"frontmatter": {"name": "other", "description": "x"}},
        {"uri": "skill://acme/billing/refunds/README.md"},
        {"uri": "acme/billing/refunds/SKILL.md"},
    ],
)
def test_malformed_entries_are_refused(over: dict[str, Any]) -> None:
    raw = entry(**over)
    if "resources" not in over:
        raw["resources"] = "dynamic"
    with pytest.raises(VerificationError):
        parse_entry(raw)


def test_manifest_must_list_skill_md_and_each_file_once() -> None:
    e = entry()
    e["resources"] = e["resources"][1:]
    with pytest.raises(VerificationError, match="does not list SKILL.md"):
        parse_entry(e)
    e = entry()
    e["resources"].append(dict(e["resources"][1]))
    with pytest.raises(VerificationError, match="listed twice"):
        parse_entry(e)


def test_case_insensitive_collision_is_refused() -> None:
    with pytest.raises(VerificationError, match="case-insensitively"):
        parse_entry(with_file("skill://acme/billing/refunds/EXAMPLES/email.md"))


@pytest.mark.parametrize(
    "res",
    [
        {"digest": "sha256:ABC", "size": 1},
        {"digest": "md5:" + "0" * 32, "size": 1},
        {"digest": sha256(b"x"), "size": -1},
        {"digest": sha256(b"x"), "size": True},
        {"digest": sha256(b"x"), "size": "1"},
    ],
)
def test_bad_digest_or_size_fields(res: dict[str, Any]) -> None:
    e = entry()
    e["resources"][1].update(res)
    with pytest.raises(VerificationError):
        parse_entry(e)


def test_limits_are_checked_from_the_entry_alone() -> None:
    e = entry()
    e["resources"] += [
        {"uri": f"skill://acme/billing/refunds/f{i}", "digest": sha256(b""), "size": 0} for i in range(511)
    ]
    with pytest.raises(VerificationError, match="512"):
        parse_entry(e)
    e = entry()
    e["resources"][1]["size"] = 16 * 1024 * 1024
    with pytest.raises(VerificationError, match="16 MiB"):
        parse_entry(e)


def test_verify_bytes_size_then_digest() -> None:
    f = parse_entry(entry()).files[1]  # type: ignore[index]
    verify_bytes(b"hi", f)
    with pytest.raises(VerificationError, match="bytes"):
        verify_bytes(b"hi!", f)
    with pytest.raises(VerificationError, match="digest"):
        verify_bytes(b"ho", f)


def test_skill_md_frontmatter_must_match_entry_field_by_field() -> None:
    e = parse_entry(entry())
    fm, body = verify_skill_md(MD, e)
    assert fm == {"name": "refunds", "description": "Do refunds."} and body == b"# Body\n"
    lying = MD.replace(b"Do refunds.", b"Do evil.!!!")  # same length, different text
    raw = entry()
    raw["resources"][0]["digest"] = sha256(lying)
    with pytest.raises(VerificationError, match="frontmatter differs"):
        verify_skill_md(lying, parse_entry(raw))


def test_yaml_dates_and_numbers_compare_like_the_json_rendering() -> None:
    fm, _ = split_frontmatter(b"---\nname: a\ndescription: b\nupdated: 2026-11-01\nv: 1\n---\n")
    assert fm["updated"] == "2026-11-01"
    assert frontmatter_diff({"name": "a", "description": "b", "updated": "2026-11-01", "v": 1.0}, fm) == []
    assert frontmatter_diff({"x": True}, {"x": 1}) != []
    assert frontmatter_diff({"x": [1, 2]}, {"x": [1, 2, 3]}) != []
    assert frontmatter_diff({"a": 1}, {"b": 1}) == ["a: in entry, missing from SKILL.md", "b: in SKILL.md, missing from entry"]


@pytest.mark.parametrize(
    "data",
    [b"# no frontmatter\n", b"---\nname: [unclosed\n---\n", b"---\n- a list\n---\n", b"---\nname: a\n"],
)
def test_frontmatter_parse_failures(data: bytes) -> None:
    with pytest.raises(VerificationError):
        split_frontmatter(data)


def test_crlf_and_bom_frontmatter() -> None:
    fm, body = split_frontmatter(b"\xef\xbb\xbf---\r\nname: a\r\ndescription: b\r\n---\r\nbody")
    assert fm == {"name": "a", "description": "b"} and body == b"body"


@pytest.mark.parametrize(
    ("value", "encoded"),
    [
        ("us-west1", "us-west1"),
        ("Hello, 世界", "=?base64?SGVsbG8sIOS4lueVjA==?="),
        (" padded", "=?base64?IHBhZGRlZA==?="),
        ("=?base64?abc?=", "=?base64?PT9iYXNlNjQ/YWJjPz0=?="),
        ("line\nbreak", "=?base64?bGluZQpicmVhaw==?="),
    ],
)
def test_header_value_encoding_matches_the_spec_table(value: str, encoded: str) -> None:
    assert header_value(value) == encoded


def test_sse_skips_notifications_and_finds_the_response() -> None:
    raw = (
        'event: message\ndata: {"jsonrpc":"2.0","method":"notifications/progress","params":{}}\n\n'
        'data: {"jsonrpc":"2.0","id":7,\ndata: "result":{"ok":true}}\n\n'
    )
    assert parse_sse(raw, 7) == {"jsonrpc": "2.0", "id": 7, "result": {"ok": True}}
    assert parse_sse(raw, 8) is None
