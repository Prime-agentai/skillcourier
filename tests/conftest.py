from __future__ import annotations

import shutil
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from skillcourier.cli import main
from skillcourier.devserver import SkillDirServer, serve_http_background

EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "skills"


@pytest.fixture(autouse=True)
def isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """No test may read or write the real ~/.claude, ~/.claude.json or ~/.codex."""
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "home" / ".claude"))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "home" / ".codex"))


@pytest.fixture
def skills_dir(tmp_path: Path) -> Path:
    d = tmp_path / "served"
    shutil.copytree(EXAMPLES, d)
    return d


@dataclass
class Served:
    server: SkillDirServer
    url: str


@pytest.fixture
def served(skills_dir: Path) -> Iterator[Served]:
    server = SkillDirServer(skills_dir)
    httpd, url = serve_http_background(server)
    yield Served(server, url)
    httpd.shutdown()
    httpd.server_close()


@pytest.fixture
def project(tmp_path: Path) -> Path:
    p = tmp_path / "project"
    p.mkdir()
    return p


@dataclass
class Result:
    rc: int
    out: str
    err: str


@pytest.fixture
def run(project: Path, capsys: pytest.CaptureFixture[str]):  # type: ignore[no-untyped-def]
    def _run(*argv: str) -> Result:
        capsys.readouterr()
        rc = main([*argv, "--cwd", str(project), "--timeout", "10"] if argv[0] != "dev-server" else list(argv))
        cap = capsys.readouterr()
        return Result(rc, cap.out, cap.err)

    return _run
