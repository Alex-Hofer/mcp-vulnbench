"""Shared fixtures: a local git repository built from examples/toy-server and two toy cases."""

import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
TOY_SERVER = REPO_ROOT / "examples" / "toy-server"

# Backup clients such as Google Drive for desktop mark every folder they back up read-only, and git
# marks its object files read-only; Windows refuses to delete read-only entries (WinError 5).
windows_only = pytest.mark.skipif(sys.platform != "win32", reason="a Windows file attribute")


def is_read_only(path: Path) -> bool:
    return bool(getattr(os.lstat(path), "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_READONLY)


def git(cwd: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)
    return result.stdout.strip()


@pytest.fixture
def toy_repo(tmp_path: Path) -> tuple[str, str, str]:
    """Commit 1 = vulnerable toy server, commit 2 = fixed; returns (url, vulnerable, fixed)."""
    repo = tmp_path / "toy-remote"
    repo.mkdir()
    git(repo, "init", "--quiet", "--initial-branch=main")
    git(repo, "config", "user.name", "Test")
    git(repo, "config", "user.email", "test@example.invalid")
    git(repo, "config", "commit.gpgsign", "false")
    shutil.copyfile(TOY_SERVER / "vulnerable" / "server.py", repo / "server.py")
    git(repo, "add", "server.py")
    git(repo, "commit", "--quiet", "--message", "vulnerable version")
    vulnerable = git(repo, "rev-parse", "HEAD")
    shutil.copyfile(TOY_SERVER / "fixed" / "server.py", repo / "server.py")
    git(repo, "commit", "--quiet", "--all", "--message", "fix both tools")
    fixed = git(repo, "rev-parse", "HEAD")
    return repo.as_uri(), vulnerable, fixed


def toy_case_data(url: str, vulnerable: str, fixed: str) -> list[dict]:
    """Ground truth of the toy server; line numbers refer to examples/toy-server/*/server.py."""
    common = {"repo": url, "license": "MIT", "language": "python", "source": "other"}

    def version(sha: str, function: str, lines: list[int]) -> dict:
        return {
            "commit": sha,
            "locations": [{"file": "server.py", "function": function, "lines": lines}],
        }

    return [
        {
            **common,
            "id": "mcpvb-9001",
            "title": "Toy: command injection in ping",
            "class": "command-injection",
            "cwe": "CWE-78",
            "mcp_tool": "ping",
            "split": "dev",
            "vulnerable": version(vulnerable, "ping", [12, 16]),
            "fixed": version(fixed, "ping", [14, 20]),
        },
        {
            **common,
            "id": "mcpvb-9002",
            "title": "Toy: path traversal in read_note",
            "class": "path-traversal",
            "cwe": "CWE-22",
            "mcp_tool": "read_note",
            "split": "dev",  # one repository, one half
            "vulnerable": version(vulnerable, "read_note", [19, 23]),
            "fixed": version(fixed, "read_note", [23, 29]),
        },
    ]


@pytest.fixture
def toy_cases_dir(tmp_path: Path, toy_repo: tuple[str, str, str]) -> Path:
    cases_dir = tmp_path / "cases"
    for data in toy_case_data(*toy_repo):
        folder = cases_dir / data["id"]
        folder.mkdir(parents=True)
        (folder / "case.yaml").write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return cases_dir
