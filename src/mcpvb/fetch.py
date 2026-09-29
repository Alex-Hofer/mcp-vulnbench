"""Fetch the vulnerable and the fixed source tree of a case into the cache."""

from __future__ import annotations

import hashlib
import io
import shutil
import subprocess
import tarfile
from dataclasses import dataclass
from pathlib import Path

from mcpvb.schema import Case

DONE_MARKER = ".mcpvb-fetched"


class FetchError(Exception):
    """The sources of a case could not be obtained."""


@dataclass(frozen=True)
class CaseSources:
    vulnerable: Path
    fixed: Path

    def for_version(self, version: str) -> Path:
        return self.vulnerable if version == "vulnerable" else self.fixed


def _git(*args: str, cwd: Path | None = None) -> bytes:
    result = subprocess.run(["git", *args], cwd=cwd, capture_output=True)
    if result.returncode != 0:
        detail = result.stderr.decode(errors="replace").strip()
        raise FetchError(f"git {' '.join(args)} failed: {detail}")
    return result.stdout


def _mirror_dir(cache: Path, url: str) -> Path:
    key = url.lower().rstrip("/").removesuffix(".git")
    return cache / "repos" / hashlib.sha256(key.encode()).hexdigest()[:16]


def _ensure_mirror(url: str, cache: Path) -> Path:
    mirror = _mirror_dir(cache, url)
    if not (mirror / "HEAD").is_file():
        if mirror.exists():
            shutil.rmtree(mirror)
        mirror.parent.mkdir(parents=True, exist_ok=True)
        _git("clone", "--bare", "--quiet", url, str(mirror))
    return mirror


def _regular_files_only(member: tarfile.TarInfo, dest: str) -> tarfile.TarInfo | None:
    """Safe extraction ('data' filter) that also skips links: analyzers only need regular files."""
    member = tarfile.data_filter(member, dest)
    return None if member.issym() or member.islnk() else member


def _export(mirror: Path, commit: str, dest: Path) -> None:
    try:
        _git("cat-file", "-e", f"{commit}^{{commit}}", cwd=mirror)
    except FetchError:
        _git("fetch", "--quiet", "origin", commit, cwd=mirror)
    archive = _git("archive", "--format=tar", commit, cwd=mirror)
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    try:
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(dest, filter=_regular_files_only)
    except (OSError, tarfile.TarError) as exc:
        raise FetchError(f"cannot extract {commit[:12]}: {exc}") from exc
    (dest / DONE_MARKER).write_text(commit, encoding="utf-8")


def fetch_case(case: Case, cache: Path) -> CaseSources:
    """Export both commits of `case` (idempotent); raise FetchError if something is unavailable."""
    mirror = _ensure_mirror(case.repo, cache)
    roots: dict[str, Path] = {}
    for name, version in (("vulnerable", case.vulnerable), ("fixed", case.fixed)):
        dest = cache / "cases" / case.id / name
        marker = dest / DONE_MARKER
        if not (marker.is_file() and marker.read_text(encoding="utf-8") == version.commit):
            _export(mirror, version.commit, dest)
        roots[name] = dest / case.subdir if case.subdir else dest
    return CaseSources(vulnerable=roots["vulnerable"], fixed=roots["fixed"])


def check_locations(case: Case, sources: CaseSources) -> list[str]:
    """Ground-truth locations that do not exist in the fetched sources (typos in case files)."""
    problems: list[str] = []
    for name, version in (("vulnerable", case.vulnerable), ("fixed", case.fixed)):
        root = sources.for_version(name)
        for loc in version.locations:
            path = root / loc.file
            if not path.is_file():
                problems.append(f"{case.id} {name}: {loc.file} not found at {version.commit[:12]}")
                continue
            n_lines = len(path.read_text(encoding="utf-8", errors="replace").splitlines())
            if loc.lines[1] > n_lines:
                problems.append(
                    f"{case.id} {name}: lines {list(loc.lines)} "
                    f"exceed the {n_lines} lines of {loc.file}"
                )
    return problems
