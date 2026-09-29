"""Fetch the vulnerable and the fixed source tree of a case into the cache."""

from __future__ import annotations

import hashlib
import io
import shutil
import subprocess
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from mcpvb.curate import python_functions
from mcpvb.schema import Case, Location

DONE_MARKER = ".mcpvb-fetched"
# Export exactly what is committed: no line-ending conversion and no export-ignore/export-subst
# from the analyzed repository (they would differ between machines or silently drop code).
EXPORT_ATTRIBUTES = "* -text -eol -export-ignore -export-subst"
EXPORT_FORMAT = "2"  # bump when the export rules change, so cached exports are refreshed
TOOL_CONFIG_FILES = frozenset({".bandit", ".semgrepignore"})


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
    (mirror / "info").mkdir(exist_ok=True)
    (mirror / "info" / "attributes").write_text(EXPORT_ATTRIBUTES, encoding="utf-8")
    return mirror


def _regular_files_only(member: tarfile.TarInfo, dest: str) -> tarfile.TarInfo | None:
    """Safe extraction ('data' filter) that also skips links: analyzers only need regular files.

    Links are skipped before the filter runs, which would otherwise reject an absolute or
    out-of-tree link by aborting the whole export. Tool configurations of the analyzed project
    are dropped too: the benchmark measures what a tool finds, not how the project configured it
    (see docs/design.md, tool configuration policy).
    """
    if member.issym() or member.islnk() or PurePosixPath(member.name).name in TOOL_CONFIG_FILES:
        return None
    return tarfile.data_filter(member, dest)


def _export(mirror: Path, commit: str, dest: Path) -> None:
    try:
        _git("cat-file", "-e", f"{commit}^{{commit}}", cwd=mirror)
    except FetchError:
        _git("fetch", "--quiet", "origin", commit, cwd=mirror)
    archive = _git("-c", "core.autocrlf=false", "archive", "--format=tar", commit, cwd=mirror)
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    try:
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(dest, filter=_regular_files_only)
    except (OSError, tarfile.TarError) as exc:
        raise FetchError(f"cannot extract {commit[:12]}: {exc}") from exc
    (dest / DONE_MARKER).write_text(f"{commit} {EXPORT_FORMAT}", encoding="utf-8")


def fetch_case(case: Case, cache: Path) -> CaseSources:
    """Export both commits of `case` (idempotent); raise FetchError if something is unavailable."""
    mirror = _ensure_mirror(case.repo, cache)
    roots: dict[str, Path] = {}
    for name, version in (("vulnerable", case.vulnerable), ("fixed", case.fixed)):
        dest = cache / "cases" / case.id / name
        marker = dest / DONE_MARKER
        if not (
            marker.is_file()
            and marker.read_text(encoding="utf-8") == f"{version.commit} {EXPORT_FORMAT}"
        ):
            _export(mirror, version.commit, dest)
        root = dest / case.subdir if case.subdir else dest
        # The root is mounted into the analyzer container: it must be a folder of this export.
        if not root.resolve().is_relative_to(dest.resolve()) or not root.is_dir():
            raise FetchError(f"subdir {case.subdir!r} not found at {version.commit[:12]}")
        roots[name] = root
    return CaseSources(vulnerable=roots["vulnerable"], fixed=roots["fixed"])


def check_locations(case: Case, sources: CaseSources) -> list[str]:
    """Ground-truth locations that do not exist in the fetched sources (typos in case files)."""
    problems: list[str] = []
    for name, version in (("vulnerable", case.vulnerable), ("fixed", case.fixed)):
        root = sources.for_version(name)
        # Exact names, not path.is_file(): Windows would accept Server.py for server.py, while
        # the SARIF matching is case-sensitive.
        names = {path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()}
        for loc in version.locations:
            path = root / loc.file
            if loc.file not in names:
                problems.append(f"{case.id} {name}: {loc.file} not found at {version.commit[:12]}")
                continue
            n_lines = len(path.read_text(encoding="utf-8", errors="replace").splitlines())
            if loc.lines[1] > n_lines:
                problems.append(
                    f"{case.id} {name}: lines {list(loc.lines)} "
                    f"exceed the {n_lines} lines of {loc.file}"
                )
            elif loc.file.endswith(".py"):
                problems += [f"{case.id} {name}: {p}" for p in _check_python_function(loc, path)]
    return problems


def _check_python_function(loc: Location, path: Path) -> list[str]:
    """The location must cover exactly the named function (first decorator to last line)."""
    try:
        functions = python_functions(path)
    except (SyntaxError, ValueError) as exc:
        return [f"cannot parse {loc.file}: {exc}"]
    matches = [
        (qualified, start, end)
        for qualified, start, end in functions
        if loc.function in (qualified, qualified.rsplit(".", 1)[-1])
    ]
    if not matches:
        return [f"function {loc.function} not found in {loc.file}"]
    if any((start, end) == loc.lines for _, start, end in matches):
        return []
    spans = ", ".join(f"{qualified} spans [{start}, {end}]" for qualified, start, end in matches)
    return [f"lines {list(loc.lines)} do not match the function: {spans}"]
