"""Run tool variants on case versions and record status, log and a manifest."""

from __future__ import annotations

import json
import os
import shutil
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from mcpvb.docker import ContainerResult
from mcpvb.schema import Case
from mcpvb.tools import ToolVariant

VERSIONS = ("vulnerable", "fixed")
META = "meta.json"
RAW = "raw.sarif"
TOOL_DIR = "tool"  # the only folder the analyzer container may write to
# docker run itself failed (125) or the command could not be executed (126) or found (127)
INFRASTRUCTURE_EXIT_CODES = frozenset({125, 126, 127})

ContainerRunner = Callable[[str, list[str], Path, Path, int], ContainerResult]


class InfrastructureError(Exception):
    """Docker could not run the analyzer at all; nothing is recorded, so the run is repeated."""


class Status(StrEnum):
    OK = "ok"
    ERROR = "error"
    TIMEOUT = "timeout"
    UNSUPPORTED = "unsupported"
    UNAVAILABLE = "unavailable"


def run_dir(results: Path, variant: str, case_id: str, version: str) -> Path:
    return results / variant / case_id / version


def raw_path(results: Path, variant: str, case_id: str, version: str) -> Path:
    return run_dir(results, variant, case_id, version) / TOOL_DIR / RAW


def read_meta(results: Path, variant: str, case_id: str, version: str) -> dict | None:
    """meta.json of a finished run; None if the run never completed or its meta.json is broken."""
    meta = run_dir(results, variant, case_id, version) / META
    if not meta.is_file():
        return None
    try:
        data = json.loads(meta.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    return data if isinstance(data, dict) and data.get("status") in set(Status) else None


def _write_atomically(path: Path, text: str) -> None:
    """Write via a temporary file and a rename, so an interrupted write never leaves half a file."""
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(text, encoding="utf-8", newline="\n")
    os.replace(temporary, path)


def read_status(results: Path, variant: str, case_id: str, version: str) -> Status | None:
    """Status of a finished run; None if the run never completed (no meta.json)."""
    meta = read_meta(results, variant, case_id, version)
    return None if meta is None else Status(meta["status"])


def fingerprint(variant: ToolVariant, case: Case, version: str, image_id: str) -> dict:
    """Everything that decides a run's result; a finished run is reused only if it matches."""
    commit = (case.vulnerable if version == "vulnerable" else case.fixed).commit
    supported = variant.supports(case.language)
    return {
        "commit": commit,
        "subdir": case.subdir,
        "image_id": image_id,
        "command": variant.render_command(case.language) if supported else None,
        "languages": [language.value for language in variant.languages],
    }


def matches(recorded: dict | None, expected: dict) -> bool:
    """A recorded fingerprint matches if every entry agrees; an unknown image id is not compared."""
    if not isinstance(recorded, dict):
        return False
    return all(
        recorded.get(key) == value for key, value in expected.items() if key != "image_id" or value
    )


def manifest_image_ids(results: Path) -> dict[str, str]:
    """Image id per variant as recorded by the last run; empty without a readable manifest."""
    try:
        entries = json.loads((results / "manifest.json").read_text(encoding="utf-8"))["variants"]
        return {name: str(entry.get("image_id", "")) for name, entry in entries.items()}
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return {}


def run_one(
    variant: ToolVariant,
    case: Case,
    version: str,
    src: Path | None,
    results: Path,
    runner: ContainerRunner,
    force: bool = False,
    image_id: str = "",
) -> Status:
    """Run one variant on one case version; meta.json is written last and marks completion.

    A finished run is reused only if its fingerprint (commit, subdir, image, command, languages)
    still matches, so an edited case or a rebuilt image never yields stale results.
    """
    expected = fingerprint(variant, case, version, image_id)
    done = read_meta(results, variant.name, case.id, version)
    if done is not None and done.get("fingerprint") == expected and not force:
        return Status(done["status"])
    if src is None and variant.supports(case.language):
        return Status.UNAVAILABLE  # not recorded: the next run retries once the sources are back
    out = run_dir(results, variant.name, case.id, version)
    if out.exists():
        shutil.rmtree(out)
    # The container writes only into out/tool; the harness writes only into out. A compromised
    # analyzer can therefore not redirect harness writes through symlinks.
    tool_out = out / TOOL_DIR
    tool_out.mkdir(parents=True)
    started = datetime.now(UTC).isoformat(timespec="seconds")
    exit_code: int | None = None
    duration = 0.0
    if not variant.supports(case.language):
        status, log = Status.UNSUPPORTED, f"{variant.name} does not support {case.language}"
    else:
        result = runner(
            variant.image, variant.render_command(case.language), src, tool_out, variant.timeout_s
        )
        if result.exit_code in INFRASTRUCTURE_EXIT_CODES:
            detail = result.output.strip()[-300:]
            raise InfrastructureError(
                f"{variant.name} {case.id} {version}: docker exit code {result.exit_code}: {detail}"
            )
        exit_code, duration, log = result.exit_code, result.duration_s, result.output
        raw = tool_out / RAW
        if exit_code is None:
            status = Status.TIMEOUT
        elif exit_code != 0 or not raw.is_file() or raw.is_symlink():
            status = Status.ERROR
        else:
            status = Status.OK
    (out / "log.txt").write_text(log, encoding="utf-8", newline="\n")
    meta = {
        "variant": variant.name,
        "tool": variant.tool,
        "tool_version": variant.version,
        "image": variant.image,
        "case": case.id,
        "version": version,
        "status": status.value,
        "exit_code": exit_code,
        "duration_s": round(duration, 3),
        "started": started,
        "fingerprint": expected,
    }
    _write_atomically(out / META, json.dumps(meta, indent=2))
    return status


def write_manifest(results: Path, variants: list[ToolVariant], image_ids: dict[str, str]) -> None:
    """Record the variants of this run; entries of variants run earlier are kept."""
    results.mkdir(parents=True, exist_ok=True)
    path = results / "manifest.json"
    manifest = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    manifest["updated"] = datetime.now(UTC).isoformat(timespec="seconds")
    entries = manifest.setdefault("variants", {})
    for v in variants:
        entries[v.name] = {
            "tool": v.tool,
            "version": v.version,
            "image": v.image,
            "image_id": image_ids.get(v.image, ""),
        }
    _write_atomically(path, json.dumps(manifest, indent=2))
