"""Run tool variants on case versions and record status, log and a manifest."""

from __future__ import annotations

import json
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

ContainerRunner = Callable[[str, list[str], Path, Path, int], ContainerResult]


class Status(StrEnum):
    OK = "ok"
    ERROR = "error"
    TIMEOUT = "timeout"
    UNSUPPORTED = "unsupported"
    UNAVAILABLE = "unavailable"


def run_dir(results: Path, variant: str, case_id: str, version: str) -> Path:
    return results / variant / case_id / version


def read_status(results: Path, variant: str, case_id: str, version: str) -> Status | None:
    """Status of a finished run; None if the run never completed (no meta.json)."""
    meta = run_dir(results, variant, case_id, version) / META
    if not meta.is_file():
        return None
    return Status(json.loads(meta.read_text(encoding="utf-8"))["status"])


def run_one(
    variant: ToolVariant,
    case: Case,
    version: str,
    src: Path | None,
    results: Path,
    runner: ContainerRunner,
    force: bool = False,
) -> Status:
    """Run one variant on one case version; meta.json is written last and marks completion."""
    done = read_status(results, variant.name, case.id, version)
    if done is not None and not force:
        return done
    out = run_dir(results, variant.name, case.id, version)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    started = datetime.now(UTC).isoformat(timespec="seconds")
    exit_code: int | None = None
    duration = 0.0
    if src is None:
        status, log = Status.UNAVAILABLE, "sources unavailable"
    elif not variant.supports(case.language):
        status, log = Status.UNSUPPORTED, f"{variant.name} does not support {case.language}"
    else:
        result = runner(
            variant.image, variant.render_command(case.language), src, out, variant.timeout_s
        )
        exit_code, duration, log = result.exit_code, result.duration_s, result.output
        if exit_code is None:
            status = Status.TIMEOUT
        elif exit_code != 0 or not (out / RAW).is_file():
            status = Status.ERROR
        else:
            status = Status.OK
    (out / "log.txt").write_text(log, encoding="utf-8")
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
    }
    (out / META).write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return status


def write_manifest(results: Path, variants: list[ToolVariant], image_ids: dict[str, str]) -> None:
    results.mkdir(parents=True, exist_ok=True)
    manifest = {
        "created": datetime.now(UTC).isoformat(timespec="seconds"),
        "variants": {
            v.name: {
                "tool": v.tool,
                "version": v.version,
                "image": v.image,
                "image_id": image_ids.get(v.image, ""),
            }
            for v in variants
        },
    }
    (results / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
