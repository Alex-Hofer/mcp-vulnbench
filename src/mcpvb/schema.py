"""Case files (cases/<id>/case.yaml): model, loading and cross-case checks."""

from __future__ import annotations

import re
from collections import Counter
from enum import StrEnum
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from mcpvb.classes import CLASS_CWES, VulnClass
from mcpvb.licenses import OSI_APPROVED

MAX_CASES_PER_REPO = 3
_SHA = re.compile(r"[0-9a-f]{40}")
_ADVISORY = re.compile(r"CVE-\d{4}-\d{4,}|GHSA(-[23456789cfghjmpqrvwx]{4}){3}")
_DRIVE = re.compile(r"[A-Za-z]:")


def repo_relative(value: str, field: str) -> str:
    """Normalize a repository-relative path; reject absolute, drive and parent-directory paths."""
    path = value.replace("\\", "/").removeprefix("./").rstrip("/")
    if not path or path.startswith("/") or _DRIVE.match(path) or ".." in path.split("/"):
        raise ValueError(f"{field} must be a relative path inside the repository")
    return path


class CaseError(Exception):
    """One or more case files are invalid; the message lists every problem."""


class Language(StrEnum):
    PYTHON = "python"
    TYPESCRIPT = "typescript"
    JAVASCRIPT = "javascript"


class Source(StrEnum):
    GHSA = "ghsa"
    MCP_BIFLOW = "mcp-biflow"
    VIPER_MCP = "viper-mcp"
    OTHER = "other"


class Split(StrEnum):
    DEV = "dev"
    TEST = "test"


class Location(BaseModel):
    """A function involved in the vulnerability; `file` is relative to `subdir` if set."""

    model_config = ConfigDict(extra="forbid")

    file: str
    function: str
    lines: tuple[int, int]

    @field_validator("file")
    @classmethod
    def _relative_posix(cls, value: str) -> str:
        return repo_relative(value, "file")

    @field_validator("lines")
    @classmethod
    def _ordered(cls, value: tuple[int, int]) -> tuple[int, int]:
        start, end = value
        if not 1 <= start <= end:
            raise ValueError("lines must be [start, end] with 1 <= start <= end")
        return value


class Version(BaseModel):
    model_config = ConfigDict(extra="forbid")

    commit: str
    locations: list[Location] = Field(min_length=1)

    @field_validator("commit")
    @classmethod
    def _full_sha(cls, value: str) -> str:
        if not _SHA.fullmatch(value):
            raise ValueError("commit must be a full 40-character lowercase SHA-1")
        return value


class Case(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    id: str = Field(pattern=r"^mcpvb-\d{4}$")
    title: str = Field(min_length=5)
    advisories: list[str] = Field(default_factory=list)
    repo: str = Field(pattern=r"^(https|file)://\S+$")
    license: str
    language: Language
    subdir: str | None = None
    vuln_class: VulnClass = Field(alias="class")
    cwe: str = Field(pattern=r"^CWE-\d+$")
    mcp_tool: str
    vulnerable: Version
    fixed: Version
    source: Source
    split: Split | None = None
    notes: str = ""

    @field_validator("subdir")
    @classmethod
    def _relative_subdir(cls, value: str | None) -> str | None:
        return None if value is None else repo_relative(value, "subdir")

    @field_validator("advisories")
    @classmethod
    def _advisory_ids(cls, value: list[str]) -> list[str]:
        bad = [advisory for advisory in value if not _ADVISORY.fullmatch(advisory)]
        if bad:
            raise ValueError(f"not a CVE or GHSA id: {bad}")
        return value

    @field_validator("license")
    @classmethod
    def _osi_license(cls, value: str) -> str:
        if value not in OSI_APPROVED:
            raise ValueError(f"license {value!r} is not OSI-approved (see mcpvb/licenses.py)")
        return value

    @model_validator(mode="after")
    def _consistent(self) -> Case:
        allowed = CLASS_CWES[self.vuln_class]
        if self.cwe not in allowed:
            raise ValueError(
                f"cwe {self.cwe} does not belong to class {self.vuln_class} "
                f"(allowed: {sorted(allowed)})"
            )
        if self.source is Source.GHSA and not self.advisories:
            raise ValueError("source 'ghsa' requires at least one advisory id")
        if self.vulnerable.commit == self.fixed.commit:
            raise ValueError("vulnerable and fixed commit must differ")
        return self


def load_case(path: Path) -> Case:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise CaseError(f"{path}: invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise CaseError(f"{path}: expected a mapping at the top level")
    try:
        case = Case.model_validate(data)
    except ValidationError as exc:
        raise CaseError(f"{path}: {exc}") from exc
    if path.parent.name != case.id:
        raise CaseError(f"{path}: folder name {path.parent.name!r} must equal id {case.id!r}")
    return case


def repo_key(url: str) -> str:
    return url.lower().rstrip("/").removesuffix(".git")


def load_cases(cases_dir: Path, ids: list[str] | None = None) -> list[Case]:
    """Load all cases (or only `ids`); raise CaseError that lists every problem."""
    if not cases_dir.is_dir():
        raise CaseError(f"{cases_dir} is not a directory")
    errors: list[str] = []
    cases: list[Case] = []
    folders = [p for p in cases_dir.iterdir() if p.is_dir() and not p.name.startswith(".")]
    for folder in sorted(folders):
        path = folder / "case.yaml"
        if not path.is_file():
            found = ", ".join(sorted(p.name for p in folder.iterdir())) or "nothing"
            errors.append(f"{folder}: the case file must be named case.yaml (found: {found})")
            continue
        try:
            cases.append(load_case(path))
        except CaseError as exc:
            errors.append(str(exc))
    per_repo = Counter(repo_key(case.repo) for case in cases)
    errors += [
        f"{repo} has {count} cases (max {MAX_CASES_PER_REPO})"
        for repo, count in per_repo.items()
        if count > MAX_CASES_PER_REPO
    ]
    if ids:
        errors += [f"unknown case id {i}" for i in sorted(set(ids) - {case.id for case in cases})]
        cases = [case for case in cases if case.id in ids]
    if errors:
        raise CaseError("\n".join(errors))
    return cases
