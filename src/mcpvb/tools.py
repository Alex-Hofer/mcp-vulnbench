"""Tool variants (tools/<name>/tool.yaml): one analyzer configuration run in Docker."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from mcpvb.classes import normalize_cwe
from mcpvb.schema import Language


class ToolError(Exception):
    """A tool variant definition is invalid or unknown."""


class ToolVariant(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    tool: str
    version: str
    image: str
    base_image: str | None = None  # image of another variant this one builds on
    dockerfile: str
    languages: list[Language] = Field(min_length=1)
    command: list[str] = Field(min_length=1)
    timeout_s: int = Field(default=1800, gt=0)
    cwe_overrides: dict[str, str] = Field(default_factory=dict)

    @field_validator("cwe_overrides")
    @classmethod
    def _normalized(cls, value: dict[str, str]) -> dict[str, str]:
        normalized = {rule: normalize_cwe(cwe) for rule, cwe in value.items()}
        bad = sorted(rule for rule, cwe in normalized.items() if cwe is None)
        if bad:
            raise ValueError(f"not a CWE for rule(s) {bad}")
        return {rule: cwe for rule, cwe in normalized.items() if cwe is not None}

    def supports(self, language: Language) -> bool:
        return language in self.languages

    def render_command(self, language: Language) -> list[str]:
        """Fill {src}, {out} and {lang} (CodeQL language name) into the command."""
        lang = "python" if language is Language.PYTHON else "javascript"
        return [part.format(src="/src", out="/out", lang=lang) for part in self.command]


def load_variant(path: Path) -> ToolVariant:
    try:
        variant = ToolVariant.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
    except UnicodeDecodeError as exc:
        raise ToolError(f"{path}: not UTF-8 ({exc}); save the file as UTF-8") from exc
    except (yaml.YAMLError, ValidationError) as exc:
        raise ToolError(f"{path}: {exc}") from exc
    if path.parent.name != variant.name:
        folder = path.parent.name
        raise ToolError(f"{path}: folder name {folder!r} must equal name {variant.name!r}")
    return variant


def load_variants(tools_dir: Path, names: list[str] | None = None) -> list[ToolVariant]:
    variants = [load_variant(path) for path in sorted(tools_dir.glob("*/tool.yaml"))]
    if not variants:
        raise ToolError(f"no tool variants found in {tools_dir} (expected <variant>/tool.yaml)")
    if names:
        unknown = sorted(set(names) - {variant.name for variant in variants})
        if unknown:
            available = [variant.name for variant in variants]
            raise ToolError(f"unknown tool variant(s) {unknown}; available: {available}")
        variants = [variant for variant in variants if variant.name in names]
    return variants
