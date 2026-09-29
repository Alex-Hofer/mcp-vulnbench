from pathlib import Path

import pytest

from mcpvb.schema import Language
from mcpvb.tools import ToolError, load_variant, load_variants

REPO_ROOT = Path(__file__).resolve().parents[1]
TOOLS = REPO_ROOT / "tools"


def test_repository_variants_load():
    variants = {variant.name: variant for variant in load_variants(TOOLS)}
    assert set(variants) == {"semgrep-default", "semgrep-mcp", "codeql", "bandit"}
    assert variants["bandit"].cwe_overrides["B307"] == "CWE-95"
    assert variants["semgrep-default"].image == variants["semgrep-mcp"].image


def test_render_command_fills_placeholders():
    codeql = load_variant(TOOLS / "codeql" / "tool.yaml")
    assert codeql.render_command(Language.TYPESCRIPT) == [
        "run-codeql.sh",
        "javascript",
        "/src",
        "/out",
    ]
    bandit = load_variant(TOOLS / "bandit" / "tool.yaml")
    assert "/out/raw.sarif" in bandit.render_command(Language.PYTHON)
    assert not bandit.supports(Language.TYPESCRIPT)


def test_unknown_variant_is_rejected():
    with pytest.raises(ToolError, match="unknown tool variant"):
        load_variants(TOOLS, ["semgrep-pro"])


def test_folder_must_match_name(tmp_path):
    folder = tmp_path / "wrong"
    folder.mkdir()
    (folder / "tool.yaml").write_text(
        (TOOLS / "bandit" / "tool.yaml").read_text(encoding="utf-8"), encoding="utf-8"
    )
    with pytest.raises(ToolError, match="folder name"):
        load_variant(folder / "tool.yaml")


def test_bad_cwe_override_is_rejected(tmp_path):
    folder = tmp_path / "x"
    folder.mkdir()
    (folder / "tool.yaml").write_text(
        "name: x\ntool: x\nversion: '1'\nimage: x\ndockerfile: docker/x\n"
        "languages: [python]\ncommand: [x]\ncwe_overrides: {R1: sqli}\n",
        encoding="utf-8",
    )
    with pytest.raises(ToolError, match="not a CWE"):
        load_variant(folder / "tool.yaml")


def test_in_source_suppressions_are_ignored():
    assert "--ignore-nosec" in load_variant(TOOLS / "bandit" / "tool.yaml").command
    for name in ("semgrep-default", "semgrep-mcp"):
        assert "--disable-nosem" in load_variant(TOOLS / name / "tool.yaml").command


def test_empty_tools_folder_is_an_error(tmp_path):
    with pytest.raises(ToolError, match="no tool variants found"):
        load_variants(tmp_path)
