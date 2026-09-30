import re
import tomllib
from pathlib import Path

from typer.testing import CliRunner

from mcpvb.cli import app

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_version_is_the_same_everywhere():
    # pyproject.toml, `mcpvb --version` and the README status line must not drift apart
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    version = pyproject["project"]["version"]
    result = CliRunner().invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.output.strip() == f"mcpvb {version}"
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert re.search(r"^> Status: v(\S+)", readme, re.MULTILINE).group(1) == version


def test_help_describes_the_program():
    result = CliRunner().invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "MCP-server vulnerabilities" in result.output


def test_validate_accepts_an_empty_case_directory(tmp_path):
    result = CliRunner().invoke(app, ["validate", "--cases-dir", str(tmp_path)])
    assert result.exit_code == 0
    assert "0 case(s) valid" in result.output


def test_validate_reports_invalid_cases(tmp_path):
    folder = tmp_path / "mcpvb-0001"
    folder.mkdir()
    (folder / "case.yaml").write_text("id: mcpvb-0001\ntitle: broken\n", encoding="utf-8")
    result = CliRunner().invoke(app, ["validate", "--cases-dir", str(tmp_path)])
    assert result.exit_code == 1
    assert "Field required" in result.output


def test_validate_checks_the_tool_variants(tmp_path):
    (tmp_path / "cases").mkdir()
    broken = tmp_path / "tools" / "x"
    broken.mkdir(parents=True)
    (broken / "tool.yaml").write_text("name: x\n", encoding="utf-8")
    args = [
        "validate",
        "--cases-dir",
        str(tmp_path / "cases"),
        "--tools-dir",
        str(tmp_path / "tools"),
    ]
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 1
    assert "Field required" in result.output
