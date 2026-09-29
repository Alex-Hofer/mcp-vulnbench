from typer.testing import CliRunner

from mcpvb.cli import app


def test_version_flag_prints_version():
    result = CliRunner().invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "mcpvb 0.1.0" in result.output


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
