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
