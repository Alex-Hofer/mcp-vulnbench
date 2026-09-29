import tarfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcpvb import fetch as fetch_module
from mcpvb.cli import app
from mcpvb.fetch import FetchError, check_locations, fetch_case
from mcpvb.schema import load_cases

TOY_SERVER = Path(__file__).resolve().parents[1] / "examples" / "toy-server"


def test_toy_ground_truth_points_at_the_functions():
    vulnerable = (TOY_SERVER / "vulnerable" / "server.py").read_text(encoding="utf-8").splitlines()
    fixed = (TOY_SERVER / "fixed" / "server.py").read_text(encoding="utf-8").splitlines()
    assert vulnerable[11] == "@mcp.tool()" and vulnerable[12].startswith("def ping")
    assert vulnerable[15] == "    return completed.stdout"
    assert vulnerable[18] == "@mcp.tool()" and vulnerable[19].startswith("def read_note")
    assert vulnerable[22] == "        return handle.read()"
    assert fixed[13] == "@mcp.tool()" and fixed[14].startswith("def ping")
    assert fixed[19] == "    return completed.stdout"
    assert fixed[22] == "@mcp.tool()" and fixed[23].startswith("def read_note")
    assert fixed[28] == '    return target.read_text(encoding="utf-8")'


def test_fetch_exports_both_versions(toy_cases_dir, tmp_path):
    case = load_cases(toy_cases_dir, ["mcpvb-9001"])[0]
    sources = fetch_case(case, tmp_path / "cache")
    assert "shell=True" in (sources.vulnerable / "server.py").read_text(encoding="utf-8")
    assert "HOST_RE" in (sources.fixed / "server.py").read_text(encoding="utf-8")
    assert check_locations(case, sources) == []


def test_fetch_is_idempotent(toy_cases_dir, tmp_path, monkeypatch):
    case = load_cases(toy_cases_dir, ["mcpvb-9001"])[0]
    fetch_case(case, tmp_path / "cache")

    def fail(*args, **kwargs):
        raise AssertionError("a second fetch must not export again")

    monkeypatch.setattr(fetch_module, "_export", fail)
    fetch_case(case, tmp_path / "cache")


def test_unknown_commit_raises(toy_cases_dir, tmp_path):
    case = load_cases(toy_cases_dir, ["mcpvb-9001"])[0]
    broken = case.model_copy(update={"fixed": case.fixed.model_copy(update={"commit": "f" * 40})})
    with pytest.raises(FetchError):
        fetch_case(broken, tmp_path / "cache")


def test_check_locations_reports_typos(toy_cases_dir, tmp_path):
    case = load_cases(toy_cases_dir, ["mcpvb-9002"])[0]
    sources = fetch_case(case, tmp_path / "cache")
    missing_file = case.vulnerable.locations[0].model_copy(update={"file": "srv.py"})
    too_long = case.fixed.locations[0].model_copy(update={"lines": (23, 99)})
    broken = case.model_copy(
        update={
            "vulnerable": case.vulnerable.model_copy(update={"locations": [missing_file]}),
            "fixed": case.fixed.model_copy(update={"locations": [too_long]}),
        }
    )
    problems = check_locations(broken, sources)
    assert any("srv.py not found" in problem for problem in problems)
    assert any("exceed the 33 lines" in problem for problem in problems)


def test_fetch_command(toy_cases_dir, tmp_path):
    args = ["fetch", "--cases-dir", str(toy_cases_dir), "--cache-dir", str(tmp_path / "cache")]
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0, result.output
    assert "2 case(s) fetched" in result.output


def test_missing_subdir_is_a_fetch_error(toy_cases_dir, tmp_path):
    case = load_cases(toy_cases_dir, ["mcpvb-9001"])[0].model_copy(update={"subdir": "servers/git"})
    with pytest.raises(FetchError, match="subdir 'servers/git' not found"):
        fetch_case(case, tmp_path / "cache")


def test_file_names_must_match_exactly(toy_cases_dir, tmp_path):
    case = load_cases(toy_cases_dir, ["mcpvb-9001"])[0]
    sources = fetch_case(case, tmp_path / "cache")
    wrong_case = case.vulnerable.locations[0].model_copy(update={"file": "Server.py"})
    version = case.vulnerable.model_copy(update={"locations": [wrong_case]})
    problems = check_locations(case.model_copy(update={"vulnerable": version}), sources)
    assert any("Server.py not found" in problem for problem in problems)


def test_tool_configs_of_the_analyzed_project_are_not_exported():
    for name in (".bandit", "src/.semgrepignore"):
        assert fetch_module._regular_files_only(tarfile.TarInfo(name), "dest") is None, name
    assert fetch_module._regular_files_only(tarfile.TarInfo("src/server.py"), "dest") is not None
