import io
import os
import shutil
import stat
import tarfile
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcpvb import fetch as fetch_module
from mcpvb.cli import app
from mcpvb.fetch import FetchError, check_locations, fetch_case
from mcpvb.schema import Case, load_cases

TOY_SERVER = Path(__file__).resolve().parents[1] / "examples" / "toy-server"
from conftest import git, is_read_only, toy_case_data, windows_only  # noqa: E402


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


def test_links_are_skipped_wherever_they_point(tmp_path):
    data = b"print('ok')\n"
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tar:
        regular = tarfile.TarInfo("src/server.py")
        regular.size = len(data)
        tar.addfile(regular, io.BytesIO(data))
        for name, kind, target in [
            ("src/absolute", tarfile.SYMTYPE, "/etc/passwd"),
            ("src/outside", tarfile.SYMTYPE, "../../elsewhere"),
            ("src/inside", tarfile.SYMTYPE, "server.py"),
            ("src/hard", tarfile.LNKTYPE, "../outside"),
        ]:
            link = tarfile.TarInfo(name)
            link.type, link.linkname = kind, target
            tar.addfile(link)
    buffer.seek(0)
    with tarfile.open(fileobj=buffer) as tar:
        tar.extractall(tmp_path, filter=fetch_module._regular_files_only)
    assert [path.name for path in (tmp_path / "src").iterdir()] == ["server.py"]
    assert (tmp_path / "src" / "server.py").read_bytes() == data


def test_tool_configs_of_the_analyzed_project_are_not_exported():
    for name in (".bandit", "src/.semgrepignore"):
        assert fetch_module._regular_files_only(tarfile.TarInfo(name), "dest") is None, name
    assert fetch_module._regular_files_only(tarfile.TarInfo("src/server.py"), "dest") is not None


def with_location(case, version: str, **changes):
    target = getattr(case, version)
    location = target.locations[0].model_copy(update=changes)
    return case.model_copy(update={version: target.model_copy(update={"locations": [location]})})


def test_location_must_name_an_existing_function(toy_cases_dir, tmp_path):
    case = load_cases(toy_cases_dir, ["mcpvb-9001"])[0]
    sources = fetch_case(case, tmp_path / "cache")
    problems = check_locations(with_location(case, "vulnerable", function="pong"), sources)
    assert any("function pong not found" in problem for problem in problems)


def test_location_lines_must_match_the_function(toy_cases_dir, tmp_path):
    case = load_cases(toy_cases_dir, ["mcpvb-9001"])[0]
    sources = fetch_case(case, tmp_path / "cache")
    problems = check_locations(with_location(case, "fixed", lines=(15, 20)), sources)
    assert any("ping spans [14, 20]" in problem for problem in problems)


def test_export_contains_the_exact_committed_files(tmp_path):
    repo = tmp_path / "attributes-remote"
    repo.mkdir()
    git(repo, "init", "--quiet", "--initial-branch=main")
    git(repo, "config", "user.name", "Test")
    git(repo, "config", "user.email", "test@example.invalid")
    git(repo, "config", "core.autocrlf", "false")
    git(repo, "config", "commit.gpgsign", "false")  # like toy_repo: no signing key in tests
    (repo / ".gitattributes").write_text("hidden.py export-ignore\n*.py text\n", encoding="utf-8")
    (repo / "hidden.py").write_bytes(b"x = 1\n")
    shas = []
    for version in ("vulnerable", "fixed"):
        shutil.copyfile(TOY_SERVER / version / "server.py", repo / "server.py")
        git(repo, "add", "-A")
        git(repo, "commit", "--quiet", "--message", version)
        shas.append(git(repo, "rev-parse", "HEAD"))
    case = Case.model_validate(toy_case_data(repo.as_uri(), *shas)[0])
    sources = fetch_case(case, tmp_path / "cache")
    assert (sources.vulnerable / "hidden.py").is_file()  # export-ignore must not drop code
    assert b"\r\n" not in (sources.vulnerable / "server.py").read_bytes()  # no autocrlf


@windows_only
def test_interrupted_export_is_replaced_when_marked_read_only(toy_cases_dir, tmp_path):
    case = load_cases(toy_cases_dir, ["mcpvb-9001"])[0]
    fetch_case(case, tmp_path / "cache")
    export = tmp_path / "cache" / "cases" / case.id / "vulnerable"
    (export / fetch_module.DONE_MARKER).unlink()  # the export was interrupted
    for path in (export, *export.rglob("*")):
        if path.is_dir():
            os.chmod(path, stat.S_IREAD)  # what backup clients do to the folders they back up
    sources = fetch_case(case, tmp_path / "cache")
    assert (sources.vulnerable / fetch_module.DONE_MARKER).is_file()


@windows_only
def test_broken_mirror_is_cloned_again_despite_read_only_git_objects(toy_cases_dir, tmp_path):
    case = load_cases(toy_cases_dir, ["mcpvb-9001"])[0]
    fetch_case(case, tmp_path / "cache")
    mirror = next((tmp_path / "cache" / "repos").iterdir())
    assert any(is_read_only(path) for path in mirror.rglob("*"))  # git's object files
    (mirror / "HEAD").unlink()  # the clone was interrupted
    fetch_case(case, tmp_path / "cache")
    assert (mirror / "HEAD").is_file()
