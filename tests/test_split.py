from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from mcpvb.cli import app
from mcpvb.schema import Case, CaseError, Split
from mcpvb.split import assign_splits, write_split

REPO_ROOT = Path(__file__).resolve().parents[1]
CWE = {"path-traversal": "CWE-22", "ssrf": "CWE-918"}  # the schema checks class against CWE


def make_case(
    number: int, vuln_class: str = "path-traversal", split: str | None = None, repo: str = ""
) -> Case:
    location = {"file": "server.py", "function": "f", "lines": [1, 2]}
    return Case.model_validate(
        {
            "id": f"mcpvb-{number:04d}",
            "title": "Toy case",
            "repo": repo or f"https://github.com/example/toy-{number}",
            "license": "MIT",
            "language": "python",
            "class": vuln_class,
            "cwe": CWE[vuln_class],
            "mcp_tool": "f",
            "vulnerable": {"commit": "a" * 40, "locations": [location]},
            "fixed": {"commit": "b" * 40, "locations": [location]},
            "source": "other",
            "split": split,
        }
    )


def test_assignment_is_stratified_and_starts_with_test():
    cases = [make_case(n) for n in range(1, 6)] + [make_case(n, "ssrf") for n in range(6, 9)]
    halves = assign_splits(cases)
    path = [halves[c.id] for c in cases if c.vuln_class.value == "path-traversal"]
    ssrf = [halves[c.id] for c in cases if c.vuln_class.value == "ssrf"]
    assert (path.count(Split.TEST), path.count(Split.DEV)) == (3, 2)
    assert (ssrf.count(Split.TEST), ssrf.count(Split.DEV)) == (2, 1)


def test_assignment_does_not_depend_on_the_input_order():
    cases = [make_case(n) for n in range(1, 8)]
    assert assign_splits(cases) == assign_splits(list(reversed(cases)))


def test_cases_of_one_repository_share_a_half():
    shared = "https://github.com/example/shared"
    cases = [make_case(n, repo=shared) for n in (1, 2, 3)] + [make_case(n) for n in (4, 5, 6)]
    halves = assign_splits(cases)
    assert halves["mcpvb-0001"] == halves["mcpvb-0002"] == halves["mcpvb-0003"]


def test_existing_halves_stay_and_new_cases_fill_their_stratum():
    old = [make_case(1, split="test"), make_case(2, split="test"), make_case(3, split="dev")]
    new = [make_case(4), make_case(5)]
    halves = assign_splits(old + new)
    assert set(halves) == {"mcpvb-0004", "mcpvb-0005"}  # old cases are not touched
    assert sorted(halves.values()) == [Split.DEV, Split.TEST]  # 2/1 becomes 3/2, fewer first


def test_a_new_case_of_a_known_repository_inherits_its_half():
    shared = "https://github.com/example/shared"
    old = [make_case(1, split="dev", repo=shared), make_case(2, split="dev"), make_case(3)]
    halves = assign_splits([*old, make_case(4, repo=shared + ".git")])
    assert halves["mcpvb-0004"] == Split.DEV  # although the stratum would favor the test half


def test_a_repository_in_both_halves_is_an_error():
    shared = "https://github.com/example/shared"
    cases = [make_case(1, split="dev", repo=shared), make_case(2, split="test", repo=shared)]
    with pytest.raises(CaseError, match="both halves"):
        assign_splits([*cases, make_case(3, repo=shared)])


def test_second_run_assigns_nothing():
    cases = [make_case(n) for n in range(1, 5)]
    halves = assign_splits(cases)
    done = [c.model_copy(update={"split": halves[c.id]}) for c in cases]
    assert assign_splits(done) == {}


@pytest.mark.parametrize("line", ["split: null", "split: ~", "split:"])
def test_write_split_replaces_an_empty_split_line(tmp_path, line):
    case_file = tmp_path / "case.yaml"
    case_file.write_text(f"id: mcpvb-0001\n{line}\nnotes: ''\n", encoding="utf-8")
    write_split(case_file, Split.DEV)
    assert case_file.read_text(encoding="utf-8") == "id: mcpvb-0001\nsplit: dev\nnotes: ''\n"


def test_write_split_reports_a_missing_split_line(tmp_path):
    case_file = tmp_path / "case.yaml"
    case_file.write_text("id: mcpvb-0001\nnotes: ''\n", encoding="utf-8")
    with pytest.raises(CaseError, match="split"):
        write_split(case_file, Split.DEV)


def set_splits(toy_cases_dir: Path, *halves: str | None) -> None:
    for case_file, half in zip(sorted(toy_cases_dir.glob("*/case.yaml")), halves, strict=True):
        data = yaml.safe_load(case_file.read_text(encoding="utf-8"))
        data["split"] = half
        case_file.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")


def validate(toy_cases_dir: Path):
    args = ["validate", "--cases-dir", str(toy_cases_dir), "--tools-dir", str(REPO_ROOT / "tools")]
    return CliRunner().invoke(app, args)


def test_validate_reports_cases_without_a_split(toy_cases_dir):
    set_splits(toy_cases_dir, None, None)
    result = validate(toy_cases_dir)
    assert result.exit_code == 1
    assert "without a split" in result.output and "mcpvb split" in result.output


def test_validate_reports_a_repository_in_both_halves(toy_cases_dir):
    set_splits(toy_cases_dir, "dev", "test")  # both toy cases come from one repository
    result = validate(toy_cases_dir)
    assert result.exit_code == 1
    assert "both halves" in result.output


def test_split_command_assigns_every_case_once(toy_cases_dir):
    set_splits(toy_cases_dir, None, None)
    first = CliRunner().invoke(app, ["split", "--cases-dir", str(toy_cases_dir)])
    assert first.exit_code == 0, first.output
    assert "assigned 2 case(s)" in first.output
    second = CliRunner().invoke(app, ["split", "--cases-dir", str(toy_cases_dir)])
    assert "assigned 0 case(s)" in second.output
    result = validate(toy_cases_dir)
    assert result.exit_code == 0, result.output


def test_split_option_selects_one_half(toy_cases_dir, tmp_path):
    args = ["fetch", "--cases-dir", str(toy_cases_dir), "--cache-dir", str(tmp_path / "cache")]
    dev = CliRunner().invoke(app, [*args, "--split", "dev"])
    assert dev.exit_code == 0, dev.output
    assert "2 case(s) fetched" in dev.output
    test = CliRunner().invoke(app, [*args, "--split", "test"])
    assert "0 case(s) fetched" in test.output
