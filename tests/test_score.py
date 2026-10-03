import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcpvb.classes import VulnClass
from mcpvb.cli import app
from mcpvb.normalize import Finding
from mcpvb.run import Status, fingerprint
from mcpvb.schema import Case, Language, load_cases
from mcpvb.score import is_detected, is_persisting, score_case, summarize
from mcpvb.tools import load_variant

REPO_ROOT = Path(__file__).resolve().parents[1]

CASE = Case.model_validate(
    {
        "id": "mcpvb-0001",
        "title": "Command injection in ping",
        "repo": "https://github.com/example/toy",
        "license": "MIT",
        "language": "python",
        "class": "command-injection",
        "cwe": "CWE-78",
        "mcp_tool": "ping",
        "vulnerable": {
            "commit": "a" * 40,
            "locations": [{"file": "server.py", "function": "ping", "lines": [12, 16]}],
        },
        "fixed": {
            "commit": "b" * 40,
            "locations": [{"file": "server.py", "function": "ping", "lines": [14, 20]}],
        },
        "source": "other",
    }
)

CWES = {VulnClass.COMMAND_INJECTION: "CWE-78", VulnClass.PATH_TRAVERSAL: "CWE-22", None: "CWE-703"}


def finding(
    line,
    vuln_class=VulnClass.COMMAND_INJECTION,
    file="server.py",
    version="vulnerable",
    case_id="mcpvb-0001",
):
    return Finding(
        variant="v",
        case_id=case_id,
        version=version,
        file=file,
        line=line,
        end_line=line,
        rule_id="r",
        cwe=CWES[vuln_class],
        vuln_class=vuln_class,
        message="",
    )


def case(case_id: str) -> Case:
    return CASE.model_copy(update={"id": case_id})


@pytest.mark.parametrize(
    "line, expected", [(12, True), (15, True), (16, True), (11, False), (17, False)]
)
def test_detection_uses_the_inclusive_line_range(line, expected):
    assert is_detected(CASE, [finding(line)]) is expected


def test_detection_requires_the_same_class():
    wrong_class = [finding(15, VulnClass.PATH_TRAVERSAL)]
    assert is_detected(CASE, wrong_class) is False
    assert is_detected(CASE, wrong_class, any_class=True) is True


def test_unclassified_findings_never_count_as_detection():
    # "any class" means any of the five classes: an assert or a missing timeout in the vulnerable
    # function is not a lenient detection of the bug
    unclassified = [finding(15, None)]
    assert is_detected(CASE, unclassified) is False
    assert is_detected(CASE, unclassified, any_class=True) is False


def test_file_level_ignores_lines_but_not_the_file():
    assert is_detected(CASE, [finding(40)], file_level=True) is True
    assert is_detected(CASE, [finding(15, file="other.py")], file_level=True) is False


def test_persisting_uses_the_fixed_location():
    assert is_persisting(CASE, [finding(19, version="fixed")]) is True
    assert is_persisting(CASE, [finding(12, version="fixed")]) is False


def test_score_case_leaves_metrics_open_when_a_run_failed():
    failed = score_case("v", CASE, Status.ERROR, Status.OK, [], [])
    assert failed.detected is None and failed.persisting is None
    fixed_failed = score_case("v", CASE, Status.OK, Status.TIMEOUT, [finding(15)], [])
    assert fixed_failed.detected is True and fixed_failed.persisting is None


def test_summarize_computes_the_documented_metrics():
    ok, error = Status.OK, Status.ERROR
    outcomes = [
        score_case("v", case("mcpvb-0001"), ok, ok, [finding(15, case_id="mcpvb-0001")], []),
        score_case(
            "v",
            case("mcpvb-0002"),
            ok,
            ok,
            [finding(15, case_id="mcpvb-0002")],
            [finding(19, version="fixed", case_id="mcpvb-0002")],
        ),
        score_case("v", case("mcpvb-0003"), ok, ok, [], []),
        score_case("v", case("mcpvb-0004"), error, ok, [], []),
    ]
    vulnerable_findings = {
        "v": [
            finding(15, case_id="mcpvb-0001"),
            finding(15, case_id="mcpvb-0002"),
            finding(30, None, case_id="mcpvb-0003"),
        ]
    }
    kloc = {"mcpvb-0001": 0.5, "mcpvb-0002": 0.5, "mcpvb-0003": 1.0, "mcpvb-0004": 2.0}
    overall = summarize(outcomes, vulnerable_findings, kloc)["variants"]["v"]["overall"]
    assert (overall["cases_ok"], overall["detected"], overall["recall"]) == (3, 2, 0.6667)
    assert (overall["fix_recognized"], overall["fix_assessed"]) == (1, 2)
    assert overall["fix_recognition"] == 0.5
    assert overall["alarms_per_kloc"] == 1.0  # 2 classified findings / 2.0 KLOC of the ok cases
    assert overall["unclassified_findings"] == 1
    assert overall["error_rate"] == 0.125  # 1 of 8 runs


def test_unsupported_runs_are_no_errors():
    outcome = score_case(
        "bandit", case("mcpvb-0005"), Status.UNSUPPORTED, Status.UNSUPPORTED, [], []
    )
    overall = summarize([outcome], {}, {})["variants"]["bandit"]["overall"]
    assert overall["error_rate"] is None
    assert overall["unsupported_cases"] == 1
    assert overall["recall"] is None


def write_bandit_runs(toy_cases_dir, results, recorded_commit: str | None = None) -> None:
    """Finished bandit runs on both toy cases, as run_one records them (fingerprint included)."""
    rules = [{"id": "B602", "properties": {"tags": ["external/cwe/cwe-78"]}}]
    physical = {"artifactLocation": {"uri": "file:///src/server.py"}, "region": {"startLine": 15}}
    hit = {
        "ruleId": "B602",
        "message": {"text": "shell=True"},
        "locations": [{"physicalLocation": physical}],
    }
    tool = {"driver": {"name": "bandit", "rules": rules}}
    docs = {
        "vulnerable": {"version": "2.1.0", "runs": [{"tool": tool, "results": [hit]}]},
        "fixed": {"version": "2.1.0", "runs": [{"tool": tool, "results": []}]},
    }
    variant = load_variant(REPO_ROOT / "tools" / "bandit" / "tool.yaml")
    for current in load_cases(toy_cases_dir):
        for version, doc in docs.items():
            folder = results / "bandit" / current.id / version
            (folder / "tool").mkdir(parents=True)  # analyzer output lives in <run>/tool/ (I8)
            (folder / "tool" / "raw.sarif").write_text(json.dumps(doc), encoding="utf-8")
            recorded = fingerprint(variant, current, version, "sha256:abc")
            if recorded_commit:
                recorded["commit"] = recorded_commit
            meta = {"status": "ok", "fingerprint": recorded}
            (folder / "meta.json").write_text(json.dumps(meta), encoding="utf-8")


def score_cli(toy_cases_dir, tmp_path, results):
    args = ["score", "--cases-dir", str(toy_cases_dir), "--tools-dir", str(REPO_ROOT / "tools")]
    args += ["--cache-dir", str(tmp_path / "cache"), "--results-dir", str(results)]
    return CliRunner().invoke(app, [*args, "--variant", "bandit"])


def test_score_command_writes_metrics(toy_cases_dir, tmp_path):
    results = tmp_path / "results"
    write_bandit_runs(toy_cases_dir, results)
    outcome = score_cli(toy_cases_dir, tmp_path, results)
    assert outcome.exit_code == 0, outcome.output
    metrics = json.loads((results / "metrics.json").read_text(encoding="utf-8"))
    overall = metrics["variants"]["bandit"]["overall"]
    assert (overall["cases_ok"], overall["detected"], overall["fix_recognition"]) == (2, 1, 1.0)


def test_score_ignores_runs_of_an_edited_case(toy_cases_dir, tmp_path):
    results = tmp_path / "results"
    write_bandit_runs(toy_cases_dir, results, recorded_commit="0" * 40)
    outcome = score_cli(toy_cases_dir, tmp_path, results)
    assert outcome.exit_code == 0, outcome.output
    assert "do not match the current case or image" in outcome.output
    metrics = json.loads((results / "metrics.json").read_text(encoding="utf-8"))
    assert metrics["variants"]["bandit"]["overall"]["cases_ok"] == 0
    assert {o["status_vulnerable"] for o in metrics["cases"]} == {"unavailable"}


def test_alarm_figures_ignore_findings_in_skipped_folders():
    outcome = score_case("v", CASE, Status.OK, Status.OK, [finding(15)], [])
    in_tests = [
        finding(3, file="tests/test_server.py"),
        finding(4, None, file="tests/test_server.py"),
    ]
    summary = summarize([outcome], {"v": [finding(15), *in_tests]}, {"mcpvb-0001": 1.0})
    overall = summary["variants"]["v"]["overall"]
    assert overall["alarms_per_kloc"] == 1.0  # only server.py counts, like the KLOC
    assert overall["unclassified_findings"] == 0


def test_alarm_figures_leave_out_cases_without_a_line_count():
    ok = Status.OK
    outcomes = [score_case("v", case(cid), ok, ok, [], []) for cid in ("mcpvb-0001", "mcpvb-0002")]
    findings = [
        finding(30, case_id="mcpvb-0001"),
        finding(30, case_id="mcpvb-0002"),
        finding(31, None, case_id="mcpvb-0002"),
    ]
    # the sources of mcpvb-0002 were unavailable, so it has no KLOC
    summary = summarize(outcomes, {"v": findings}, {"mcpvb-0001": 1.0})
    overall = summary["variants"]["v"]["overall"]
    assert overall["alarms_per_kloc"] == 1.0
    assert overall["alarms_median_per_case"] == 1
    assert overall["unclassified_findings"] == 0


def test_alarm_figures_ignore_findings_outside_the_case_language():
    outcome = score_case("v", CASE, Status.OK, Status.OK, [finding(15)], [])
    other_languages = [
        finding(7, file=".github/workflows/release.yml"),
        finding(9, None, file="frontend/app.ts"),
    ]
    summary = summarize([outcome], {"v": [finding(15), *other_languages]}, {"mcpvb-0001": 1.0})
    overall = summary["variants"]["v"]["overall"]
    assert overall["alarms_per_kloc"] == 1.0  # the KLOC of a Python case counts only .py files
    assert overall["unclassified_findings"] == 0


def test_score_files_use_lf_line_endings_on_every_system(toy_cases_dir, tmp_path):
    results = tmp_path / "results"
    write_bandit_runs(toy_cases_dir, results)
    assert score_cli(toy_cases_dir, tmp_path, results).exit_code == 0
    written = [results / "metrics.json", *results.glob("bandit/*/*/findings.json")]
    assert len(written) == 5
    for path in written:
        assert b"\r\n" not in path.read_bytes(), path


def test_summarize_reports_each_half_like_overall():
    ok = Status.OK
    halves = {"mcpvb-0001": "dev", "mcpvb-0002": "dev", "mcpvb-0003": "test"}
    outcomes = [
        score_case("v", case(cid).model_copy(update={"split": half}), ok, ok, found, [])
        for (cid, half), found in zip(
            halves.items(),
            [[finding(15, case_id="mcpvb-0001")], [], [finding(15, case_id="mcpvb-0003")]],
            strict=True,
        )
    ]
    kloc = dict.fromkeys(halves, 1.0)
    summary = summarize(outcomes, {"v": [finding(15, case_id=c) for c in halves]}, kloc)
    by_split = summary["variants"]["v"]["by_split"]
    assert (by_split["dev"]["cases_ok"], by_split["dev"]["detected"]) == (2, 1)
    assert (by_split["test"]["cases_ok"], by_split["test"]["recall"]) == (1, 1.0)
    assert by_split["dev"]["alarms_per_kloc"] == 1.0
    assert summary["cases"][0]["split"] == "dev"


def test_summarize_reports_each_half_per_language_group():
    ok = Status.OK
    rows = {
        "mcpvb-0001": ("python", "dev", [finding(15, case_id="mcpvb-0001")]),
        "mcpvb-0002": ("typescript", "dev", []),
        "mcpvb-0003": ("javascript", "test", [finding(15, case_id="mcpvb-0003")]),
        "mcpvb-0004": ("typescript", "test", []),
    }
    outcomes = []
    for cid, (language, half, found) in rows.items():
        this = case(cid).model_copy(update={"language": Language(language), "split": half})
        outcomes.append(score_case("v", this, ok, ok, found, []))
    groups = summarize(outcomes, {}, {})["variants"]["v"]["by_language_split"]
    # JavaScript and TypeScript are one group: same analyzers, rules and models
    assert sorted(groups) == ["javascript/typescript", "python"]
    assert sorted(groups["python"]) == ["dev"]  # no Python case in the test half
    assert (groups["python"]["dev"]["cases_ok"], groups["python"]["dev"]["detected"]) == (1, 1)
    scripts = groups["javascript/typescript"]
    assert (scripts["dev"]["cases_ok"], scripts["dev"]["recall"]) == (1, 0.0)
    assert (scripts["test"]["cases_ok"], scripts["test"]["detected"]) == (2, 1)


def test_a_half_without_ok_runs_has_no_rates():
    outcome = score_case(
        "v", CASE.model_copy(update={"split": "test"}), Status.ERROR, Status.ERROR, [], []
    )
    test_half = summarize([outcome], {}, {})["variants"]["v"]["by_split"]["test"]
    assert test_half["recall"] is None and test_half["alarms_per_kloc"] is None
