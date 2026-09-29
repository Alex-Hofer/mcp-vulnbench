import json
import os
from pathlib import Path

import pytest

from mcpvb.classes import VulnClass
from mcpvb.normalize import NormalizeError, load_run, parse_sarif, relative_path
from mcpvb.run import Status, run_dir

REAL = Path(__file__).parent / "fixtures" / "sarif" / "real"


def sarif(results: list[dict], rules=None, extensions=None) -> dict:
    tool: dict = {"driver": {"name": "t", "rules": rules or []}}
    if extensions is not None:
        tool["extensions"] = extensions
    return {"version": "2.1.0", "runs": [{"tool": tool, "results": results}]}


def result(rule_id: str, uri: str, line: int) -> dict:
    physical = {"artifactLocation": {"uri": uri}, "region": {"startLine": line}}
    return {
        "ruleId": rule_id,
        "message": {"text": "msg"},
        "locations": [{"physicalLocation": physical}],
    }


def write(tmp_path: Path, doc: dict) -> Path:
    path = tmp_path / "raw.sarif"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def parse(path: Path, overrides=None):
    return parse_sarif(path, "v", "mcpvb-0001", "vulnerable", overrides)


@pytest.mark.parametrize(
    "uri, expected",
    [
        ("file:///src/app/server.py", "app/server.py"),
        ("/src/app/server.py", "app/server.py"),
        ("./app/server.py", "app/server.py"),
        ("app\\server.py", "app/server.py"),
        ("file:///src/My%20Dir/x.py", "My Dir/x.py"),
        ("server.py", "server.py"),
    ],
)
def test_relative_path(uri, expected):
    assert relative_path(uri) == expected


def test_semgrep_style_tags(tmp_path):
    tags = [
        "CWE-78: Improper Neutralization of Special Elements used in an OS Command",
        "OWASP-A03",
    ]
    rules = [{"id": "python.shell-true", "properties": {"tags": tags}}]
    doc = sarif([result("python.shell-true", "/src/server.py", 15)], rules)
    [finding] = parse(write(tmp_path, doc))
    assert (finding.file, finding.line, finding.end_line) == ("server.py", 15, 15)
    assert finding.cwe == "CWE-78" and finding.vuln_class is VulnClass.COMMAND_INJECTION


def test_codeql_style_rules_in_extensions(tmp_path):
    tags = ["security", "external/cwe/cwe-022", "external/cwe/cwe-023"]
    extensions = [
        {
            "name": "codeql/python-queries",
            "rules": [{"id": "py/path-injection", "properties": {"tags": tags}}],
        }
    ]
    doc = sarif([result("py/path-injection", "server.py", 22)], extensions=extensions)
    [finding] = parse(write(tmp_path, doc))
    assert finding.cwe == "CWE-22" and finding.vuln_class is VulnClass.PATH_TRAVERSAL


def test_override_wins_over_the_tool_cwe(tmp_path):
    rules = [{"id": "B307", "properties": {"tags": ["security", "external/cwe/cwe-78"]}}]
    doc = sarif([result("B307", "server.py", 3)], rules)
    [finding] = parse(write(tmp_path, doc), {"B307": "CWE-95"})
    assert finding.vuln_class is VulnClass.CODE_INJECTION


def test_out_of_scope_cwe_is_kept_but_unclassified(tmp_path):
    rules = [{"id": "B110", "properties": {"tags": ["external/cwe/cwe-703"]}}]
    [finding] = parse(write(tmp_path, sarif([result("B110", "server.py", 9)], rules)))
    assert finding.cwe == "CWE-703" and finding.vuln_class is None


def test_results_without_location_are_skipped(tmp_path):
    doc = sarif([{"ruleId": "r", "message": {"text": "no location"}}])
    assert parse(write(tmp_path, doc)) == []


@pytest.mark.parametrize("content", ["{", "[]", '{"version": "2.1.0"}'])
def test_broken_sarif_raises(tmp_path, content):
    path = tmp_path / "raw.sarif"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(NormalizeError):
        parse(path)


def ok_run(results: Path, doc_text: str) -> Path:
    folder = run_dir(results, "bandit", "mcpvb-0001", "vulnerable")
    (folder / "tool").mkdir(parents=True)
    (folder / "meta.json").write_text(json.dumps({"status": "ok"}), encoding="utf-8")
    (folder / "tool" / "raw.sarif").write_text(doc_text, encoding="utf-8")
    return folder


def test_ok_run_with_broken_sarif_counts_as_error(tmp_path):
    ok_run(tmp_path, "not json")
    status, findings = load_run(tmp_path, "bandit", "mcpvb-0001", "vulnerable")
    assert status is Status.ERROR and findings == []


def test_load_run_writes_findings_json(tmp_path):
    rules = [{"id": "B602", "properties": {"tags": ["external/cwe/cwe-78"]}}]
    folder = ok_run(tmp_path, json.dumps(sarif([result("B602", "/src/server.py", 15)], rules)))
    status, findings = load_run(tmp_path, "bandit", "mcpvb-0001", "vulnerable")
    assert status is Status.OK and findings[0].rule_id == "B602"
    written = json.loads((folder / "findings.json").read_text(encoding="utf-8"))
    assert written[0]["vuln_class"] == "command-injection"


@pytest.mark.parametrize("path", sorted(REAL.glob("*.sarif")), ids=lambda p: p.stem)
def test_recorded_tool_output_parses(path):
    assert all(f.file and f.line >= 1 for f in parse(path))


def test_recorded_bandit_output_contains_shell_true():
    path = REAL / "bandit-toy-vulnerable.sarif"
    if not path.exists():
        pytest.skip("record the fixtures first (Task 6, Step 7)")
    findings = parse(path)
    assert any(
        f.rule_id == "B602" and f.line == 15 and f.vuln_class is VulnClass.COMMAND_INJECTION
        for f in findings
    )


def test_symlinked_sarif_counts_as_error(tmp_path):
    folder = run_dir(tmp_path, "bandit", "mcpvb-0001", "vulnerable")
    (folder / "tool").mkdir(parents=True)
    (folder / "meta.json").write_text(json.dumps({"status": "ok"}), encoding="utf-8")
    elsewhere = tmp_path / "elsewhere.sarif"
    elsewhere.write_text(json.dumps(sarif([])), encoding="utf-8")
    try:
        os.symlink(elsewhere, folder / "tool" / "raw.sarif")
    except OSError:
        pytest.skip("creating symlinks is not permitted on this machine")
    status, findings = load_run(tmp_path, "bandit", "mcpvb-0001", "vulnerable")
    assert status is Status.ERROR and findings == []


def one_result(**changes) -> dict:
    physical = {"artifactLocation": {"uri": "server.py"}, "region": {"startLine": 3}}
    result = {
        "ruleId": "r",
        "message": {"text": "m"},
        "locations": [{"physicalLocation": physical}],
    }
    result.update(changes)
    return {"version": "2.1.0", "runs": [{"results": [result]}]}


BAD_REGION = [
    {"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": {"startLine": "x"}}}
]
MALFORMED_OR_FAILED = {
    "run-null": {"version": "2.1.0", "runs": [None]},
    "results-null": {"version": "2.1.0", "runs": [{"results": None}]},
    "results-missing": {"version": "2.1.0", "runs": [{}]},
    "result-null": {"version": "2.1.0", "runs": [{"results": [None]}]},
    "message-string": one_result(message="plain string"),
    "line-not-int": one_result(locations=BAD_REGION),
    "execution-failed": {
        "version": "2.1.0",
        "runs": [{"results": [], "invocations": [{"executionSuccessful": False}]}],
    },
}


@pytest.mark.parametrize("name", sorted(MALFORMED_OR_FAILED))
def test_malformed_or_failed_sarif_raises(tmp_path, name):
    with pytest.raises(NormalizeError):
        parse(write(tmp_path, MALFORMED_OR_FAILED[name]))


def test_malformed_sarif_marks_only_that_run_as_error(tmp_path):
    ok_run(tmp_path, json.dumps(MALFORMED_OR_FAILED["results-null"]))
    status, findings = load_run(tmp_path, "bandit", "mcpvb-0001", "vulnerable")
    assert status is Status.ERROR and findings == []


def test_well_formed_single_result_still_parses(tmp_path):
    [finding] = parse(write(tmp_path, one_result()))
    assert (finding.file, finding.line) == ("server.py", 3)
