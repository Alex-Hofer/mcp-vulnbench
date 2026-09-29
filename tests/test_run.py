import json
import os
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from mcpvb import docker
from mcpvb.cli import app
from mcpvb.docker import ContainerResult
from mcpvb.fetch import fetch_case
from mcpvb.run import (
    InfrastructureError,
    Status,
    fingerprint,
    matches,
    raw_path,
    read_status,
    run_dir,
    run_one,
    write_manifest,
)
from mcpvb.schema import Language, load_cases
from mcpvb.tools import load_variant

REPO_ROOT = Path(__file__).resolve().parents[1]


EMPTY_SARIF = (
    '{"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "fake"}}, "results": []}]}'
)


class FakeRunner:
    def __init__(self, exit_code: int | None = 0, write_sarif: bool = True):
        self.exit_code = exit_code
        self.write_sarif = write_sarif
        self.calls: list[list[str]] = []
        self.outs: list[Path] = []

    def __call__(self, image, command, src, out, timeout_s):
        self.calls.append(command)
        self.outs.append(out)
        if self.write_sarif:
            (out / "raw.sarif").write_text(EMPTY_SARIF, encoding="utf-8")
        return ContainerResult(self.exit_code, "fake log", 0.25)


class SymlinkRunner(FakeRunner):
    """A compromised analyzer: it plants symlinks in the folder it may write to."""

    def __init__(self, links: dict[str, Path]):
        super().__init__()
        self.links = links

    def __call__(self, image, command, src, out, timeout_s):
        result = super().__call__(image, command, src, out, timeout_s)
        for name, target in self.links.items():
            (out / name).unlink(missing_ok=True)
            try:
                os.symlink(target, out / name)
            except OSError:
                pytest.skip("creating symlinks is not permitted on this machine")
        return result


@pytest.fixture
def bandit():
    return load_variant(REPO_ROOT / "tools" / "bandit" / "tool.yaml")


@pytest.fixture
def case(toy_cases_dir):
    return load_cases(toy_cases_dir, ["mcpvb-9001"])[0]


def test_successful_run_is_recorded(bandit, case, tmp_path):
    runner = FakeRunner()
    status = run_one(bandit, case, "vulnerable", tmp_path, tmp_path / "results", runner)
    assert status is Status.OK
    meta_path = run_dir(tmp_path / "results", "bandit", case.id, "vulnerable") / "meta.json"
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    assert meta["status"] == "ok" and meta["tool_version"] == "1.9.4"
    assert runner.calls[0][:3] == ["bandit", "--recursive", "/src"]


@pytest.mark.parametrize(
    "exit_code, write_sarif, expected",
    [(2, True, Status.ERROR), (0, False, Status.ERROR), (None, False, Status.TIMEOUT)],
)
def test_failures_get_their_own_status(bandit, case, tmp_path, exit_code, write_sarif, expected):
    runner = FakeRunner(exit_code, write_sarif)
    assert run_one(bandit, case, "vulnerable", tmp_path, tmp_path / "results", runner) is expected


def test_unsupported_language_skips_the_container(bandit, case, tmp_path):
    ts_case = case.model_copy(update={"language": Language.TYPESCRIPT})
    runner = FakeRunner()
    status = run_one(bandit, ts_case, "vulnerable", tmp_path, tmp_path / "results", runner)
    assert status is Status.UNSUPPORTED
    assert runner.calls == []


def test_missing_sources_are_unavailable(bandit, case, tmp_path):
    status = run_one(bandit, case, "fixed", None, tmp_path / "results", FakeRunner())
    assert status is Status.UNAVAILABLE


def test_completed_runs_are_not_repeated(bandit, case, tmp_path):
    results = tmp_path / "results"
    run_one(bandit, case, "vulnerable", tmp_path, results, FakeRunner())
    second = FakeRunner()
    run_one(bandit, case, "vulnerable", tmp_path, results, second)
    assert second.calls == []
    run_one(bandit, case, "vulnerable", tmp_path, results, second, force=True)
    assert len(second.calls) == 1


def test_aborted_run_without_meta_is_repeated(bandit, case, tmp_path):
    results = tmp_path / "results"
    partial = run_dir(results, "bandit", case.id, "vulnerable")
    partial.mkdir(parents=True)
    (partial / "raw.sarif").write_text("{", encoding="utf-8")  # left over from an aborted run
    runner = FakeRunner()
    assert run_one(bandit, case, "vulnerable", tmp_path, results, runner) is Status.OK
    assert len(runner.calls) == 1
    assert read_status(results, "bandit", case.id, "vulnerable") is Status.OK


def test_run_stops_early_without_docker(monkeypatch, toy_cases_dir, tmp_path):
    def unavailable():
        raise docker.DockerUnavailable("docker daemon not reachable - start Docker Desktop")

    monkeypatch.setattr(docker, "preflight", unavailable)
    args = ["run", "--cases-dir", str(toy_cases_dir), "--tools-dir", str(REPO_ROOT / "tools")]
    result = CliRunner().invoke(app, [*args, "--results-dir", str(tmp_path / "results")])
    assert result.exit_code == 2
    assert "start Docker Desktop" in result.output


@pytest.mark.docker
@pytest.mark.parametrize("name", ["bandit", "semgrep-default", "semgrep-mcp", "codeql"])
def test_real_tool_run_on_toy_case(name, toy_cases_dir, tmp_path):
    variant = load_variant(REPO_ROOT / "tools" / name / "tool.yaml")
    if not docker.image_id(variant.image):
        pytest.skip(f"image {variant.image} not built: uv run mcpvb images --variant {name}")
    case = load_cases(toy_cases_dir, ["mcpvb-9001"])[0]
    sources = fetch_case(case, tmp_path / "cache")
    results = tmp_path / "results"
    for version in ("vulnerable", "fixed"):
        src = sources.for_version(version)
        status = run_one(variant, case, version, src, results, docker.run_container)
        log = (run_dir(results, name, case.id, version) / "log.txt").read_text(encoding="utf-8")
        assert status is Status.OK, log
    if os.environ.get("MCPVB_RECORD_FIXTURES") == "1":
        target = REPO_ROOT / "tests" / "fixtures" / "sarif" / "real"
        target.mkdir(parents=True, exist_ok=True)
        for version in ("vulnerable", "fixed"):
            raw = raw_path(results, name, case.id, version)
            fixture = target / f"{name}-toy-{version}.sarif"
            fixture.write_text(minimized_sarif(raw), encoding="utf-8")


def minimized_sarif(raw: Path) -> str:
    """Results plus the rules they use (id and tags only).

    Enough for the parser tests, small, and free of rule texts: Semgrep registry rules must not
    be redistributed (Semgrep Rules License v1.0).
    """
    doc = json.loads(raw.read_text(encoding="utf-8"))
    for sarif_run in doc.get("runs", []):
        for result in sarif_run.get("results", []):
            result["message"] = {"text": result.get("ruleId", "")}  # tools copy rule texts here
        used = {result.get("ruleId") for result in sarif_run.get("results", [])}
        tool = sarif_run.get("tool", {})
        for component in [tool.get("driver", {}), *tool.get("extensions", [])]:
            component["rules"] = [
                {
                    "id": rule["id"],
                    "properties": {"tags": rule.get("properties", {}).get("tags", [])},
                }
                for rule in component.get("rules", [])
                if rule.get("id") in used
            ]
    return json.dumps(doc, indent=2) + "\n"


def test_minimized_sarif_drops_rule_texts(tmp_path):
    rules = [
        {"id": "r1", "shortDescription": {"text": "rule text"}, "properties": {"tags": ["CWE-78"]}},
        {"id": "unused", "properties": {"tags": []}},
    ]
    result = {"ruleId": "r1", "message": {"text": "Message text from the rule"}, "locations": []}
    doc = {
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"rules": rules}}, "results": [result]}],
    }
    raw = tmp_path / "raw.sarif"
    raw.write_text(json.dumps(doc), encoding="utf-8")
    minimized = json.loads(minimized_sarif(raw))["runs"][0]
    assert minimized["tool"]["driver"]["rules"] == [
        {"id": "r1", "properties": {"tags": ["CWE-78"]}}
    ]
    assert minimized["results"][0]["message"] == {"text": "r1"}


def test_recorded_fixtures_carry_no_tool_message_texts():
    for path in sorted((REPO_ROOT / "tests" / "fixtures" / "sarif" / "real").glob("*.sarif")):
        for sarif_run in json.loads(path.read_text(encoding="utf-8"))["runs"]:
            for result in sarif_run.get("results", []):
                assert result["message"] == {"text": result["ruleId"]}, path.name


def test_analyzer_output_folder_is_separate_from_harness_files(bandit, case, tmp_path):
    runner = FakeRunner()
    results = tmp_path / "results"
    run_one(bandit, case, "vulnerable", tmp_path, results, runner)
    folder = run_dir(results, "bandit", case.id, "vulnerable")
    assert runner.outs == [folder / "tool"]
    assert (folder / "meta.json").is_file() and (folder / "log.txt").is_file()


def test_symlinked_analyzer_output_is_rejected(bandit, case, tmp_path):
    elsewhere = tmp_path / "elsewhere.sarif"
    elsewhere.write_text('{"version": "2.1.0", "runs": []}', encoding="utf-8")
    runner = SymlinkRunner({"raw.sarif": elsewhere})
    status = run_one(bandit, case, "vulnerable", tmp_path, tmp_path / "results", runner)
    assert status is Status.ERROR


def test_harness_never_writes_through_analyzer_symlinks(bandit, case, tmp_path):
    victim = tmp_path / "victim.txt"
    victim.write_text("untouched", encoding="utf-8")
    runner = SymlinkRunner({"log.txt": victim, "meta.json": victim})
    run_one(bandit, case, "vulnerable", tmp_path, tmp_path / "results", runner)
    assert victim.read_text(encoding="utf-8") == "untouched"


def fake_docker(monkeypatch, image_id: str, runner: FakeRunner) -> None:
    monkeypatch.setattr(docker, "preflight", lambda: None)
    monkeypatch.setattr(docker, "image_id", lambda image: image_id)
    monkeypatch.setattr(docker, "run_container", runner)


def run_cli(toy_cases_dir, tmp_path):
    args = ["run", "--cases-dir", str(toy_cases_dir), "--tools-dir", str(REPO_ROOT / "tools")]
    args += ["--cache-dir", str(tmp_path / "cache"), "--results-dir", str(tmp_path / "results")]
    return CliRunner().invoke(app, [*args, "--variant", "bandit"])


def test_run_stops_when_an_image_is_missing(monkeypatch, toy_cases_dir, tmp_path):
    runner = FakeRunner()
    fake_docker(monkeypatch, "", runner)
    result = run_cli(toy_cases_dir, tmp_path)
    assert result.exit_code == 2
    assert "mcpvb images" in result.output
    assert runner.calls == []


def test_run_checks_the_ground_truth_before_any_container_starts(
    monkeypatch, toy_cases_dir, tmp_path
):
    case_file = toy_cases_dir / "mcpvb-9002" / "case.yaml"
    data = yaml.safe_load(case_file.read_text(encoding="utf-8"))
    data["vulnerable"]["locations"][0]["lines"] = [20, 23]  # typo: read_note spans [19, 23]
    case_file.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    runner = FakeRunner()
    fake_docker(monkeypatch, "sha256:abc", runner)
    result = run_cli(toy_cases_dir, tmp_path)
    assert result.exit_code == 1
    assert "mcpvb-9002" in result.output and "read_note" in result.output
    assert runner.calls == []  # a wrong range would otherwise silently become a miss


def test_run_stops_on_docker_infrastructure_errors(monkeypatch, toy_cases_dir, tmp_path):
    runner = FakeRunner(exit_code=125, write_sarif=False)
    fake_docker(monkeypatch, "sha256:abc", runner)
    result = run_cli(toy_cases_dir, tmp_path)
    assert result.exit_code == 2
    assert len(runner.calls) == 1  # stops at the first failure


@pytest.mark.parametrize("exit_code", [125, 126, 127])
def test_infrastructure_errors_are_not_recorded(bandit, case, tmp_path, exit_code):
    results = tmp_path / "results"
    with pytest.raises(InfrastructureError):
        run_one(bandit, case, "vulnerable", tmp_path, results, FakeRunner(exit_code, False))
    assert read_status(results, "bandit", case.id, "vulnerable") is None


def test_unavailable_sources_are_not_recorded(bandit, case, tmp_path):
    results = tmp_path / "results"
    assert run_one(bandit, case, "fixed", None, results, FakeRunner()) is Status.UNAVAILABLE
    assert read_status(results, "bandit", case.id, "fixed") is None


def run_twice(first: dict, second: dict, bandit, case, tmp_path) -> FakeRunner:
    """Run with the first setup, then with the second; return the runner of the second run."""
    results = tmp_path / "results"
    run_one(first.get("variant", bandit), first.get("case", case), "vulnerable", tmp_path,
            results, FakeRunner(), image_id=first.get("image_id", "sha256:a"))  # fmt: skip
    runner = FakeRunner()
    run_one(second.get("variant", bandit), second.get("case", case), "vulnerable", tmp_path,
            results, runner, image_id=second.get("image_id", "sha256:a"))  # fmt: skip
    return runner


def test_unchanged_setup_reuses_the_run(bandit, case, tmp_path):
    assert run_twice({}, {}, bandit, case, tmp_path).calls == []


def test_changed_case_commit_repeats_the_run(bandit, case, tmp_path):
    moved = case.model_copy(
        update={"vulnerable": case.vulnerable.model_copy(update={"commit": "c" * 40})}
    )
    assert len(run_twice({}, {"case": moved}, bandit, case, tmp_path).calls) == 1


def test_rebuilt_image_repeats_the_run(bandit, case, tmp_path):
    assert len(run_twice({}, {"image_id": "sha256:b"}, bandit, case, tmp_path).calls) == 1


def test_changed_command_repeats_the_run(bandit, case, tmp_path):
    changed = bandit.model_copy(update={"command": [*bandit.command, "--verbose"]})
    assert len(run_twice({}, {"variant": changed}, bandit, case, tmp_path).calls) == 1


def test_manifest_keeps_the_other_variants(bandit, tmp_path):
    semgrep = load_variant(REPO_ROOT / "tools" / "semgrep-default" / "tool.yaml")
    write_manifest(tmp_path, [bandit], {bandit.image: "sha256:a"})
    write_manifest(tmp_path, [semgrep], {semgrep.image: "sha256:b"})
    manifest = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
    assert set(manifest["variants"]) == {"bandit", "semgrep-default"}
    assert manifest["variants"]["bandit"]["image_id"] == "sha256:a"


def test_corrupt_meta_counts_as_not_finished(bandit, case, tmp_path):
    results = tmp_path / "results"
    run_one(bandit, case, "vulnerable", tmp_path, results, FakeRunner())
    meta = run_dir(results, "bandit", case.id, "vulnerable") / "meta.json"
    meta.write_text('{"status": "o', encoding="utf-8")  # truncated by an interrupted write
    assert read_status(results, "bandit", case.id, "vulnerable") is None
    runner = FakeRunner()
    assert run_one(bandit, case, "vulnerable", tmp_path, results, runner) is Status.OK
    assert len(runner.calls) == 1


def test_unsupported_wins_over_missing_sources(bandit, case, tmp_path):
    ts_case = case.model_copy(update={"language": Language.TYPESCRIPT})
    status = run_one(bandit, ts_case, "vulnerable", None, tmp_path / "results", FakeRunner())
    assert status is Status.UNSUPPORTED


def test_recorded_runs_match_only_the_current_case_and_image(bandit, case):
    expected = fingerprint(bandit, case, "vulnerable", "sha256:new")
    assert matches(expected, expected)
    assert not matches(None, expected)
    assert not matches({**expected, "commit": "0" * 40}, expected)  # the case was edited
    assert not matches({**expected, "image_id": "sha256:old"}, expected)  # the image was rebuilt
    unknown_image = {**expected, "image_id": ""}  # no manifest: the image cannot be compared
    assert matches({**expected, "image_id": "sha256:old"}, unknown_image)
