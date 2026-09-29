import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcpvb import docker
from mcpvb.cli import app
from mcpvb.normalize import parse_sarif
from mcpvb.schema import Language
from mcpvb.tools import load_variant

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_preflight_explains_missing_daemon(monkeypatch):
    def daemon_down(*args, **kwargs):
        return subprocess.CompletedProcess(args[0], 1, stdout="", stderr="Cannot connect")

    monkeypatch.setattr(docker.subprocess, "run", daemon_down)
    with pytest.raises(docker.DockerUnavailable, match="start Docker Desktop"):
        docker.preflight()


def test_preflight_explains_missing_cli(monkeypatch):
    def no_cli(*args, **kwargs):
        raise FileNotFoundError("docker")

    monkeypatch.setattr(docker.subprocess, "run", no_cli)
    with pytest.raises(docker.DockerUnavailable, match="install Docker Desktop"):
        docker.preflight()


def test_container_user_can_be_overridden(monkeypatch):
    monkeypatch.setenv("MCPVB_CONTAINER_USER", "2000:2000")
    assert docker.container_user() == "2000:2000"


@pytest.mark.docker
def test_codeql_precompiled_queries_are_readable_for_the_container_user():
    image = load_variant(REPO_ROOT / "tools" / "codeql" / "tool.yaml").image
    if not docker.image_id(image):
        pytest.skip(f"image {image} not built: uv run mcpvb images --variant codeql")
    count_unreadable = "find /opt/codeql/qlpacks -name '*.qlx' ! -readable | wc -l"
    user = ["--user", docker.container_user()]
    result = subprocess.run(
        ["docker", "run", "--rm", "--network", "none", *user, image, "sh", "-c", count_unreadable],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    # Unreadable precompiled queries make CodeQL recompile every query: minutes per run.
    assert result.stdout.strip() == "0"


def test_images_stops_early_without_docker(monkeypatch):
    def unavailable():
        raise docker.DockerUnavailable("docker daemon not reachable - start Docker Desktop")

    monkeypatch.setattr(docker, "preflight", unavailable)
    result = CliRunner().invoke(app, ["images", "--tools-dir", str(REPO_ROOT / "tools")])
    assert result.exit_code == 2
    assert "start Docker Desktop" in result.output


SUPPRESSED = {
    "bandit": ("B602", "# nosec"),
    "semgrep-default": ("subprocess-shell-true", "# nosemgrep"),
}


@pytest.mark.docker
@pytest.mark.parametrize("name", sorted(SUPPRESSED))
def test_in_source_suppressions_do_not_hide_findings(name, tmp_path):
    rule, comment = SUPPRESSED[name]
    variant = load_variant(REPO_ROOT / "tools" / name / "tool.yaml")
    if not docker.image_id(variant.image):
        pytest.skip(f"image {variant.image} not built: uv run mcpvb images --variant {name}")
    source, out = tmp_path / "src", tmp_path / "out"
    source.mkdir()
    out.mkdir()
    shell_call = 'subprocess.run(f"ping {host}", shell=True)'
    code = f"import subprocess\n\n\ndef ping(host):\n    return {shell_call}  {comment}\n"
    (source / "server.py").write_text(code, encoding="utf-8")
    command = variant.render_command(Language.PYTHON)
    result = docker.run_container(variant.image, command, source, out, 600)
    assert result.exit_code == 0, result.output
    findings = parse_sarif(out / "raw.sarif", name, "mcpvb-0001", "vulnerable")
    assert any(rule in finding.rule_id and finding.line == 5 for finding in findings)


def test_containers_never_pull_images(monkeypatch, tmp_path):
    seen: dict[str, list[str]] = {}

    def fake_run(args, **kwargs):
        seen["args"] = args
        return subprocess.CompletedProcess(args, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(docker.subprocess, "run", fake_run)
    docker.run_container("mcpvb/bandit:1.9.4", ["bandit"], tmp_path, tmp_path, 10)
    args = seen["args"]
    assert "--pull" in args and args[args.index("--pull") + 1] == "never"


def test_containers_drop_privileges(monkeypatch, tmp_path):
    seen: dict[str, list[str]] = {}

    def fake_run(args, **kwargs):
        seen["args"] = args
        return subprocess.CompletedProcess(args, 0, stdout=b"", stderr=b"")

    monkeypatch.setattr(docker.subprocess, "run", fake_run)
    docker.run_container("mcpvb/bandit:1.9.4", ["bandit"], tmp_path, tmp_path, 10)
    options = seen["args"][: seen["args"].index("mcpvb/bandit:1.9.4")]
    assert options[options.index("--cap-drop") + 1] == "ALL"
    assert options[options.index("--security-opt") + 1] == "no-new-privileges"
    assert int(options[options.index("--pids-limit") + 1]) > 0
