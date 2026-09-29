import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcpvb import docker
from mcpvb.cli import app
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
