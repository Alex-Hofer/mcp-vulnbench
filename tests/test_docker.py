import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcpvb import docker
from mcpvb.cli import app

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


def test_images_stops_early_without_docker(monkeypatch):
    def unavailable():
        raise docker.DockerUnavailable("docker daemon not reachable - start Docker Desktop")

    monkeypatch.setattr(docker, "preflight", unavailable)
    result = CliRunner().invoke(app, ["images", "--tools-dir", str(REPO_ROOT / "tools")])
    assert result.exit_code == 2
    assert "start Docker Desktop" in result.output
