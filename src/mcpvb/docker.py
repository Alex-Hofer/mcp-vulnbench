"""Thin wrapper around the docker CLI (kept small so the orchestration can use a fake)."""

from __future__ import annotations

import os
import subprocess
import time
import uuid
from dataclasses import dataclass
from pathlib import Path


class DockerUnavailable(Exception):
    """The docker CLI is missing or the daemon does not answer."""


@dataclass(frozen=True)
class ContainerResult:
    exit_code: int | None  # None: the timeout was hit and the container was killed
    output: str
    duration_s: float


def preflight() -> None:
    """Fail early with a helpful message instead of turning every run into an error."""
    try:
        result = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except FileNotFoundError as exc:
        raise DockerUnavailable("docker CLI not found - install Docker Desktop") from exc
    except subprocess.TimeoutExpired as exc:
        message = "docker did not answer in 30 s - is Docker Desktop running?"
        raise DockerUnavailable(message) from exc
    if result.returncode != 0:
        detail = result.stderr.strip()
        raise DockerUnavailable(f"docker daemon not reachable - start Docker Desktop ({detail})")


def build(image: str, context: Path) -> None:
    subprocess.run(["docker", "build", "--tag", image, str(context)], check=True)


def image_id(image: str) -> str:
    """Local image id ('' if the image is not built): recorded in the manifest."""
    result = subprocess.run(
        ["docker", "image", "inspect", "--format", "{{.Id}}", image],
        capture_output=True,
        text=True,
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def container_user() -> str:
    """Host user on Linux/macOS (bind mounts stay writable), 1000:1000 on Windows."""
    if override := os.environ.get("MCPVB_CONTAINER_USER"):
        return override
    if hasattr(os, "getuid"):
        return f"{os.getuid()}:{os.getgid()}"
    return "1000:1000"


def _text(stream: bytes | str | None) -> str:
    if stream is None:
        return ""
    return stream.decode("utf-8", errors="replace") if isinstance(stream, bytes) else stream


def run_container(
    image: str, command: list[str], src: Path, out: Path, timeout_s: int
) -> ContainerResult:
    """Run `command` in `image`: sources read-only at /src, `out` at /out, no network."""
    name = f"mcpvb-{uuid.uuid4().hex[:12]}"
    isolation = ["--network", "none", "--cpus", "2", "--memory", "4g", "--user", container_user()]
    mounts = [
        "--mount",
        f"type=bind,source={src.resolve()},target=/src,readonly",
        "--mount",
        f"type=bind,source={out.resolve()},target=/out",
    ]
    args = [
        "docker",
        "run",
        "--rm",
        "--name",
        name,
        *isolation,
        "--env",
        "HOME=/tmp",
        *mounts,
        "--workdir",
        "/src",
        image,
        *command,
    ]
    start = time.monotonic()
    try:
        completed = subprocess.run(args, capture_output=True, timeout=timeout_s)
    except subprocess.TimeoutExpired as exc:
        subprocess.run(["docker", "kill", name], capture_output=True)
        output = _text(exc.stdout) + _text(exc.stderr)
        return ContainerResult(None, output, time.monotonic() - start)
    output = _text(completed.stdout) + _text(completed.stderr)
    return ContainerResult(completed.returncode, output, time.monotonic() - start)
