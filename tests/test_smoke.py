import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcpvb import docker
from mcpvb.cli import app
from mcpvb.tools import load_variants

REPO_ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.docker


def test_toy_benchmark_end_to_end(toy_cases_dir, tmp_path):
    variants = load_variants(REPO_ROOT / "tools", ["bandit", "semgrep-default"])
    missing = [v.image for v in variants if not docker.image_id(v.image)]
    if missing:
        pytest.skip(f"images missing: {missing} (run: uv run mcpvb images)")
    results = tmp_path / "results"
    args = ["bench", "--cases-dir", str(toy_cases_dir), "--tools-dir", str(REPO_ROOT / "tools")]
    args += ["--cache-dir", str(tmp_path / "cache"), "--results-dir", str(results)]
    args += ["--variant", "bandit", "--variant", "semgrep-default"]
    outcome = CliRunner().invoke(app, args)
    assert outcome.exit_code == 0, outcome.output
    first = (results / "metrics.json").read_text(encoding="utf-8")
    bandit = json.loads(first)["variants"]["bandit"]["overall"]
    assert bandit["cases_ok"] == 2 and bandit["error_rate"] == 0.0
    assert bandit["detected"] >= 1  # B602 (shell=True, CWE-78) inside ping
    assert "mcpvb-9001" in (results / "report.md").read_text(encoding="utf-8")
    again = CliRunner().invoke(app, [*args, "--force"])
    assert again.exit_code == 0, again.output
    assert (results / "metrics.json").read_text(encoding="utf-8") == first  # reproducible
