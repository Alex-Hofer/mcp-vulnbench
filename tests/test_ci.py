import re
from pathlib import Path

import yaml

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml"


def load_workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def test_actions_are_pinned_to_commit_shas():
    jobs = load_workflow()["jobs"].values()
    uses = [step["uses"] for job in jobs for step in job["steps"] if "uses" in step]
    assert uses
    for ref in uses:
        # Floating tags can vanish or move (setup-uv has no v10 tag); a SHA always resolves.
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", ref), ref


def test_workflow_token_is_read_only():
    assert load_workflow()["permissions"] == {"contents": "read"}


def test_local_python_matches_ci():
    local = (WORKFLOW.parents[2] / ".python-version").read_text(encoding="utf-8").strip()
    jobs = load_workflow()["jobs"].values()
    steps = [step for job in jobs for step in job["steps"] if "setup-uv" in step.get("uses", "")]
    assert {step["with"]["python-version"] for step in steps} == {local}
