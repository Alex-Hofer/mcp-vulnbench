from pathlib import Path

from mcpvb.tools import load_variants

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCKER = REPO_ROOT / "docker"


def dockerfile(name: str) -> str:
    return (DOCKER / name / "Dockerfile").read_text(encoding="utf-8")


def test_base_images_are_pinned_by_digest():
    for path in sorted(DOCKER.glob("*/Dockerfile")):
        bases = [
            line
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.startswith("FROM ")
        ]
        assert bases and all("@sha256:" in line for line in bases), path


def test_downloads_are_checksum_verified():
    assert "sha256sum -c" in dockerfile("codeql")
    assert "ADD --checksum=sha256:" in dockerfile("semgrep")


def test_bandit_dependencies_are_pinned():
    assert "-c /tmp/constraints.txt" in dockerfile("bandit")
    pins = (DOCKER / "bandit" / "constraints.txt").read_text(encoding="utf-8").split()
    assert pins and all("==" in pin for pin in pins)


def test_every_variant_image_is_pinned_or_builds_on_a_declared_variant_image():
    variants = load_variants(REPO_ROOT / "tools")
    images = {v.image for v in variants}
    for v in variants:
        lines = (REPO_ROOT / v.dockerfile / "Dockerfile").read_text(encoding="utf-8").splitlines()
        froms = [line.split()[1] for line in lines if line.startswith("FROM ")]
        if v.base_image:
            assert froms == [v.base_image] and v.base_image in images, v.name
        else:
            assert froms and all("@sha256:" in base for base in froms), v.name


def test_codeql_mcp_refuses_a_base_that_ignores_analyze_options():
    dockerfile = (REPO_ROOT / "models" / "codeql" / "Dockerfile").read_text(encoding="utf-8")
    script = (DOCKER / "codeql" / "run-codeql.sh").read_text(encoding="utf-8")
    assert "grep -q 'shift 3' /usr/local/bin/run-codeql.sh" in dockerfile
    assert "shift 3" in script and '"$@"' in script  # the marker the check relies on


def test_node_for_the_typescript_extractor_is_pinned_and_verified():
    codeql = dockerfile("codeql")
    assert "ARG NODE_VERSION=" in codeql and "ARG NODE_SHA256=" in codeql
    assert "node-v${NODE_VERSION}-linux-x64.tar.gz" in codeql
    assert '"${NODE_SHA256}  /tmp/node.tar.gz" | sha256sum -c -' in codeql


def test_semgrep_rules_cover_javascript_and_typescript_and_keep_mcp_rules_apart():
    semgrep = dockerfile("semgrep")
    default_loop = next(line for line in semgrep.splitlines() if "/rules/default/$dir" in line)
    for rules in ("python/*/security", "javascript/*/security", "typescript/*/security"):
        assert rules in default_loop, rules
    assert "typescript/mcp/*) continue" in default_loop  # MCP rules belong to semgrep-mcp only
    mcp_loop = next(line for line in semgrep.splitlines() if "/rules/mcp/$dir" in line)
    assert "ai/ai-best-practices/mcp-*" in mcp_loop and "typescript/mcp/security" in mcp_loop
