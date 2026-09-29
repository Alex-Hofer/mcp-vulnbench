import re
from pathlib import Path

import pytest
import yaml

from mcpvb import docker
from mcpvb.normalize import parse_sarif
from mcpvb.schema import Language
from mcpvb.tools import load_variant

REPO_ROOT = Path(__file__).resolve().parents[1]
PACK = REPO_ROOT / "models" / "codeql" / "mcp"
FIXTURE = REPO_ROOT / "tests" / "fixtures" / "mcp-server"
TOKEN = r"(Member\[\w+\]|ReturnValue|Instance|Argument\[[\w:,]+\]|Parameter\[[\w:,]+\])"
TYPE_MARK = re.compile(r"# type: (\S+) (\S+) (\S+)")
MODEL_MARK = re.compile(r"# model: (\S+) (\S+)")
EXPECT_MARK = re.compile(r"# expect: (\S+)")
MISS_MARK = re.compile(r"# known-miss: (\S+)")
PACKAGES = {"mcp", "fastmcp"}


def model_rows() -> tuple[set[tuple[str, str]], set[tuple[str, str, str]]]:
    """The (type, path) rows of all sources and the (type1, type2, path) rows of all types."""
    sources, types = set(), set()
    for path in sorted((PACK / "models").glob("*.model.yml")):
        for extension in yaml.safe_load(path.read_text(encoding="utf-8"))["extensions"]:
            target = extension["addsTo"]
            assert target["pack"] == "codeql/python-all", path
            for row in extension["data"]:
                if target["extensible"] == "sourceModel":
                    start, access_path, kind = row
                    assert kind == "remote", row
                    sources.add((start, access_path))
                else:
                    assert target["extensible"] == "typeModel", path
                    type1, start, access_path = row
                    types.add((type1, start, access_path))
                assert re.fullmatch(rf"{TOKEN}(\.{TOKEN})*", access_path), row
    names = {type1 for type1, _, _ in types}
    assert all(start in PACKAGES | names for start, _ in sources)  # every start is known
    assert all(start in PACKAGES | names for _, start, _ in types)
    return sources, types


def fixture_marks(pattern: re.Pattern) -> list[tuple[str, int, tuple[str, ...]]]:
    marks = []
    for path in sorted(FIXTURE.glob("*.py")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if match := pattern.search(line):
                marks.append((path.name, number, match.groups()))
    return marks


def test_the_pack_declares_its_data_extensions():
    pack = yaml.safe_load((PACK / "qlpack.yml").read_text(encoding="utf-8"))
    assert pack["name"] == "mcpvb/mcp-models" and pack["library"] is True
    assert pack["extensionTargets"] == {"codeql/python-all": "*"}
    assert pack["dataExtensions"] == ["models/*.model.yml"]


def test_every_model_row_has_a_fixture_handler():
    sources, types = model_rows()
    # a typo in a row or in a marker breaks one of these equalities
    assert {groups for _, _, groups in fixture_marks(MODEL_MARK)} == sources
    assert {groups for _, _, groups in fixture_marks(TYPE_MARK)} == types


def test_codeql_mcp_differs_from_codeql_only_in_the_model_pack():
    base = load_variant(REPO_ROOT / "tools" / "codeql" / "tool.yaml")
    mcp = load_variant(REPO_ROOT / "tools" / "codeql-mcp" / "tool.yaml")
    extra = ["--additional-packs=/opt/mcpvb/models", "--model-packs=mcpvb/mcp-models"]
    assert mcp.command == base.command + extra
    assert mcp.base_image == base.image
    assert (mcp.version, mcp.timeout_s) == (base.version, base.timeout_s)


@pytest.mark.docker
def test_mcp_models_turn_mcp_input_into_remote_sources(tmp_path):
    names = ("codeql", "codeql-mcp")
    variants = [load_variant(REPO_ROOT / "tools" / n / "tool.yaml") for n in names]
    missing = [v.image for v in variants if not docker.image_id(v.image)]
    if missing:
        pytest.skip(f"images missing: {missing} (uv run mcpvb images --variant codeql-mcp)")
    expected = {(name, line, groups[0]) for name, line, groups in fixture_marks(EXPECT_MARK)}
    known_misses = {(name, line, groups[0]) for name, line, groups in fixture_marks(MISS_MARK)}
    found = {}
    for variant in variants:
        out = tmp_path / variant.name
        out.mkdir()
        result = docker.run_container(
            variant.image, variant.render_command(Language.PYTHON), FIXTURE, out, 1800
        )
        assert result.exit_code == 0, result.output[-2000:]
        findings = parse_sarif(out / "raw.sarif", variant.name, "fixture", "vulnerable")
        found[variant.name] = {(f.file, f.line, f.rule_id) for f in findings}
    assert expected.isdisjoint(found["codeql"])  # without the models: no source, no alert
    assert expected <= found["codeql-mcp"], sorted(expected - found["codeql-mcp"])
    # documented limits of Models-as-Data: if CodeQL starts finding these, update the docs
    assert known_misses.isdisjoint(found["codeql-mcp"]), sorted(known_misses & found["codeql-mcp"])
