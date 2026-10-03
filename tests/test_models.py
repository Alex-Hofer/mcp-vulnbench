import re
from dataclasses import dataclass
from pathlib import Path

import pytest
import yaml

from mcpvb import docker
from mcpvb.normalize import parse_sarif
from mcpvb.schema import Language
from mcpvb.tools import load_variant

REPO_ROOT = Path(__file__).resolve().parents[1]
PACKS = REPO_ROOT / "models" / "codeql"
FIXTURES = REPO_ROOT / "tests" / "fixtures"
TOKEN = (
    r"(Member\[[\w,]+\]|ReturnValue|Instance|Subclass|Awaited|Fuzzy"
    r"|Argument\[[\w:,.]+\]|Parameter\[[\w:,.]+\])"
)
Mark = tuple[str, int, tuple[str, ...]]
Rows = set[tuple[str, ...]]


@dataclass(frozen=True)
class Suite:
    """The model pack for one CodeQL language and the fixture server that exercises its rows."""

    pack: str  # folder under models/codeql
    name: str
    target: str  # the library pack the rows extend
    language: Language  # what the fixture is analyzed as
    fixture: Path
    glob: str
    comment: str  # starts a marker comment in the fixture
    packages: frozenset[str]  # the import names rows start from, written as in the rows

    def marks(self, kind: str, values: int) -> list[Mark]:
        """The fixture's markers `<comment> <kind>: <value> ...`; a missing last value is ''."""
        tail = r" (\S+)" * (values - 1) + r"(?: (\S+))?" if values > 1 else r" (\S+)"
        pattern = re.compile(rf"{re.escape(self.comment)} {kind}:{tail}")
        marks = []
        for path in sorted(self.fixture.glob(self.glob)):
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                if match := pattern.search(line):
                    groups = tuple(group or "" for group in match.groups())
                    marks.append((path.name, number, groups))
        return marks

    def knows(self, start: str, names: set[str]) -> bool:
        """A row starts from a type a typeModel row defines, a package, or a type of a package."""
        package = start.rsplit("'.", 1)[0] + "'" if "'." in start else start
        return start in names or package in self.packages


SUITES = {
    "python": Suite(
        pack="mcp",
        name="mcpvb/mcp-models",
        target="codeql/python-all",
        language=Language.PYTHON,
        fixture=FIXTURES / "mcp-server",
        glob="*.py",
        comment="#",
        packages=frozenset({"mcp", "fastmcp"}),
    ),
    "javascript": Suite(
        pack="mcp-js",
        name="mcpvb/mcp-models-js",
        target="codeql/javascript-all",
        language=Language.TYPESCRIPT,
        fixture=FIXTURES / "mcp-server-ts",
        glob="*.ts",
        comment="//",
        packages=frozenset(
            {
                "'@modelcontextprotocol/sdk/server/mcp.js'",
                "@modelcontextprotocol/sdk/server/mcp",
                "'@modelcontextprotocol/sdk/server/index.js'",
                "@modelcontextprotocol/sdk/server/index",
                "@modelcontextprotocol/server",
                "fastmcp",
                "zod",
                "zod/v3",
                "zod/v4",
            }
        ),
    ),
}
suites = pytest.mark.parametrize("suite", SUITES.values(), ids=SUITES.keys())


def model_rows(suite: Suite) -> tuple[Rows, Rows, Rows]:
    """The rows of the pack: sources, types and summaries.

    A source is (type, path), a type (type1, type2, path) and a summary, which carries taint
    through a call, (type, path, input, output).
    """
    sources, types, summaries = set(), set(), set()
    for path in sorted((PACKS / suite.pack / "models").glob("*.model.yml")):
        for extension in yaml.safe_load(path.read_text(encoding="utf-8"))["extensions"]:
            target = extension["addsTo"]
            # rows for a library pack that is not part of the analysis make CodeQL fail
            assert target["pack"] == suite.target, path
            for row in extension["data"]:
                if target["extensible"] == "sourceModel":
                    start, access_path, kind = row
                    assert kind == "remote" and access_path, row
                    sources.add((start, access_path))
                    paths = [access_path]
                elif target["extensible"] == "summaryModel":
                    start, access_path, taken, given, kind = row
                    assert kind == "taint" and access_path, row
                    summaries.add((start, access_path, taken, given))
                    paths = [access_path, taken, given]
                else:
                    assert target["extensible"] == "typeModel", path
                    type1, start, access_path = row
                    types.add((type1, start, access_path))
                    paths = [access_path]
                # the empty path of a typeModel row is the type itself
                assert all(re.fullmatch(rf"({TOKEN}(\.{TOKEN})*)?", p) for p in paths), row
    names = {type1 for type1, _, _ in types}
    starts = {row[0] for row in sources | summaries} | {start for _, start, _ in types}
    assert not [start for start in starts if not suite.knows(start, names)]  # every start is known
    return sources, types, summaries


@suites
def test_the_pack_declares_its_data_extensions(suite):
    pack = yaml.safe_load((PACKS / suite.pack / "qlpack.yml").read_text(encoding="utf-8"))
    assert pack["name"] == suite.name and pack["library"] is True
    assert pack["extensionTargets"] == {suite.target: "*"}
    assert pack["dataExtensions"] == ["models/*.model.yml"]


@suites
def test_every_model_row_has_a_fixture_handler(suite):
    sources, types, summaries = model_rows(suite)
    assert sources and types
    # a typo in a row or in a marker breaks one of these equalities
    assert {groups for _, _, groups in suite.marks("model", 2)} == sources
    assert {groups for _, _, groups in suite.marks("type", 3)} == types
    assert {groups for _, _, groups in suite.marks("summary", 4)} == summaries


def test_javascript_package_names_with_a_dot_are_quoted():
    # CodeQL reads the text after the first unquoted dot as a type name: an unquoted
    # "@modelcontextprotocol/sdk/server/mcp.js" would be the type "js" and match nothing
    for package in SUITES["javascript"].packages:
        assert "." not in package or re.fullmatch(r"'[^']+'", package), package


def test_codeql_mcp_differs_from_codeql_only_in_the_model_pack():
    base = load_variant(REPO_ROOT / "tools" / "codeql" / "tool.yaml")
    mcp = load_variant(REPO_ROOT / "tools" / "codeql-mcp" / "tool.yaml")
    extra = ["--additional-packs=/opt/mcpvb/models"]
    extra += [f"--model-packs={suite.name}" for suite in SUITES.values()]
    assert mcp.command == base.command + extra
    assert mcp.base_image == base.image
    assert (mcp.version, mcp.timeout_s, mcp.languages) == (
        base.version,
        base.timeout_s,
        base.languages,
    )


@pytest.mark.docker
@suites
def test_mcp_models_turn_mcp_input_into_remote_sources(suite, tmp_path):
    names = ("codeql", "codeql-mcp")
    variants = [load_variant(REPO_ROOT / "tools" / n / "tool.yaml") for n in names]
    missing = [v.image for v in variants if not docker.image_id(v.image)]
    if missing:
        pytest.skip(f"images missing: {missing} (uv run mcpvb images --variant codeql-mcp)")
    expected = {(name, line, groups[0]) for name, line, groups in suite.marks("expect", 1)}
    known_misses = {(name, line, groups[0]) for name, line, groups in suite.marks("known-miss", 1)}
    assert expected and known_misses
    found = {}
    for variant in variants:
        out = tmp_path / variant.name
        out.mkdir()
        result = docker.run_container(
            variant.image, variant.render_command(suite.language), suite.fixture, out, 1800
        )
        assert result.exit_code == 0, result.output[-2000:]
        findings = parse_sarif(out / "raw.sarif", variant.name, "fixture", "vulnerable")
        found[variant.name] = {(f.file, f.line, f.rule_id) for f in findings}
    assert expected.isdisjoint(found["codeql"])  # without the models: no source, no alert
    assert expected <= found["codeql-mcp"], sorted(expected - found["codeql-mcp"])
    # documented limits of Models-as-Data: if CodeQL starts finding these, update the docs
    assert known_misses.isdisjoint(found["codeql-mcp"]), sorted(known_misses & found["codeql-mcp"])
