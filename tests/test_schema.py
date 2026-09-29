import copy
from pathlib import Path

import pytest
import yaml

from mcpvb.schema import CaseError, load_case, load_cases

VALID = {
    "id": "mcpvb-0001",
    "title": "Command injection in ping tool",
    "advisories": ["CVE-2025-12345"],
    "repo": "https://github.com/example/toy-mcp",
    "license": "MIT",
    "language": "python",
    "class": "command-injection",
    "cwe": "CWE-78",
    "mcp_tool": "ping",
    "vulnerable": {
        "commit": "a" * 40,
        "locations": [{"file": "server.py", "function": "ping", "lines": [10, 14]}],
    },
    "fixed": {
        "commit": "b" * 40,
        "locations": [{"file": "server.py", "function": "ping", "lines": [12, 18]}],
    },
    "source": "ghsa",
}


def write_case(root: Path, data: dict) -> Path:
    folder = root / data["id"]
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "case.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def variant(**changes) -> dict:
    data = copy.deepcopy(VALID)
    data.update(changes)
    return data


def location(file: str = "server.py", lines: tuple[int, int] = (10, 14)) -> dict:
    return {"file": file, "function": "ping", "lines": list(lines)}


def test_valid_case_loads(tmp_path):
    case = load_case(write_case(tmp_path, VALID))
    assert case.vuln_class == "command-injection"
    assert case.vulnerable.locations[0].lines == (10, 14)


@pytest.mark.parametrize(
    "changes, message",
    [
        ({"cwe": "CWE-22"}, "does not belong to class"),
        ({"license": "SSPL-1.0"}, "not OSI-approved"),
        ({"advisories": []}, "requires at least one advisory"),
        ({"advisories": ["CVE-25-1"]}, "not a CVE or GHSA id"),
        ({"id": "case-1"}, "String should match pattern"),
        ({"fixed": {"commit": "a" * 40, "locations": [location()]}}, "must differ"),
        ({"vulnerable": {"commit": "abc123", "locations": [location()]}}, "40-character"),
        ({"unknown_field": 1}, "Extra inputs are not permitted"),
    ],
)
def test_invalid_cases_are_rejected(tmp_path, changes, message):
    with pytest.raises(CaseError, match=message):
        load_case(write_case(tmp_path, variant(**changes)))


def test_line_range_must_be_ordered(tmp_path):
    bad = variant(vulnerable={"commit": "a" * 40, "locations": [location(lines=(14, 10))]})
    with pytest.raises(CaseError, match="1 <= start <= end"):
        load_case(write_case(tmp_path, bad))


def test_windows_style_paths_are_normalized(tmp_path):
    data = variant(
        vulnerable={"commit": "a" * 40, "locations": [location(file=".\\src\\server.py")]}
    )
    case = load_case(write_case(tmp_path, data))
    assert case.vulnerable.locations[0].file == "src/server.py"


def test_paths_must_stay_inside_the_repository(tmp_path):
    data = variant(vulnerable={"commit": "a" * 40, "locations": [location(file="../etc/passwd")]})
    with pytest.raises(CaseError, match="relative path inside the repository"):
        load_case(write_case(tmp_path, data))


def test_folder_must_match_id(tmp_path):
    path = write_case(tmp_path, VALID)
    renamed = path.parent.rename(tmp_path / "mcpvb-0002")
    with pytest.raises(CaseError, match="folder name"):
        load_case(renamed / "case.yaml")


def test_at_most_three_cases_per_repository(tmp_path):
    urls = [
        "https://github.com/example/toy-mcp",
        "https://github.com/Example/Toy-MCP.git",
        "https://github.com/example/toy-mcp/",
        "https://github.com/example/toy-mcp",
    ]
    for number, url in enumerate(urls, start=1):
        write_case(tmp_path, variant(id=f"mcpvb-000{number}", repo=url))
    with pytest.raises(CaseError, match="has 4 cases"):
        load_cases(tmp_path)


def test_selecting_unknown_ids_is_an_error(tmp_path):
    write_case(tmp_path, VALID)
    with pytest.raises(CaseError, match="unknown case id mcpvb-0999"):
        load_cases(tmp_path, ["mcpvb-0999"])


def test_missing_case_directory_is_an_error(tmp_path):
    with pytest.raises(CaseError, match="is not a directory"):
        load_cases(tmp_path / "nope")


@pytest.mark.parametrize("subdir", ["../..", "/etc", r"C:\Windows", "src/../../x"])
def test_subdir_must_stay_inside_the_repository(tmp_path, subdir):
    with pytest.raises(CaseError, match="relative path inside the repository"):
        load_case(write_case(tmp_path, variant(subdir=subdir)))


def test_subdir_uses_forward_slashes(tmp_path):
    assert load_case(write_case(tmp_path, variant(subdir=r"src\git"))).subdir == "src/git"


def test_drive_paths_are_rejected(tmp_path):
    data = variant(vulnerable={"commit": "a" * 40, "locations": [location(file=r"C:\secret\x.py")]})
    with pytest.raises(CaseError, match="relative path inside the repository"):
        load_case(write_case(tmp_path, data))


def test_misnamed_case_files_are_reported(tmp_path):
    folder = tmp_path / "mcpvb-0001"
    folder.mkdir()
    (folder / "case.yml").write_text(yaml.safe_dump(VALID), encoding="utf-8")
    with pytest.raises(CaseError, match="must be named case.yaml"):
        load_cases(tmp_path)


def test_case_file_in_another_encoding_is_reported(tmp_path):
    folder = tmp_path / "mcpvb-0001"
    folder.mkdir()
    (folder / "case.yaml").write_bytes("title: Größe\n".encode("cp1252"))
    with pytest.raises(CaseError, match="UTF-8"):
        load_case(folder / "case.yaml")
