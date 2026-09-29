from pathlib import Path

import pytest

from mcpvb.curate import python_functions

TOY_SERVER = Path(__file__).resolve().parents[1] / "examples" / "toy-server"


def test_toy_server_ranges_match_the_ground_truth():
    assert python_functions(TOY_SERVER / "vulnerable" / "server.py") == [
        ("ping", 12, 16),
        ("read_note", 19, 23),
    ]
    assert python_functions(TOY_SERVER / "fixed" / "server.py") == [
        ("ping", 14, 20),
        ("read_note", 23, 29),
    ]


def test_methods_are_qualified_and_start_at_the_first_decorator(tmp_path):
    source = (
        "class Server:\n"
        "    @staticmethod\n"
        "    @cached\n"
        "    def handle(request):\n"
        "        return request\n"
        "\n"
        "\n"
        "async def main():\n"
        "    pass\n"
    )
    path = tmp_path / "server.py"
    path.write_text(source, encoding="utf-8")
    assert python_functions(path) == [("Server.handle", 2, 5), ("main", 8, 9)]


@pytest.mark.parametrize("encoding", ["utf-8-sig", "utf-16"])
def test_functions_are_found_in_bom_and_utf16_files(tmp_path, encoding):
    path = tmp_path / "server.py"
    path.write_text("def ping():\n    return 1\n", encoding=encoding)
    assert python_functions(path) == [("ping", 1, 2)]
