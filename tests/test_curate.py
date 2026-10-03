from pathlib import Path

import pytest

from mcpvb.curate import ANONYMOUS, functions, python_functions, script_functions

TOY_SERVER = Path(__file__).resolve().parents[1] / "examples" / "toy-server"

SCRIPT = """\
import { exec } from "child_process";

export async function ping(host: string): Promise<string> {
  return host;
}

export const readNote = async (name: string) => {
  return name;
};

class Server {
  @Tool({ name: "run" })
  @Logged()
  async run(command: string) {
    return command;
  }

  handle = async (req: Request) => req;
}

const tools = {
  remove(target: string) { return target; },
  fetch: async (url: string) => url,
  "read-file": function (path: string) { return path; },
};

server.tool("shell", { cmd: z.string() }, async ({ cmd }) => {
  function inner(x: string) { return x; }
  return inner(cmd);
});

function overloaded(a: string): string;
function overloaded(a: any) { return a; }

module.exports.legacy = function (x) { return x; };
"""


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


def test_script_functions_name_declarations_fields_and_callbacks(tmp_path):
    path = tmp_path / "server.ts"
    path.write_text(SCRIPT, encoding="utf-8")
    assert script_functions(path) == [
        ("ping", 3, 5),
        ("readNote", 7, 9),
        ("Server.run", 12, 16),  # from the first decorator
        ("Server.handle", 18, 18),
        ("remove", 22, 22),
        ("fetch", 23, 23),
        ("read-file", 24, 24),
        (ANONYMOUS, 27, 30),  # the callback passed to server.tool
        ("inner", 28, 28),
        ("overloaded", 33, 33),  # the overload signature has no body and is not listed
        ("legacy", 35, 35),
    ]


@pytest.mark.parametrize("suffix", [".js", ".mjs", ".cjs", ".jsx", ".tsx", ".mts", ".cts"])
def test_script_functions_cover_every_script_suffix(tmp_path, suffix):
    path = tmp_path / f"server{suffix}"
    path.write_text("export function ping(host) {\n  return host;\n}\n", encoding="utf-8")
    assert functions(path) == [("ping", 1, 3)]


@pytest.mark.parametrize("encoding", ["utf-8-sig", "utf-16"])
def test_script_functions_are_found_in_bom_and_utf16_files(tmp_path, encoding):
    path = tmp_path / "server.ts"
    path.write_text("function ping() {\n  return 1;\n}\n", encoding=encoding)
    assert script_functions(path) == [("ping", 1, 3)]


def test_script_functions_survive_a_syntax_error(tmp_path):
    path = tmp_path / "server.ts"
    path.write_text("function ok() { return 1; }\nconst broken = = ;\n", encoding="utf-8")
    assert ("ok", 1, 1) in script_functions(path)


def test_functions_rejects_other_file_types(tmp_path):
    path = tmp_path / "notes.md"
    path.write_text("# notes\n", encoding="utf-8")
    with pytest.raises(ValueError, match="notes.md"):
        functions(path)


TOY_SERVER_TS = Path(__file__).resolve().parents[1] / "examples" / "toy-server-ts"


def test_toy_ts_server_ranges_match_the_ground_truth():
    assert script_functions(TOY_SERVER_TS / "vulnerable" / "server.ts") == [
        ("pingHost", 11, 13),
        (ANONYMOUS, 15, 17),
        (ANONYMOUS, 19, 22),
    ]
    assert script_functions(TOY_SERVER_TS / "fixed" / "server.ts") == [
        ("pingHost", 13, 18),
        (ANONYMOUS, 20, 22),
        (ANONYMOUS, 24, 31),
    ]
