"""Helpers for curating cases: function ranges in source files (for `lines` in case.yaml)."""

from __future__ import annotations

import ast
import codecs
from pathlib import Path

import tree_sitter_javascript
import tree_sitter_typescript
from tree_sitter import Language, Node, Parser

_GRAMMARS = {
    ".ts": tree_sitter_typescript.language_typescript,
    ".mts": tree_sitter_typescript.language_typescript,
    ".cts": tree_sitter_typescript.language_typescript,
    ".tsx": tree_sitter_typescript.language_tsx,
    ".js": tree_sitter_javascript.language,
    ".mjs": tree_sitter_javascript.language,
    ".cjs": tree_sitter_javascript.language,
    ".jsx": tree_sitter_javascript.language,
}
SCRIPT_SUFFIXES = frozenset(_GRAMMARS)
ANONYMOUS = "<anonymous>"  # a function without a name, e.g. a callback passed to server.tool()
_FUNCTIONS = {
    "function_declaration",
    "generator_function_declaration",
    "function_expression",
    "generator_function",
    "arrow_function",
    "method_definition",
}
_CLASSES = {"class_declaration", "abstract_class_declaration", "class"}
_NAMES = {"identifier", "property_identifier", "private_property_identifier", "type_identifier"}
# Where a function without its own name gets one: parent node type -> (name field, value field).
_NAMED_BY = {
    "variable_declarator": ("name", "value"),
    "public_field_definition": ("name", "value"),
    "field_definition": ("property", "value"),
    "pair": ("key", "value"),
    "assignment_expression": ("left", "right"),
}


def _source(path: Path) -> str | bytes:
    """Source for ast.parse: bytes keep PEP 263 cookies and a UTF-8 BOM working; UTF-16
    (what redirecting `git show` in Windows PowerShell 5 produces) is decoded first."""
    data = path.read_bytes()
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return data.decode("utf-16")
    return data


def python_functions(path: Path) -> list[tuple[str, int, int]]:
    """(qualified name, first line including decorators, last line) of every function."""
    tree = ast.parse(_source(path), filename=str(path))
    found: list[tuple[str, int, int]] = []

    def visit(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start = min([child.lineno, *(d.lineno for d in child.decorator_list)])
                found.append((f"{prefix}{child.name}", start, child.end_lineno or child.lineno))
                visit(child, f"{prefix}{child.name}.")
            elif isinstance(child, ast.ClassDef):
                visit(child, f"{prefix}{child.name}.")
            else:
                visit(child, prefix)

    visit(tree, "")
    return found


def _label(node: Node | None) -> str | None:
    """The text of a name node; None for patterns, computed keys and other non-names."""
    if node is not None and node.type == "member_expression":  # exports.name = function () {}
        node = node.child_by_field_name("property")
    if node is None or node.text is None:
        return None
    text = node.text.decode("utf-8", errors="replace")
    if node.type == "string":
        return text.strip("\"'`")
    return text if node.type in _NAMES else None


def _function_name(node: Node) -> str | None:
    """Its own name, or the variable, property or class field the function is assigned to."""
    own = _label(node.child_by_field_name("name"))
    parent = node.parent
    if own or parent is None or parent.type not in _NAMED_BY:
        return own
    name_field, value_field = _NAMED_BY[parent.type]
    value = parent.child_by_field_name(value_field)
    if value is None or value.id != node.id:
        return None
    return _label(parent.child_by_field_name(name_field))


def _first_line(node: Node) -> int:
    first = node
    while first.prev_sibling is not None and first.prev_sibling.type == "decorator":
        first = first.prev_sibling
    return first.start_point[0] + 1


def script_functions(path: Path) -> list[tuple[str, int, int]]:
    """(name, first line including decorators, last line) of every function-like node of a
    TypeScript or JavaScript file.

    Class members are qualified with the class. A function without a name, such as a callback
    passed to `server.tool()`, is listed as <anonymous>. The parser tolerates syntax errors, so
    the functions around a construct it does not know are still found.
    """
    source = _source(path)
    data = source.encode("utf-8") if isinstance(source, str) else source
    parser = Parser(Language(_GRAMMARS[path.suffix]()))
    tree = parser.parse(data.removeprefix(codecs.BOM_UTF8))
    found: list[tuple[str, int, int]] = []

    def visit(node: Node, prefix: str) -> None:
        for child in node.children:
            if child.type in _FUNCTIONS:
                name = _function_name(child)
                label = f"{prefix}{name}" if name else ANONYMOUS
                found.append((label, _first_line(child), child.end_point[0] + 1))
                visit(child, "")  # nested functions are mostly callbacks: listed by their own name
            elif child.type in _CLASSES:
                name = _label(child.child_by_field_name("name"))
                visit(child, f"{prefix}{name}." if name else prefix)
            else:
                visit(child, prefix)

    visit(tree.root_node, "")
    return found


def functions(path: Path) -> list[tuple[str, int, int]]:
    """Function ranges of a Python, TypeScript or JavaScript file."""
    if path.suffix == ".py":
        return python_functions(path)
    if path.suffix in SCRIPT_SUFFIXES:
        return script_functions(path)
    raise ValueError(f"{path.name}: function ranges exist for Python, TypeScript and JavaScript")
