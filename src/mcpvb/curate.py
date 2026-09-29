"""Helpers for curating cases: function ranges in Python files (for `lines` in case.yaml)."""

from __future__ import annotations

import ast
import codecs
from pathlib import Path


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
