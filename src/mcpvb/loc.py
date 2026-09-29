"""Lines of code per case (denominator of the alarm-volume metric)."""

from pathlib import Path

from mcpvb.schema import Language

_JS_TS = {".ts", ".tsx", ".js", ".mjs", ".cjs"}
EXTENSIONS: dict[Language, set[str]] = {
    Language.PYTHON: {".py"},
    Language.TYPESCRIPT: _JS_TS,
    Language.JAVASCRIPT: _JS_TS,
}
SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "dist",
    "build",
    "__pycache__",
    "test",
    "tests",
    "third_party",
    "vendor",
}


def count_kloc(root: Path, language: Language) -> float:
    """Non-blank lines of the case language in thousands, without vendor, build and test folders."""
    total = 0
    for path in root.rglob("*"):
        if path.suffix not in EXTENSIONS[language] or not path.is_file():
            continue
        if SKIP_DIRS.intersection(path.relative_to(root).parts[:-1]):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        total += sum(1 for line in text.splitlines() if line.strip())
    return total / 1000
