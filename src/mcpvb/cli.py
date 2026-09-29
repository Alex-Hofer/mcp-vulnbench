"""Command-line interface of mcp-vulnbench."""

from pathlib import Path

import typer

from mcpvb import __version__
from mcpvb.schema import Case, CaseError, load_cases

app = typer.Typer(
    help="Benchmark static analyzers on real MCP-server vulnerabilities.",
    no_args_is_help=True,
)


def _show_version(value: bool) -> None:
    if value:
        typer.echo(f"mcpvb {__version__}")
        raise typer.Exit()


VERSION_OPTION = typer.Option(
    False, "--version", callback=_show_version, is_eager=True, help="Show the version and exit."
)


@app.callback()
def main(version: bool = VERSION_OPTION) -> None:
    """Benchmark static analyzers on real MCP-server vulnerabilities."""


CASES_DIR = typer.Option(Path("cases"), "--cases-dir", help="Directory with <id>/case.yaml files.")
CASE_OPTION = typer.Option(None, "--case", help="Only this case id (repeatable).")


def _load_cases_or_exit(cases_dir: Path, ids: list[str] | None = None) -> list[Case]:
    try:
        return load_cases(cases_dir, ids)
    except CaseError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc


@app.command()
def validate(cases_dir: Path = CASES_DIR) -> None:
    """Check all case files against the schema and the cross-case rules."""
    cases = _load_cases_or_exit(cases_dir)
    typer.echo(f"{len(cases)} case(s) valid")
