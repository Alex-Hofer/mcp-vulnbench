"""Command-line interface of mcp-vulnbench."""

import subprocess
from pathlib import Path

import typer

from mcpvb import __version__, docker
from mcpvb.fetch import FetchError, check_locations, fetch_case
from mcpvb.schema import Case, CaseError, load_cases
from mcpvb.tools import ToolError, ToolVariant, load_variants

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


CACHE_DIR = typer.Option(Path(".cache"), "--cache-dir", help="Cache for repositories and sources.")


@app.command()
def fetch(
    cases_dir: Path = CASES_DIR,
    cache_dir: Path = CACHE_DIR,
    case: list[str] | None = CASE_OPTION,
) -> None:
    """Download both versions of every case and check the ground-truth locations."""
    cases = _load_cases_or_exit(cases_dir, case)
    problems: list[str] = []
    for current in cases:
        try:
            sources = fetch_case(current, cache_dir)
        except FetchError as exc:
            problems.append(f"{current.id}: {exc}")
            continue
        problems += check_locations(current, sources)
    for problem in problems:
        typer.echo(problem, err=True)
    if problems:
        raise typer.Exit(code=1)
    typer.echo(f"{len(cases)} case(s) fetched into {cache_dir}")


TOOLS_DIR = typer.Option(Path("tools"), "--tools-dir", help="Directory with <variant>/tool.yaml.")
VARIANT_OPTION = typer.Option(None, "--variant", help="Only this tool variant (repeatable).")


def _load_variants_or_exit(tools_dir: Path, names: list[str] | None = None) -> list[ToolVariant]:
    try:
        return load_variants(tools_dir, names)
    except ToolError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc


def _preflight_or_exit() -> None:
    try:
        docker.preflight()
    except docker.DockerUnavailable as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from exc


@app.command()
def images(tools_dir: Path = TOOLS_DIR, variant: list[str] | None = VARIANT_OPTION) -> None:
    """Build the Docker images of the tool variants locally (never push them)."""
    variants = _load_variants_or_exit(tools_dir, variant)
    _preflight_or_exit()
    for image, dockerfile in dict.fromkeys((v.image, v.dockerfile) for v in variants):
        typer.echo(f"building {image} from {dockerfile}")
        try:
            docker.build(image, tools_dir.resolve().parent / dockerfile)
        except subprocess.CalledProcessError as exc:
            typer.echo(f"building {image} failed (exit code {exc.returncode})", err=True)
            raise typer.Exit(code=1) from exc
