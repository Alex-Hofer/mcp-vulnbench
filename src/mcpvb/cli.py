"""Command-line interface of mcp-vulnbench."""

import json
import subprocess
from pathlib import Path

import typer

from mcpvb import __version__, docker
from mcpvb.curate import python_functions
from mcpvb.fetch import FetchError, check_locations, fetch_case
from mcpvb.loc import count_kloc
from mcpvb.normalize import Finding, load_run
from mcpvb.report import write_report
from mcpvb.run import VERSIONS, InfrastructureError, run_one, write_manifest
from mcpvb.schema import Case, CaseError, load_cases
from mcpvb.score import CaseOutcome, score_case, summarize
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


RESULTS_DIR = typer.Option(
    Path("results/latest"), "--results-dir", help="Run outputs, metrics and the report."
)
FORCE_OPTION = typer.Option(False, "--force", help="Repeat runs that already finished.")


def _run_all(
    cases: list[Case], variants: list[ToolVariant], cache_dir: Path, results_dir: Path, force: bool
) -> None:
    image_ids = {v.image: docker.image_id(v.image) for v in variants}
    missing = sorted({v.image for v in variants if not image_ids[v.image]})
    if missing:
        typer.echo(f"image(s) not built: {', '.join(missing)} - run `mcpvb images` first", err=True)
        raise typer.Exit(code=2)
    write_manifest(results_dir, variants, image_ids)
    for current in cases:
        try:
            sources = fetch_case(current, cache_dir)
        except FetchError as exc:
            typer.echo(f"{current.id}: {exc}", err=True)
            sources = None
        for variant in variants:
            for version in VERSIONS:
                src = sources.for_version(version) if sources else None
                try:
                    status = run_one(
                        variant,
                        current,
                        version,
                        src,
                        results_dir,
                        docker.run_container,
                        force,
                        image_ids[variant.image],
                    )
                except InfrastructureError as exc:
                    typer.echo(f"{exc}\nstopped: fix Docker, then run again", err=True)
                    raise typer.Exit(code=2) from exc
                typer.echo(f"{variant.name:<16} {current.id} {version:<10} {status}")


@app.command()
def run(
    cases_dir: Path = CASES_DIR,
    tools_dir: Path = TOOLS_DIR,
    cache_dir: Path = CACHE_DIR,
    results_dir: Path = RESULTS_DIR,
    variant: list[str] | None = VARIANT_OPTION,
    case: list[str] | None = CASE_OPTION,
    force: bool = FORCE_OPTION,
) -> None:
    """Run the tool variants on both versions of every case."""
    cases = _load_cases_or_exit(cases_dir, case)
    variants = _load_variants_or_exit(tools_dir, variant)
    _preflight_or_exit()
    _run_all(cases, variants, cache_dir, results_dir, force)


@app.command()
def report(results_dir: Path = RESULTS_DIR) -> None:
    """Render report.md and recall.svg from metrics.json."""
    if not (results_dir / "metrics.json").is_file():
        typer.echo(f"{results_dir / 'metrics.json'} not found - run `mcpvb score` first", err=True)
        raise typer.Exit(code=1)
    typer.echo(f"wrote {write_report(results_dir)}")


PYTHON_FILE = typer.Argument(..., exists=True, dir_okay=False, help="A Python source file.")


@app.command()
def functions(path: Path = PYTHON_FILE) -> None:
    """Print 'name<TAB>start-end' for every function (to fill `lines` in case.yaml)."""
    for name, start, end in python_functions(path):
        typer.echo(f"{name}\t{start}-{end}")


def _score(
    cases: list[Case], variants: list[ToolVariant], cache_dir: Path, results_dir: Path
) -> dict:
    outcomes: list[CaseOutcome] = []
    vulnerable_findings: dict[str, list[Finding]] = {}
    kloc: dict[str, float] = {}
    for current in cases:
        try:
            kloc[current.id] = count_kloc(
                fetch_case(current, cache_dir).vulnerable, current.language
            )
        except FetchError:
            kloc[current.id] = 0.0
        for variant in variants:
            overrides = variant.cwe_overrides
            status_v, found_v = load_run(
                results_dir, variant.name, current.id, "vulnerable", overrides
            )
            status_f, found_f = load_run(results_dir, variant.name, current.id, "fixed", overrides)
            outcomes.append(score_case(variant.name, current, status_v, status_f, found_v, found_f))
            vulnerable_findings.setdefault(variant.name, []).extend(found_v)
    metrics = summarize(outcomes, vulnerable_findings, kloc)
    results_dir.mkdir(parents=True, exist_ok=True)
    (results_dir / "metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics


@app.command()
def score(
    cases_dir: Path = CASES_DIR,
    tools_dir: Path = TOOLS_DIR,
    cache_dir: Path = CACHE_DIR,
    results_dir: Path = RESULTS_DIR,
    variant: list[str] | None = VARIANT_OPTION,
    case: list[str] | None = CASE_OPTION,
) -> None:
    """Normalize the SARIF outputs and write metrics.json."""
    cases = _load_cases_or_exit(cases_dir, case)
    variants = _load_variants_or_exit(tools_dir, variant)
    _score(cases, variants, cache_dir, results_dir)
    typer.echo(f"wrote {results_dir / 'metrics.json'}")


@app.command()
def bench(
    cases_dir: Path = CASES_DIR,
    tools_dir: Path = TOOLS_DIR,
    cache_dir: Path = CACHE_DIR,
    results_dir: Path = RESULTS_DIR,
    variant: list[str] | None = VARIANT_OPTION,
    case: list[str] | None = CASE_OPTION,
    force: bool = FORCE_OPTION,
) -> None:
    """validate -> fetch -> run -> score -> report in one go."""
    cases = _load_cases_or_exit(cases_dir, case)
    variants = _load_variants_or_exit(tools_dir, variant)
    _preflight_or_exit()
    _run_all(cases, variants, cache_dir, results_dir, force)
    _score(cases, variants, cache_dir, results_dir)
    typer.echo(f"report: {write_report(results_dir)}")
