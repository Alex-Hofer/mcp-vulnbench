"""Command-line interface of mcp-vulnbench."""

import json
import subprocess
from collections import Counter
from pathlib import Path

import typer

from mcpvb import __version__, docker
from mcpvb.curate import python_functions
from mcpvb.fetch import CaseSources, FetchError, check_locations, fetch_case
from mcpvb.loc import count_kloc
from mcpvb.normalize import Finding, load_run
from mcpvb.report import write_report
from mcpvb.run import (
    VERSIONS,
    InfrastructureError,
    fingerprint,
    manifest_image_ids,
    matches,
    read_meta,
    run_one,
    write_manifest,
)
from mcpvb.schema import Case, CaseError, Split, load_cases
from mcpvb.score import CaseOutcome, score_case, summarize
from mcpvb.split import assign_splits, repositories_in_both_halves, write_split
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
TOOLS_DIR = typer.Option(Path("tools"), "--tools-dir", help="Directory with <variant>/tool.yaml.")
SPLIT_OPTION = typer.Option(None, "--split", help="Only the cases of this half (dev or test).")


def _load_cases_or_exit(
    cases_dir: Path, ids: list[str] | None = None, split: Split | None = None
) -> list[Case]:
    try:
        cases = load_cases(cases_dir, ids)
    except CaseError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    return [case for case in cases if split is None or case.split == split]


@app.command()
def validate(cases_dir: Path = CASES_DIR, tools_dir: Path = TOOLS_DIR) -> None:
    """Check all case files and tool variants."""
    problems: list[str] = []
    try:
        cases = load_cases(cases_dir)
        unsplit = [case.id for case in cases if case.split is None]
        if unsplit:
            problems.append(
                f"{len(unsplit)} case(s) without a split: {', '.join(unsplit)} - run `mcpvb split`"
            )
        for key in repositories_in_both_halves(cases):
            problems.append(f"cases of {key} are in both halves; a repository belongs to one half")
    except CaseError as exc:
        problems.append(str(exc))
    try:
        variants = load_variants(tools_dir)
    except ToolError as exc:
        problems.append(str(exc))
    if problems:
        typer.echo("\n".join(problems), err=True)
        raise typer.Exit(code=1)
    typer.echo(f"{len(cases)} case(s) valid")
    typer.echo(f"{len(variants)} tool variant(s) valid")


@app.command("split")
def split_cases(cases_dir: Path = CASES_DIR) -> None:
    """Assign every case without a split to the dev or the test half (stratified, seeded)."""
    cases = _load_cases_or_exit(cases_dir)
    assigned = assign_splits(cases)
    try:
        for case_id, half in assigned.items():
            write_split(cases_dir / case_id / "case.yaml", half)
    except CaseError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    totals = Counter(assigned.values())
    typer.echo(
        f"assigned {len(assigned)} case(s): dev {totals[Split.DEV]}, test {totals[Split.TEST]}"
    )


CACHE_DIR = typer.Option(Path(".cache"), "--cache-dir", help="Cache for repositories and sources.")


@app.command()
def fetch(
    cases_dir: Path = CASES_DIR,
    cache_dir: Path = CACHE_DIR,
    case: list[str] | None = CASE_OPTION,
    split: Split | None = SPLIT_OPTION,
) -> None:
    """Download both versions of every case and check the ground-truth locations."""
    cases = _load_cases_or_exit(cases_dir, case, split)
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
    builds = dict.fromkeys((v.image, v.dockerfile, v.base_image) for v in variants)
    # An image that builds on another variant's image comes last, and only once that image exists:
    # a missing base would otherwise be pulled from a registry.
    for image, dockerfile, base in sorted(builds, key=lambda build: build[2] is not None):
        if base and not docker.image_id(base):
            typer.echo(
                f"{image} builds on {base}, which is not built - build that variant first", err=True
            )
            raise typer.Exit(code=1)
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


def _fetch_checked(cases: list[Case], cache_dir: Path) -> dict[str, CaseSources | None]:
    """Sources of every case; stops before any container starts if a location is wrong.

    Unavailable sources are no reason to stop (their runs are retried later), but a wrong file
    or line range in case.yaml would silently turn into a missed detection.
    """
    sources: dict[str, CaseSources | None] = {}
    problems: list[str] = []
    for current in cases:
        try:
            sources[current.id] = fetch_case(current, cache_dir)
        except FetchError as exc:
            typer.echo(f"{current.id}: {exc}", err=True)
            sources[current.id] = None
            continue
        problems += check_locations(current, sources[current.id])
    if problems:
        for problem in problems:
            typer.echo(problem, err=True)
        typer.echo("stopped: fix the ground-truth locations in case.yaml first", err=True)
        raise typer.Exit(code=1)
    return sources


def _run_all(
    cases: list[Case], variants: list[ToolVariant], cache_dir: Path, results_dir: Path, force: bool
) -> None:
    image_ids = {v.image: docker.image_id(v.image) for v in variants}
    missing = sorted({v.image for v in variants if not image_ids[v.image]})
    if missing:
        typer.echo(f"image(s) not built: {', '.join(missing)} - run `mcpvb images` first", err=True)
        raise typer.Exit(code=2)
    all_sources = _fetch_checked(cases, cache_dir)
    write_manifest(results_dir, variants, image_ids)
    for current in cases:
        sources = all_sources[current.id]
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
    split: Split | None = SPLIT_OPTION,
    force: bool = FORCE_OPTION,
) -> None:
    """Run the tool variants on both versions of every case."""
    cases = _load_cases_or_exit(cases_dir, case, split)
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
    image_ids = manifest_image_ids(results_dir)
    stale: list[str] = []

    def current_run(variant: ToolVariant, case: Case, version: str) -> tuple:
        """Findings of a run made on the current case and image; any other run counts as not run."""
        expected = fingerprint(variant, case, version, image_ids.get(variant.name, ""))
        meta = read_meta(results_dir, variant.name, case.id, version)
        if meta is not None and not matches(meta.get("fingerprint"), expected):
            stale.append(f"{variant.name} {case.id} {version}")
            return None, []
        return load_run(results_dir, variant.name, case.id, version, variant.cwe_overrides)

    for current in cases:
        try:
            kloc[current.id] = count_kloc(
                fetch_case(current, cache_dir).vulnerable, current.language
            )
        except FetchError as exc:
            typer.echo(
                f"warning: {current.id}: {exc} - left out of the alarm figures; run `mcpvb fetch`",
                err=True,
            )
        for variant in variants:
            status_v, found_v = current_run(variant, current, "vulnerable")
            status_f, found_f = current_run(variant, current, "fixed")
            outcomes.append(score_case(variant.name, current, status_v, status_f, found_v, found_f))
            vulnerable_findings.setdefault(variant.name, []).extend(found_v)
    if stale:
        shown = ", ".join(stale[:5]) + (" ..." if len(stale) > 5 else "")
        typer.echo(
            f"warning: {len(stale)} run(s) do not match the current case or image and count as"
            f" not run ({shown}) - repeat them with `mcpvb run`",
            err=True,
        )
    metrics = summarize(outcomes, vulnerable_findings, kloc)
    results_dir.mkdir(parents=True, exist_ok=True)
    (results_dir / "metrics.json").write_text(
        json.dumps(metrics, indent=2), encoding="utf-8", newline="\n"
    )
    return metrics


@app.command()
def score(
    cases_dir: Path = CASES_DIR,
    tools_dir: Path = TOOLS_DIR,
    cache_dir: Path = CACHE_DIR,
    results_dir: Path = RESULTS_DIR,
    variant: list[str] | None = VARIANT_OPTION,
    case: list[str] | None = CASE_OPTION,
    split: Split | None = SPLIT_OPTION,
) -> None:
    """Normalize the SARIF outputs and write metrics.json."""
    cases = _load_cases_or_exit(cases_dir, case, split)
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
    split: Split | None = SPLIT_OPTION,
    force: bool = FORCE_OPTION,
) -> None:
    """validate -> fetch -> run -> score -> report in one go."""
    cases = _load_cases_or_exit(cases_dir, case, split)
    variants = _load_variants_or_exit(tools_dir, variant)
    _preflight_or_exit()
    _run_all(cases, variants, cache_dir, results_dir, force)
    _score(cases, variants, cache_dir, results_dir)
    typer.echo(f"report: {write_report(results_dir)}")
