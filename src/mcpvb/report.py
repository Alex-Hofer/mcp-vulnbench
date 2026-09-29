"""metrics.json -> report.md plus recall.svg (static and reproducible)."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.figure import Figure  # noqa: E402

from mcpvb.classes import VulnClass  # noqa: E402

SURFACE, INK, MUTED, GRID, BAR = "#fcfcfb", "#52514e", "#898781", "#e1e0d9", "#2a78d6"
STATUSES = ("ok", "error", "timeout", "unsupported", "unavailable")
STATUS_CELLS = {"error": "err", "timeout": "t/o", "unsupported": "n/s", "unavailable": "n/a"}
LEGEND = (
    "✓ detected, fix recognized · ◐ detected, fix not recognized · "
    "● detected, fixed version not assessed · ✗ missed · "
    "err / t/o / n/s / n/a: run of the vulnerable version failed, timed out, is unsupported or "
    "had no sources"
)


def _pct(value: float | None) -> str:
    return "–" if value is None else f"{value * 100:.0f} %"


def _counted(rate: float | None, hits: int | None, total: int | None) -> str:
    """A rate with its counts: with few cases, a percentage alone overstates the evidence."""
    if rate is None:
        return "–"
    return _pct(rate) if total is None else f"{_pct(rate)} ({hits}/{total})"


def _share(entry: dict | None) -> str:
    if not entry:
        return "–"
    return _counted(entry.get("recall"), entry.get("detected"), entry.get("cases_ok"))


def _num(value: float | None) -> str:
    return "–" if value is None else f"{value:g}"


def _cell(outcome: dict) -> str:
    if outcome["detected"] is None:
        return STATUS_CELLS.get(outcome["status_vulnerable"], "–")
    if not outcome["detected"]:
        return "✗"
    if outcome["persisting"] is None:
        return "●"
    return "◐" if outcome["persisting"] else "✓"


def render_report(metrics: dict, manifest: dict | None = None) -> str:
    variants = metrics["variants"]
    names = list(variants)
    case_ids = sorted({o["case_id"] for o in metrics["cases"]})
    lines = ["# mcp-vulnbench results", ""]
    if manifest:
        tools = ", ".join(
            f"{n} ({m['tool']} {m['version']})" for n, m in manifest["variants"].items()
        )
        lines += [f"Tools: {tools}", ""]
    lines += [
        f"Cases: {len(case_ids)}",
        "",
        "## Overview",
        "",
        "| Variant | Cases (ok) | Detected | Recall | Fix recognized | Alarms/KLOC | Error rate |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for name in names:
        o = variants[name]["overall"]
        cells = [
            str(o["cases_ok"]),
            str(o["detected"]),
            _pct(o["recall"]),
            _counted(o["fix_recognition"], o["fix_recognized"], o.get("fix_assessed")),
            _num(o["alarms_per_kloc"]),
            _pct(o["error_rate"]),
        ]
        lines.append(f"| {name} | " + " | ".join(cells) + " |")
    classes = [k.value for k in VulnClass if any(k.value in variants[n]["by_class"] for n in names)]
    lines += ["", "## Recall by class", "", "| Variant | " + " | ".join(classes) + " |"]
    lines.append("|---|" + "---:|" * len(classes))
    for name in names:
        by_class = variants[name]["by_class"]
        cells = [_share(by_class.get(k)) for k in classes]
        lines.append(f"| {name} | " + " | ".join(cells) + " |")
    lines += _split_table(variants, names)
    lines += _status_table(metrics, names) + _details_table(variants, names)
    lines += ["", "## Cases", "", LEGEND, "", "| Case | Class | " + " | ".join(names) + " |"]
    lines.append("|---|---|" + "---|" * len(names))
    by_key = {(o["variant"], o["case_id"]): o for o in metrics["cases"]}
    for case_id in case_ids:
        vuln_class = next(o["vuln_class"] for o in metrics["cases"] if o["case_id"] == case_id)
        cells = [_cell(by_key[(n, case_id)]) if (n, case_id) in by_key else "–" for n in names]
        lines.append(f"| {case_id} | {vuln_class} | " + " | ".join(cells) + " |")
    lines += [
        "",
        "![Recall per variant](recall.svg)",
        "",
        "Metric definitions: [docs/methodology.md](../../docs/methodology.md)",
        "",
    ]
    return "\n".join(lines)


def _split_table(variants: dict, names: list[str]) -> list[str]:
    """The overall figures per half (development and test), if the cases are split."""
    halves = sorted({h for name in names for h in variants[name].get("by_split", {})})
    if not halves:
        return []
    lines = ["", "## By split", ""]
    lines.append(
        "| Variant | Split | Cases (ok) | Detected | Recall | Fix recognized | Alarms/KLOC |"
    )
    lines.append("|---|---|---:|---:|---:|---:|---:|")
    for name in names:
        for half in halves:
            block = variants[name].get("by_split", {}).get(half)
            if block is None:
                continue
            fix = _counted(
                block["fix_recognition"], block["fix_recognized"], block.get("fix_assessed")
            )
            cells = [
                half,
                str(block["cases_ok"]),
                str(block["detected"]),
                _pct(block["recall"]),
                fix,
                _num(block["alarms_per_kloc"]),
            ]
            lines.append(f"| {name} | " + " | ".join(cells) + " |")
    return lines


def _status_table(metrics: dict, names: list[str]) -> list[str]:
    """How every run ended, per variant (both versions of every case)."""
    lines = ["", "## Run status", "", "| Variant | " + " | ".join(STATUSES) + " |"]
    lines.append("|---|" + "---:|" * len(STATUSES))
    for name in names:
        counts = Counter(
            status
            for outcome in metrics["cases"]
            if outcome["variant"] == name
            for status in (outcome["status_vulnerable"], outcome["status_fixed"])
        )
        lines.append(f"| {name} | " + " | ".join(str(counts[s]) for s in STATUSES) + " |")
    return lines


def _details_table(variants: dict, names: list[str]) -> list[str]:
    """Lenient recalls, recall per language and alarm details (docs/methodology.md)."""
    languages = sorted({language for n in names for language in variants[n]["by_language"]})
    header = [
        "Variant",
        "Recall (file level)",
        "Recall (any class)",
        *(f"Recall ({language})" for language in languages),
        "Median alarms/case",
        "Unclassified findings",
    ]
    lines = ["", "## Details", "", "| " + " | ".join(header) + " |"]
    lines.append("|---|" + "---:|" * (len(header) - 1))
    for name in names:
        variant = variants[name]
        cells = [
            _pct(variant["lenient"]["recall_file_level"]),
            _pct(variant["lenient"]["recall_any_class"]),
            *(_pct(variant["by_language"].get(lang, {}).get("recall")) for lang in languages),
            _num(variant["overall"]["alarms_median_per_case"]),
            str(variant["overall"]["unclassified_findings"]),
        ]
        lines.append(f"| {name} | " + " | ".join(cells) + " |")
    return lines


def render_chart(metrics: dict, path: Path) -> None:
    """Horizontal bars of overall recall per variant; the report table is the accessible view."""
    # A fixed hash salt makes the SVG ids reproducible; set it only while this chart is saved.
    # LF line endings on every system, so the file is byte-identical everywhere.
    with matplotlib.rc_context({"svg.hashsalt": "mcpvb"}):
        fig = chart_figure(metrics)
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            fig.savefig(handle, format="svg", metadata={"Date": None}, facecolor=SURFACE)
    plt.close(fig)


def chart_figure(metrics: dict) -> Figure:
    names = list(metrics["variants"])
    recalls = [metrics["variants"][n]["overall"]["recall"] for n in names]
    fig, ax = plt.subplots(figsize=(6.4, 0.5 * len(names) + 1.4), facecolor=SURFACE)
    ax.set_facecolor(SURFACE)
    # No bar for a variant without assessed cases: "n/a" must not look like "found nothing".
    ax.barh(names, [(recall or 0.0) * 100 for recall in recalls], height=0.5, color=BAR)
    ax.set_xlim(0, 100)
    ax.invert_yaxis()
    ax.set_title("Recall per variant (%)", loc="left", color=INK, fontsize=11)
    ax.xaxis.grid(True, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color(MUTED)
    ax.tick_params(colors=MUTED, length=0)
    ax.tick_params(axis="y", labelcolor=INK)
    for y, recall in enumerate(recalls):
        x, label = (1.5, "n/a") if recall is None else (recall * 100 + 1.5, f"{recall * 100:.0f} %")
        ax.text(x, y, label, va="center", color=INK, fontsize=9)
    fig.tight_layout()
    return fig


def write_report(results: Path) -> Path:
    metrics = json.loads((results / "metrics.json").read_text(encoding="utf-8"))
    manifest_path = results / "manifest.json"
    manifest = (
        json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.is_file() else None
    )
    report = results / "report.md"
    report.write_text(render_report(metrics, manifest), encoding="utf-8", newline="\n")
    render_chart(metrics, results / "recall.svg")
    return report
