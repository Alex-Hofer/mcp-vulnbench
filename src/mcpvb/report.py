"""metrics.json -> report.md plus recall.svg (static and reproducible)."""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.figure import Figure  # noqa: E402

from mcpvb.classes import VulnClass  # noqa: E402

SURFACE, INK, MUTED, GRID, BAR = "#fcfcfb", "#52514e", "#898781", "#e1e0d9", "#2a78d6"
LEGEND = (
    "✓ detected, fix recognized · ◐ detected, fix not recognized · "
    "● detected, fixed version not assessed · ✗ missed · – not assessed"
)


def _pct(value: float | None) -> str:
    return "–" if value is None else f"{value * 100:.0f} %"


def _num(value: float | None) -> str:
    return "–" if value is None else f"{value:g}"


def _cell(outcome: dict) -> str:
    if outcome["detected"] is None:
        return "–"
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
            _pct(o["fix_recognition"]),
            _num(o["alarms_per_kloc"]),
            _pct(o["error_rate"]),
        ]
        lines.append(f"| {name} | " + " | ".join(cells) + " |")
    classes = [k.value for k in VulnClass if any(k.value in variants[n]["by_class"] for n in names)]
    lines += ["", "## Recall by class", "", "| Variant | " + " | ".join(classes) + " |"]
    lines.append("|---|" + "---:|" * len(classes))
    for name in names:
        by_class = variants[name]["by_class"]
        cells = [_pct(by_class.get(k, {}).get("recall")) for k in classes]
        lines.append(f"| {name} | " + " | ".join(cells) + " |")
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


def render_chart(metrics: dict, path: Path) -> None:
    """Horizontal bars of overall recall per variant; the report table is the accessible view."""
    matplotlib.rcParams["svg.hashsalt"] = "mcpvb"
    fig = chart_figure(metrics)
    fig.savefig(path, format="svg", metadata={"Date": None}, facecolor=SURFACE)
    plt.close(fig)


def chart_figure(metrics: dict) -> Figure:
    names = list(metrics["variants"])
    recalls = [(metrics["variants"][n]["overall"]["recall"] or 0.0) * 100 for n in names]
    fig, ax = plt.subplots(figsize=(6.4, 0.5 * len(names) + 1.4), facecolor=SURFACE)
    ax.set_facecolor(SURFACE)
    ax.barh(names, recalls, height=0.5, color=BAR)
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
    for y, value in enumerate(recalls):
        ax.text(value + 1.5, y, f"{value:.0f} %", va="center", color=INK, fontsize=9)
    fig.tight_layout()
    return fig


def write_report(results: Path) -> Path:
    metrics = json.loads((results / "metrics.json").read_text(encoding="utf-8"))
    manifest_path = results / "manifest.json"
    manifest = (
        json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.is_file() else None
    )
    report = results / "report.md"
    report.write_text(render_report(metrics, manifest), encoding="utf-8")
    render_chart(metrics, results / "recall.svg")
    return report
