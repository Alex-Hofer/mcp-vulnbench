import copy
import json

import matplotlib

from mcpvb.report import chart_figure, render_chart, render_report, write_report

OVERALL = {
    "cases_ok": 2,
    "detected": 1,
    "recall": 0.5,
    "fix_recognized": 0,
    "fix_recognition": 0.0,
    "alarms_per_kloc": 55.56,
    "alarms_median_per_case": 1.0,
    "unclassified_findings": 0,
    "error_rate": 0.0,
    "unsupported_cases": 0,
}


def outcome(case_id, vuln_class, detected, persisting):
    return {
        "variant": "bandit",
        "case_id": case_id,
        "language": "python",
        "vuln_class": vuln_class,
        "status_vulnerable": "ok",
        "status_fixed": "ok",
        "detected": detected,
        "detected_file_level": detected,
        "detected_any_class": detected,
        "persisting": persisting,
    }


METRICS = {
    "variants": {
        "bandit": {
            "overall": OVERALL,
            "by_class": {
                "command-injection": {"cases_ok": 1, "detected": 1, "recall": 1.0},
                "path-traversal": {"cases_ok": 1, "detected": 0, "recall": 0.0},
            },
            "by_language": {"python": {"cases_ok": 2, "detected": 1, "recall": 0.5}},
            "lenient": {"recall_file_level": 0.5, "recall_any_class": 0.5},
        }
    },
    "cases": [
        outcome("mcpvb-9001", "command-injection", True, True),
        outcome("mcpvb-9002", "path-traversal", False, None),
    ],
}


def test_report_contains_overview_and_case_table():
    text = render_report(METRICS)
    assert "| bandit | 2 | 1 | 50 % | 0 % | 55.56 | 0 % |" in text
    assert "| bandit | 100 % | 0 % |" in text
    assert "| mcpvb-9001 | command-injection | ◐ |" in text
    assert "| mcpvb-9002 | path-traversal | ✗ |" in text


def test_report_and_chart_are_deterministic(tmp_path):
    (tmp_path / "metrics.json").write_text(json.dumps(METRICS), encoding="utf-8")
    first = write_report(tmp_path).read_text(encoding="utf-8")
    first_svg = (tmp_path / "recall.svg").read_text(encoding="utf-8")
    second = write_report(tmp_path).read_text(encoding="utf-8")
    assert first == second
    assert first_svg == (tmp_path / "recall.svg").read_text(encoding="utf-8")


def test_value_labels_stay_inside_the_chart():
    metrics = copy.deepcopy(METRICS)
    metrics["variants"]["bandit"]["overall"]["recall"] = 1.0
    fig = chart_figure(metrics)
    fig.canvas.draw()
    for label in fig.axes[0].texts:
        assert label.get_window_extent().x1 <= fig.bbox.x1, label.get_text()


def test_missing_recall_is_not_drawn_as_zero():
    metrics = copy.deepcopy(METRICS)
    metrics["variants"]["bandit"]["overall"]["recall"] = None
    labels = [label.get_text() for label in chart_figure(metrics).axes[0].texts]
    assert labels == ["n/a"]


def test_report_counts_run_statuses():
    metrics = copy.deepcopy(METRICS)
    metrics["cases"][1].update(status_vulnerable="error", detected=None)
    text = render_report(metrics)
    assert "| Variant | ok | error | timeout | unsupported | unavailable |" in text
    assert "| bandit | 3 | 1 | 0 | 0 | 0 |" in text


def test_report_shows_lenient_recall_and_alarm_details():
    text = render_report(METRICS)
    assert "| bandit | 50 % | 50 % | 50 % | 1 | 0 |" in text


def test_case_table_names_the_status_of_unassessed_runs():
    metrics = copy.deepcopy(METRICS)
    metrics["cases"][1].update(status_vulnerable="timeout", detected=None)
    assert "| mcpvb-9002 | path-traversal | t/o |" in render_report(metrics)


def test_rendering_the_chart_keeps_global_matplotlib_settings(tmp_path):
    with matplotlib.rc_context({"svg.hashsalt": None}):
        render_chart(METRICS, tmp_path / "recall.svg")
        assert matplotlib.rcParams["svg.hashsalt"] is None
