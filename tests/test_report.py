import copy
import json

from mcpvb.report import chart_figure, render_report, write_report

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
