"""Match findings against the ground truth and compute the metrics of docs/methodology.md."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import PurePosixPath
from statistics import median

from mcpvb.classes import VulnClass
from mcpvb.loc import EXTENSIONS, SKIP_DIRS
from mcpvb.normalize import Finding
from mcpvb.run import Status
from mcpvb.schema import Case, Language, Location


def _hits(
    location: Location,
    finding: Finding,
    vuln_class: VulnClass,
    *,
    file_level: bool,
    any_class: bool,
) -> bool:
    if finding.file != location.file or finding.vuln_class is None:
        return False
    if not any_class and finding.vuln_class != vuln_class:
        return False
    return file_level or location.lines[0] <= finding.line <= location.lines[1]


def is_detected(
    case: Case, findings: list[Finding], *, file_level: bool = False, any_class: bool = False
) -> bool:
    """A finding on the vulnerable version inside a ground-truth location."""
    return any(
        _hits(location, finding, case.vuln_class, file_level=file_level, any_class=any_class)
        for location in case.vulnerable.locations
        for finding in findings
    )


def is_persisting(case: Case, fixed_findings: list[Finding]) -> bool:
    """A finding of the case's class still inside a fixed location: the fix is not recognized."""
    return any(
        _hits(location, finding, case.vuln_class, file_level=False, any_class=False)
        for location in case.fixed.locations
        for finding in fixed_findings
    )


@dataclass(frozen=True)
class CaseOutcome:
    variant: str
    case_id: str
    language: str
    vuln_class: str
    status_vulnerable: str
    status_fixed: str
    detected: bool | None
    detected_file_level: bool | None
    detected_any_class: bool | None
    persisting: bool | None
    split: str | None = None
    caveat: bool = False  # the notes say that the fixed version is not clean (docs/curation.md)


def score_case(
    variant: str,
    case: Case,
    status_vulnerable: Status | None,
    status_fixed: Status | None,
    vulnerable_findings: list[Finding],
    fixed_findings: list[Finding],
) -> CaseOutcome:
    ok_vulnerable = status_vulnerable is Status.OK
    detected = is_detected(case, vulnerable_findings) if ok_vulnerable else None
    persisting = (
        is_persisting(case, fixed_findings) if detected and status_fixed is Status.OK else None
    )
    return CaseOutcome(
        variant=variant,
        case_id=case.id,
        language=case.language.value,
        vuln_class=case.vuln_class.value,
        status_vulnerable=(status_vulnerable or Status.UNAVAILABLE).value,
        status_fixed=(status_fixed or Status.UNAVAILABLE).value,
        detected=detected,
        detected_file_level=is_detected(case, vulnerable_findings, file_level=True)
        if ok_vulnerable
        else None,
        detected_any_class=is_detected(case, vulnerable_findings, any_class=True)
        if ok_vulnerable
        else None,
        persisting=persisting,
        split=str(case.split) if case.split else None,
        caveat="Caveat:" in case.notes,
    )


def _in_alarm_scope(file: str, language: str) -> bool:
    """Alarm figures cover the same code as the KLOC count (see loc.count_kloc)."""
    path = PurePosixPath(file)
    in_language = path.suffix in EXTENSIONS[Language(language)]
    return in_language and not SKIP_DIRS.intersection(path.parts[:-1])


def _rate(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 4) if denominator else None


def _recall(outcomes: list[CaseOutcome], attribute: str = "detected") -> dict:
    scored = [o for o in outcomes if getattr(o, attribute) is not None]
    hits = sum(1 for o in scored if getattr(o, attribute))
    return {"cases_ok": len(scored), "detected": hits, "recall": _rate(hits, len(scored))}


def language_group(language: str) -> str:
    """JavaScript and TypeScript are measured as one group: same analyzers, rules and models."""
    return "python" if language == Language.PYTHON else "javascript/typescript"


def _block(mine: list[CaseOutcome], found: list[Finding], kloc: dict[str, float]) -> dict:
    """The overall metrics of one variant on a set of cases (all of them, or one half)."""
    assessed = [o for o in mine if o.detected and o.persisting is not None]
    recognized = sum(1 for o in assessed if not o.persisting)
    clean = [o for o in assessed if not o.caveat]
    runs = [
        status
        for o in mine
        for status in (o.status_vulnerable, o.status_fixed)
        if status != Status.UNSUPPORTED
    ]
    ok_cases = sorted({o.case_id for o in mine if o.status_vulnerable == Status.OK})
    # a case without a line count (sources unavailable) is left out of the alarm figures
    alarm_cases = [cid for cid in ok_cases if cid in kloc]
    languages = {o.case_id: o.language for o in mine}
    findings = [
        f
        for f in found
        if f.case_id in alarm_cases and _in_alarm_scope(f.file, languages[f.case_id])
    ]
    classified = [f for f in findings if f.vuln_class is not None]
    per_case = [sum(1 for f in classified if f.case_id == cid) for cid in alarm_cases]
    total_kloc = sum(kloc[cid] for cid in alarm_cases)
    return {
        **_recall(mine),
        "fix_recognized": recognized,
        "fix_recognition": _rate(recognized, len(assessed)),
        "fix_assessed": len(assessed),
        "fix_recognized_without_caveat": sum(1 for o in clean if not o.persisting),
        "fix_assessed_without_caveat": len(clean),
        "alarms_per_kloc": round(len(classified) / total_kloc, 2) if total_kloc else None,
        "alarms_median_per_case": median(per_case) if per_case else None,
        "unclassified_findings": len(findings) - len(classified),
        "error_rate": _rate(sum(1 for s in runs if s != Status.OK), len(runs)),
        "unsupported_cases": sum(1 for o in mine if o.status_vulnerable == Status.UNSUPPORTED),
    }


def summarize(
    outcomes: list[CaseOutcome],
    vulnerable_findings: dict[str, list[Finding]],
    kloc: dict[str, float],
) -> dict:
    """Metrics per variant; see docs/methodology.md for every definition."""
    variants: dict[str, dict] = {}
    for name in sorted({o.variant for o in outcomes}):
        mine = [o for o in outcomes if o.variant == name]
        found = vulnerable_findings.get(name, [])
        halves = sorted({o.split for o in mine if o.split})
        grouped: dict[str, dict[str, list[CaseOutcome]]] = {}
        for o in mine:
            if o.split:
                grouped.setdefault(language_group(o.language), {}).setdefault(o.split, []).append(o)
        variants[name] = {
            "overall": _block(mine, found, kloc),
            "by_class": {
                k.value: _recall([o for o in mine if o.vuln_class == k.value])
                for k in VulnClass
                if any(o.vuln_class == k.value for o in mine)
            },
            "by_language": {
                language: _recall([o for o in mine if o.language == language])
                for language in sorted({o.language for o in mine})
            },
            "by_split": {h: _block([o for o in mine if o.split == h], found, kloc) for h in halves},
            "by_language_split": {
                group: {h: _block(grouped[group][h], found, kloc) for h in sorted(grouped[group])}
                for group in sorted(grouped)
            },
            "lenient": {
                "recall_file_level": _recall(mine, "detected_file_level")["recall"],
                "recall_any_class": _recall(mine, "detected_any_class")["recall"],
            },
        }
    return {"variants": variants, "cases": [asdict(o) for o in outcomes]}
