"""Assign cases to the development or the test half (see docs/methodology.md)."""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from pathlib import Path

from mcpvb.schema import Case, CaseError, Split, repo_key

SEED = "mcpvb-split-v1"
_EMPTY_SPLIT_LINE = re.compile(r"^split:[ \t]*(?:null|~)?[ \t]*$", re.MULTILINE)


def _by_repository(cases: list[Case]) -> dict[str, list[Case]]:
    groups: dict[str, list[Case]] = {}
    for case in cases:
        groups.setdefault(repo_key(case.repo), []).append(case)
    return groups


def repositories_in_both_halves(cases: list[Case]) -> list[str]:
    """Repositories whose cases are in both halves (a leak between development and test)."""
    return sorted(
        key
        for key, members in _by_repository(cases).items()
        if len({c.split for c in members if c.split is not None}) > 1
    )


def _balancing_half(new: list[Case], counts: Counter) -> Split:
    """The half that leaves the strata of these cases most balanced; the test half on a tie."""
    need = Counter((c.language, c.vuln_class) for c in new)

    def imbalance(half: Split) -> int:
        total = 0
        for (language, vuln_class), n in need.items():
            dev = counts[(language, vuln_class, Split.DEV)] + (n if half is Split.DEV else 0)
            test = counts[(language, vuln_class, Split.TEST)] + (n if half is Split.TEST else 0)
            total += abs(dev - test)
        return total

    return Split.DEV if imbalance(Split.DEV) < imbalance(Split.TEST) else Split.TEST


def assign_splits(cases: list[Case]) -> dict[str, Split]:
    """A half for every case without one; cases that already have a half keep it.

    Whole repositories are assigned, so a model rule written for one repository's code can never
    help a case of the same repository in the other half. New cases of a repository that already
    has a half inherit it. The other repositories are taken in sha256(seed + repository) order;
    each joins the half that leaves its (language, class) strata most balanced, the test half on a
    tie. Adding cases later never moves existing ones.
    """
    mixed = repositories_in_both_halves(cases)
    if mixed:
        raise CaseError(
            f"cases of {', '.join(mixed)} are in both halves; a repository belongs to one half"
        )
    groups = _by_repository(cases)
    counts = Counter((c.language, c.vuln_class, c.split) for c in cases if c.split is not None)
    assigned: dict[str, Split] = {}
    for key in sorted(groups, key=lambda k: hashlib.sha256(f"{SEED}{k}".encode()).hexdigest()):
        new = [c for c in groups[key] if c.split is None]
        if not new:
            continue
        known = {c.split for c in groups[key] if c.split is not None}
        half = known.pop() if known else _balancing_half(new, counts)
        for case in new:
            counts[(case.language, case.vuln_class, half)] += 1
            assigned[case.id] = half
    return assigned


def write_split(case_file: Path, half: Split) -> None:
    """Fill the empty `split:` line of a case file; every other byte stays as it is."""
    text = case_file.read_text(encoding="utf-8")
    new_text, count = _EMPTY_SPLIT_LINE.subn(f"split: {half.value}", text)
    if count != 1:
        raise CaseError(f"{case_file}: expected exactly one empty 'split:' line (split: null)")
    case_file.write_text(new_text, encoding="utf-8", newline="\n")
