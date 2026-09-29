"""SARIF 2.1.0 -> normalized findings (ADR 0001)."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import unquote, urlparse

from pydantic import BaseModel

from mcpvb.classes import VulnClass, class_for_cwe, cwe_number, cwes_in_text
from mcpvb.run import RAW, Status, read_status, run_dir

SRC_PREFIX = "/src/"
FINDINGS = "findings.json"


class NormalizeError(Exception):
    """The SARIF file is missing, not JSON, or not a SARIF log."""


class Finding(BaseModel):
    variant: str
    case_id: str
    version: str
    file: str
    line: int
    end_line: int
    rule_id: str
    cwe: str | None
    vuln_class: VulnClass | None
    message: str


def relative_path(uri: str) -> str:
    """'file:///src/a/b.py', '/src/a/b.py', './a/b.py' or 'a\\b.py' -> 'a/b.py'."""
    path = unquote(urlparse(uri).path) if uri.startswith("file:") else unquote(uri)
    path = path.replace("\\", "/")
    if path.startswith(SRC_PREFIX):
        path = path[len(SRC_PREFIX) :]
    return path.removeprefix("./").lstrip("/")


def _collect_rules(sarif_run: dict) -> dict[str, dict]:
    """Rules of the driver and of all extensions (CodeQL keeps its query rules in extensions)."""
    tool = sarif_run.get("tool", {})
    components = [tool.get("driver", {}), *tool.get("extensions", [])]
    return {
        rule["id"]: rule
        for component in components
        for rule in component.get("rules", [])
        if "id" in rule
    }


def _cwe_texts(properties: dict) -> list[str]:
    texts = [str(tag) for tag in properties.get("tags", [])]
    return texts + [str(value) for key, value in properties.items() if "cwe" in key.lower()]


def _pick_cwe(rule_id: str, rule: dict, result: dict, overrides: dict[str, str]) -> str | None:
    """Override first; otherwise the smallest in-scope CWE, else the smallest CWE at all."""
    if rule_id in overrides:
        return overrides[rule_id]
    texts = _cwe_texts(rule.get("properties", {})) + _cwe_texts(result.get("properties", {}))
    candidates: set[str] = set().union(*(cwes_in_text(text) for text in texts))
    in_scope = [cwe for cwe in candidates if class_for_cwe(cwe) is not None]
    pool = in_scope or list(candidates)
    return min(pool, key=cwe_number) if pool else None


def _location(result: dict) -> tuple[str, int, int] | None:
    for location in result.get("locations", []):
        physical = location.get("physicalLocation", {})
        uri = physical.get("artifactLocation", {}).get("uri")
        region = physical.get("region", {})
        start = region.get("startLine")
        if uri and start:
            return relative_path(uri), int(start), int(region.get("endLine", start))
    return None


def parse_sarif(
    path: Path, variant: str, case_id: str, version: str, overrides: dict[str, str] | None = None
) -> list[Finding]:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise NormalizeError(f"{path}: file not found") from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise NormalizeError(f"{path}: not valid JSON ({exc})") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("runs"), list):
        raise NormalizeError(f"{path}: not a SARIF log (no 'runs' list)")
    findings: list[Finding] = []
    for sarif_run in doc["runs"]:
        rules = _collect_rules(sarif_run)
        for result in sarif_run.get("results", []):
            location = _location(result)
            if location is None:
                continue
            rule_id = result.get("ruleId") or result.get("rule", {}).get("id") or "unknown"
            cwe = _pick_cwe(rule_id, rules.get(rule_id, {}), result, overrides or {})
            file, line, end_line = location
            findings.append(
                Finding(
                    variant=variant,
                    case_id=case_id,
                    version=version,
                    file=file,
                    line=line,
                    end_line=end_line,
                    rule_id=rule_id,
                    cwe=cwe,
                    vuln_class=class_for_cwe(cwe),
                    message=result.get("message", {}).get("text", ""),
                )
            )
    return findings


def load_run(
    results: Path, variant: str, case_id: str, version: str, overrides: dict[str, str] | None = None
) -> tuple[Status | None, list[Finding]]:
    """Status and findings of one run; broken SARIF turns an 'ok' run into 'error'."""
    status = read_status(results, variant, case_id, version)
    if status is not Status.OK:
        return status, []
    folder = run_dir(results, variant, case_id, version)
    try:
        findings = parse_sarif(folder / RAW, variant, case_id, version, overrides)
    except NormalizeError as exc:
        (folder / "normalize-error.txt").write_text(str(exc), encoding="utf-8")
        return Status.ERROR, []
    serialized = [finding.model_dump(mode="json") for finding in findings]
    (folder / FINDINGS).write_text(json.dumps(serialized, indent=2), encoding="utf-8")
    return Status.OK, findings
