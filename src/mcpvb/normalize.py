"""SARIF 2.1.0 -> normalized findings (ADR 0001)."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import unquote, urlparse

from pydantic import BaseModel

from mcpvb.classes import VulnClass, class_for_cwe, cwe_number, cwes_in_text
from mcpvb.run import Status, raw_path, read_status, run_dir

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


def _require(condition: bool, path: Path, problem: str) -> None:
    if not condition:
        raise NormalizeError(f"{path}: {problem}")


def _is_line(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 1


def _check_run(sarif_run: object, path: Path) -> list:
    """The results of a run; a malformed run or one reporting a failed execution is an error."""
    _require(isinstance(sarif_run, dict), path, "a run is not an object")
    results = sarif_run.get("results")
    _require(isinstance(results, list), path, "a run has no 'results' list (scan incomplete)")
    invocations = sarif_run.get("invocations", [])
    well_formed = isinstance(invocations, list) and all(isinstance(i, dict) for i in invocations)
    _require(well_formed, path, "'invocations' is malformed")
    failed = any(invocation.get("executionSuccessful") is False for invocation in invocations)
    _require(not failed, path, "the tool reported a failed execution")
    return results


def _collect_rules(sarif_run: dict, path: Path) -> dict[str, dict]:
    """Rules of the driver and of all extensions (CodeQL keeps its query rules in extensions)."""
    tool = sarif_run.get("tool", {})
    _require(isinstance(tool, dict), path, "'tool' is not an object")
    extensions = tool.get("extensions", [])
    _require(isinstance(extensions, list), path, "'tool.extensions' is not a list")
    rules: dict[str, dict] = {}
    for component in [tool.get("driver", {}), *extensions]:
        _require(isinstance(component, dict), path, "a tool component is not an object")
        component_rules = component.get("rules", [])
        _require(isinstance(component_rules, list), path, "'rules' is not a list")
        for rule in component_rules:
            if isinstance(rule, dict) and isinstance(rule.get("id"), str):
                rules[rule["id"]] = rule
    return rules


def _cwe_texts(properties: object) -> list[str]:
    if not isinstance(properties, dict):
        return []
    tags = properties.get("tags", [])
    texts = [str(tag) for tag in tags] if isinstance(tags, list) else []
    return texts + [str(value) for key, value in properties.items() if "cwe" in str(key).lower()]


def _pick_cwe(rule_id: str, rule: dict, result: dict, overrides: dict[str, str]) -> str | None:
    """Override first; otherwise the smallest in-scope CWE, else the smallest CWE at all."""
    if rule_id in overrides:
        return overrides[rule_id]
    texts = _cwe_texts(rule.get("properties", {})) + _cwe_texts(result.get("properties", {}))
    candidates: set[str] = set().union(*(cwes_in_text(text) for text in texts))
    in_scope = [cwe for cwe in candidates if class_for_cwe(cwe) is not None]
    pool = in_scope or list(candidates)
    return min(pool, key=cwe_number) if pool else None


def _location(result: dict, path: Path) -> tuple[str, int, int] | None:
    locations = result.get("locations", [])
    _require(isinstance(locations, list), path, "'locations' is not a list")
    for location in locations:
        _require(isinstance(location, dict), path, "a location is not an object")
        physical = location.get("physicalLocation", {})
        _require(isinstance(physical, dict), path, "'physicalLocation' is not an object")
        artifact, region = physical.get("artifactLocation", {}), physical.get("region", {})
        valid = isinstance(artifact, dict) and isinstance(region, dict)
        _require(valid, path, "'artifactLocation' or 'region' is not an object")
        uri, start = artifact.get("uri"), region.get("startLine")
        if uri and start is not None:
            end = region.get("endLine", start)
            valid = isinstance(uri, str) and _is_line(start) and _is_line(end)
            _require(valid, path, "a location has an invalid uri or line numbers")
            return relative_path(uri), start, end
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
        results = _check_run(sarif_run, path)
        rules = _collect_rules(sarif_run, path)
        for result in results:
            _require(isinstance(result, dict), path, "a result is not an object")
            message = result.get("message", {})
            _require(isinstance(message, dict), path, "a result message is not an object")
            location = _location(result, path)
            if location is None:
                continue
            rule = result.get("rule", {})
            rule_ref = rule.get("id") if isinstance(rule, dict) else None
            rule_id = str(result.get("ruleId") or rule_ref or "unknown")
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
                    message=str(message.get("text", "")),
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
        raw = raw_path(results, variant, case_id, version)
        if raw.is_symlink():
            raise NormalizeError(f"{raw}: is a symlink; analyzer output must be a regular file")
        findings = parse_sarif(raw, variant, case_id, version, overrides)
    except NormalizeError as exc:
        (folder / "normalize-error.txt").write_text(str(exc), encoding="utf-8")
        return Status.ERROR, []
    serialized = [finding.model_dump(mode="json") for finding in findings]
    (folder / FINDINGS).write_text(json.dumps(serialized, indent=2), encoding="utf-8")
    return Status.OK, findings
