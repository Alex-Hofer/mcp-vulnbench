# 0001 – SARIF as the only tool output format

Status: accepted, 2026-10

## Context
Semgrep, CodeQL and Bandit can all write SARIF 2.1.0. Tool-specific formats would need one parser
per tool.

## Decision
Every variant writes `/out/raw.sarif`. One parser (`normalize.py`) reads the rules from
`tool.driver` and `tool.extensions`, takes the location from the first physical location and the
CWE from rule tags (`CWE-78: ...`, `external/cwe/cwe-078`) or result properties. `cwe_overrides`
in `tool.yaml` correct CWEs that a tool files under the wrong weakness class.

## Consequences
- Adding a tool needs no parser code if it writes SARIF with CWE tags.
- A tool without SARIF output needs a small converter inside its image.
