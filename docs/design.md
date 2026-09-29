# Design

mcp-vulnbench is an open, extensible benchmark of real, publicly disclosed vulnerabilities in
open-source MCP (Model Context Protocol) servers, plus a harness that runs static analyzers on every
case and scores them. It follows the principles of [SmartBugs](https://github.com/smartbugs/smartbugs):
tool configurations as data, execution in Docker, explicit statuses for failures.

## Why

MCP servers expose file-system, shell and network operations to LLM agents. Tool arguments come from
a model that prompt injection can steer, so every tool argument is untrusted input; the same holds
for everything else a server receives through the protocol, such as resource URIs and transport
headers. Most published MCP CVEs are classic code bugs on that path: command injection, path
traversal, SSRF. Popular MCP scanners inspect the tool metadata of running servers and never read
the code; generic SAST reads the code but does not know that MCP tool arguments are untrusted. This
benchmark measures what actually finds these bugs.

## Scope (v1)

- Taint-style bugs in MCP server code, five classes: `command-injection` (CWE-78, CWE-88),
  `path-traversal` (CWE-22, CWE-59), `ssrf` (CWE-918), `sql-injection` (CWE-89),
  `code-injection` (CWE-94, CWE-95).
- Languages: Python, then TypeScript/JavaScript.
- Analyzers: Semgrep CE (security rules, and a variant with the official MCP rules), CodeQL
  (security-extended), Bandit.
- Out of scope: tool poisoning and other prompt-level attacks, MCP clients, live third-party
  servers, a web UI.

## Pipeline

```
cases/*/case.yaml ─► fetch ─► sources (vulnerable + fixed, cached)
                                  │
tools/*/tool.yaml ─► run (Docker, no network) ─► raw.sarif + meta.json
                                  │
                              normalize ─► findings.json
                                  │
ground truth (case.yaml) ─► score ─► metrics.json ─► report ─► report.md + recall.svg
```

## Components

| Module | Responsibility |
|---|---|
| `schema.py` | Case model, loading, cross-case checks (OSI license, at most 3 cases per repository) |
| `fetch.py` | Export both commits of a case into `.cache/` via `git archive`; check ground-truth locations |
| `tools.py` | Tool variant: pinned image, command template, supported languages, CWE overrides |
| `docker.py` | Thin wrapper around the docker CLI: preflight, build, run with limits |
| `run.py` | One container per (variant, case, version); statuses; `meta.json` written last; manifest |
| `normalize.py` | One SARIF 2.1.0 parser for all tools; CWE from overrides, rule tags or result properties |
| `score.py` | Matching against the ground truth and the metrics in [methodology.md](methodology.md) |
| `report.py` | Markdown tables and a static SVG chart |

## Error handling

Every run ends in exactly one status: `ok`, `error`, `timeout`, `unsupported` or `unavailable`. Only
`ok` runs enter the denominators; the others are reported separately and never count as "not
found". A run whose tool exits 0 but writes no valid SARIF is an `error`, and so is a SARIF run
without a `results` list or with `executionSuccessful: false`. A run directory without `meta.json`
counts as not run and is repeated; a finished run is reused only while the case commit, `subdir`,
image and command are unchanged. Docker failures (exit codes 125-127, missing images) stop the run
without recording anything, and unavailable sources are retried on the next run.

## Harness security

The analyzers never execute the analyzed code (CodeQL extracts Python and JavaScript without a
build). Containers still run with `--network none`, the sources mounted read-only, a non-root user
and CPU/memory limits. Source archives are extracted with Python's `data` filter; links are skipped.
An analyzer may write only into `<run>/tool/`; the harness keeps its own files (`meta.json`,
`log.txt`, `findings.json`) one level up and reads `raw.sarif` only if it is a regular file, so a
compromised analyzer cannot redirect harness writes through symlinks.

## Tool configuration policy

The benchmark measures what an analyzer finds, not how the analyzed project configured it. A
maintainer's `# nosec` on the vulnerable line would otherwise hide the bug from Bandit only, and a
committed `.semgrepignore` could switch Semgrep off for the whole repository. So, for every tool:

- In-source suppressions are ignored: Bandit runs with `--ignore-nosec`, Semgrep with
  `--disable-nosem`.
- Tool configuration files of the analyzed project (`.bandit`, `.semgrepignore`) are dropped when
  the sources are exported.
- Each tool's built-in defaults stay in place. Semgrep's default ignore list skips folders such as
  `tests/`, Bandit scans them; the ground truth never lies in test folders.

## Reproducibility

Tool versions and the semgrep-rules commit are pinned in `docker/*/Dockerfile` and
`tools/*/tool.yaml`. Base images are pinned by digest, the CodeQL bundle and the semgrep-rules
archive are verified against SHA-256 checksums while the images are built, and Bandit's
dependencies are pinned in `docker/bandit/constraints.txt`. Every run writes the local image IDs to
`manifest.json`, and `.python-version` keeps local development on the Python version CI uses. Two
runs with the same images produce the same `metrics.json` (checked by the smoke test).

## Legal

- Cases need an OSI-approved license: the CodeQL CLI may be used on OSI-licensed open-source code
  and for academic research.
- Semgrep registry rules are under the Semgrep Rules License v1.0: they are downloaded while the
  image is built locally, never committed, and images containing them are never published.
- Tools whose terms forbid publishing benchmark results (the cloud parts of some commercial
  scanners) are not part of the measurement.
- The benchmark contains only vulnerabilities that are already public. New findings go to the
  maintainers privately first.

## Related work

- VIPER-MCP (arXiv 2605.21392): taint analysis plus exploit confirmation over 39,884 repositories;
  67 CVEs; dataset not public.
- MCP-BiFlow (arXiv 2605.07836): MCP-aware static analysis; compares CodeQL, Semgrep, Snyk Code and
  MCPScan on 32 confirmed cases.
- MCPSecBench, MCPTox, MCP-SafetyBench: prompt- and protocol-level attacks, not code bugs.

mcp-vulnbench differs by being a reusable, extensible benchmark with vulnerable/fixed commit pairs
and reproducible tool runs.
