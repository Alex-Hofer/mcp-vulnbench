# Methodology

## Ground truth
Each case lists, for the vulnerable and for the fixed commit, the functions involved in the
vulnerability: `file` (relative to `subdir` if set) and an inclusive line range `[start, end]` from
the first decorator line to the last line of the function. The locations are the functions on the
vulnerable path that the fix changed, plus the function that contains the sink reached from the
MCP tool (analyzers usually report the sink line), even if the fix left it unchanged. The fixed
version lists the same functions as they exist after the fix, so an analyzer that keeps reporting
an unchanged sink is counted as not recognizing the fix.

## Matching
A finding *f* of a variant hits a location *L* of case *c* if `f.file == L.file`,
`L.start <= f.line <= L.end` and `f.class == c.class`. The class of a finding comes from its CWE
(`src/mcpvb/classes.py`); a variant may correct the CWE of single rules (`cwe_overrides` in
`tools/<variant>/tool.yaml`). A case is **detected** if any finding hits any of its vulnerable
locations. Two lenient variants are reported too: file level (lines ignored) and class-agnostic
(a finding of any of the five classes counts, not only of the case's class). Findings without one
of the five classes, such as an `assert` or a missing request timeout, never count as a detection.

## Development and test split
Every case belongs to the development or the test half, and all cases of one repository belong to
the same half, so a model rule written for one project's code never helps a case of the same
project in the other half. `mcpvb split` assigns new cases: a new case of a repository that
already has a half inherits it; the other repositories are taken in
`sha256("mcpvb-split-v1" + repository)` order, and each joins the half that leaves its
(language, class) strata most balanced (the test half on a tie). Existing cases never move, and
`mcpvb validate` rejects a repository in both halves. The split is committed before any model is
run on a real case; models are developed on the development half only and measured on the test
half once they are frozen. The harness enforces the freeze: a variant with `frozen_at: <tag>` in
its `tool.yaml` runs on test cases only while the files under its `dockerfile` directory equal that
git tag; the analyze options in `tool.yaml` are part of every run's fingerprint instead, so a
changed command is never mistaken for an old run. `MCPVB_UNFROZEN_MODELS=1` overrides the guard
for development; such a run is marked `unfrozen` in `manifest.json`, and no published number comes
from one. A later change to the models gets a new tag, and the results name the tag they were
measured with. The report shows both halves, overall and per language group: Python on one side,
JavaScript and TypeScript together on the other, since they share analyzers, rules and models.

## Metrics (per variant: overall, per class, per language and per half)
- **Recall** = detected cases / cases whose vulnerable run is `ok`.
- **Fix recognition** = detected cases without a persisting finding / detected cases whose fixed
  run is `ok`. A finding *persists* if it has the case's class and lies inside a fixed location.
  Some fixed versions are not clean: the fix leaves a weakness of the same class behind, or the
  location is so large that it holds other tools as well. The notes of such a case say so in a
  sentence that starts with `Caveat:` ([curation.md](curation.md#fixes-that-leave-something-behind)),
  the report marks the case with †, and its details table gives fix recognition a second time
  without these cases.
- **Alarms per KLOC** = classified findings (class among the five in scope) on the vulnerable
  versions of `ok` cases / KLOC of those versions. KLOC counts non-blank lines of the case language
  (JavaScript and TypeScript files alike for a case in either language) without `test`, `tests`, `node_modules`, `vendor`, `third_party`, `dist`, `build`, virtualenvs
  and `__pycache__`; findings in files of other languages (for example workflow YAML or a web
  frontend) or inside those folders are not counted either, so numerator and denominator cover the
  same code. A case whose sources are unavailable when scoring has no line count and is left out
  of the alarm figures (with a warning). The median alarms per case is the median of the same
  count over the same cases. Unclassified findings (same scope) are counted separately.
- **Error rate** = runs with a status other than `ok` / all runs, without `unsupported` runs (a
  tool that does not support a language is not failing).

## Why there is no precision
Findings outside the ground-truth locations are not necessarily false positives: they may be real,
still unknown vulnerabilities or true but unrelated issues. Labeling every finding by hand does
not scale and would bias the benchmark towards whatever the labeler checked. False alarms are
therefore approximated from two directions: does a tool still report the fixed code (fix
recognition), and how much does it report per KLOC (alarm volume). See ADR 0002.

## Tool configuration
Every tool runs without a severity or confidence filter, so a tool is measured the way a team
that adopts it without tuning would see it. The settings that differ from a tool's out-of-the-box
behavior are deliberate:

- CodeQL runs the `security-extended` suite, which adds lower-precision security queries to the
  default suite.
- Semgrep runs the security rules of the semgrep-rules repository for Python, JavaScript and
  TypeScript at a pinned commit (`python/*/security`, `javascript/*/security`,
  `typescript/*/security`; `semgrep-mcp` adds `ai/ai-best-practices/mcp-*` and
  `typescript/mcp/security`) instead of a registry ruleset that changes over time, and with
  `--timeout 0`, so no rule is cut off on a large file.
- `codeql-mcp` is `codeql` plus the models in `models/codeql`, which mark MCP input as remote
  sources. Nothing else differs. The models stop where the handler starts: they add no sinks and
  know no project's code.
  - Python (`mcp`, `fastmcp`; frozen as `models-v1`): the parameters of tool, resource and prompt
    handlers; the HTTP headers that `fastmcp` hands to handlers; the bearer token that token
    verifiers and `get_access_token()` receive.
  - JavaScript and TypeScript (`@modelcontextprotocol/sdk` 1.x, `@modelcontextprotocol/server` 2.x,
    `fastmcp`): the arguments of tool, resource and prompt callbacks; the request a low-level
    request handler receives; the transport headers and the bearer token the SDK hands to a
    callback. Four more rows carry taint through `zod` (`parse`, `safeParse` and their async
    forms): a low-level handler gets raw arguments and validates them with a schema first, and
    CodeQL, which has no model of zod, would lose the input at that call.
- In-source suppressions and the analyzed project's tool configuration files are ignored for
  every tool (see [design.md](design.md#tool-configuration-policy)).

## Statuses
`ok`, `error` (non-zero exit, missing, broken or failed SARIF), `timeout`, `unsupported` (language
not supported by the variant), `unavailable` (sources could not be fetched; not stored, retried on
the next run). Only `ok` runs enter the denominators.

## Reproducibility
Tool versions and the semgrep-rules commit are pinned; `manifest.json` records the local image
IDs. A finished run is reused only while the case commit, `subdir`, image and command are
unchanged; `--force` repeats it anyway. `score` applies the same check: a run made on an older
case version or another image than the manifest names counts as not run (with a warning).
