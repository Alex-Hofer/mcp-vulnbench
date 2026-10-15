# Two upstream proposals for Python MCP sources, measured

Two pull requests to CodeQL propose to treat the input of MCP server handlers in Python as a
source of untrusted data:

- [github/codeql#22703](https://github.com/github/codeql/pull/22703): data extensions (Models as
  Data). The rows are those of `models/codeql/mcp` in this repository (tag `models-v1`, variant
  `codeql-mcp`). The pull request (commit `f298591a`) holds the same source rows in a more compact
  notation and leaves out the eight type rows that only repeat a type's own import path, which
  CodeQL derives from the type name.
- [github/codeql#22750](https://github.com/github/codeql/pull/22750), commit `21a5a92c`: a QL
  class that extends `RemoteFlowSource::Range` and recognizes handlers by their decorator.

This page records what each of them finds on the 28 Python cases of the benchmark, and what
happens with both applied. The two variants with the class were measured on 2026-10-04 with
mcp-vulnbench v0.5.0. The figures for CodeQL as shipped and for the rows alone are the published
results of v0.5.0, measured the day before with the same CodeQL bundle. The experiment stands
next to the benchmark: its variants are not part of `tools/`, and the published results are
unchanged.

## Result

| CodeQL 2.27.1, `python-security-extended` | development half | test half | all |
|---|---:|---:|---:|
| as shipped (`codeql`) | 1 / 12 | 0 / 16 | 1 / 28 |
| with the class of #22750 | 4 / 12 | 5 / 16 | 9 / 28 |
| with the rows of #22703 (`codeql-mcp`) | 4 / 12 | 9 / 16 | 13 / 28 |
| with both | 4 / 12 | 9 / 16 | 13 / 28 |

The nine cases the class detects are among the thirteen the rows detect. With both applied, the
alerts of every run are exactly the union of the two.

The rows were written against the development half. On that half the two are level; the
difference is on the half the rows were not developed on.

### What only the rows find

Four cases, for two reasons:

- mcpvb-0017, 0018 and 0025 use the low-level `Server` (`@server.call_tool()`,
  `@server.read_resource()`), which the class does not model.
- mcpvb-0002 applies the decorator as a call, `mcp.tool()(k8s_get)`. The class looks for the
  decorator on the function definition (and for `add_tool(fn)`).

Beyond these four cases the rows also cover input that is not a handler parameter: HTTP headers
(`get_http_headers()`, `get_http_request().headers`) and bearer tokens (`verify_token`,
`get_access_token()`). In the benchmark these sources raise alerts in mcpvb-0021 and mcpvb-0024
but decide no case.

### What only the class finds

No additional case, but:

- Handlers with a tool decorator above a project decorator, as in

  ```python
  @mcp.tool
  @_phantom_tool
  def analyze_spectrum(file_path: str) -> dict: ...
  ```

  The rows mark the parameters of the function that `mcp.tool` receives. Here that is what the
  project decorator returns, not the handler, so the handler's own parameters get no source (a
  limit listed in [github/codeql#22702](https://github.com/github/codeql/issues/22702)). The
  class reads the decorator list of the function and is not affected. This accounts for all 183
  alerts that the class raises and the rows do not: 114 in the vulnerable and 69 in the fixed
  versions of five cases of the development half (mcpvb-0008, 0010, 0014, 0016, 0021; four
  repositories).
- One of these alerts is the vulnerability of a case. In mcpvb-0014 the class reports
  `py/command-line-injection` on the `subprocess.run(command, shell=True)` of
  `run_kubectl_command`, with a flow from the parameters of the `process_natural_language` tool.
  Neither CodeQL as shipped nor the rows report this flow. The case counts as detected for all
  variants through a different alert in the same function
  (`py/shell-command-constructed-from-input`), so the table does not show the difference. Fifteen
  more of the 183 alerts lie in the ground-truth functions of that case (`py/log-injection`,
  `py/polynomial-redos`); the others are elsewhere.
- In CodeQL 2.27.1, `py/xxe`, `py/xml-bomb` and `py/nosql-injection` take only
  `RemoteFlowSource`. On a test file they see the sources of the class and not those from data
  extensions (the gap reported in #22702 and fixed upstream on 2026-10-15 in
  [github/codeql#22822](https://github.com/github/codeql/pull/22822)). No run of the benchmark
  raises one of these three alerts, with either proposal.
- The class leaves out parameters annotated with the SDK's `Context` (as imported from `fastmcp`
  or `mcp.server.fastmcp`), which carry the request context and not tool input. Rows cannot make
  that distinction and mark them as well. No alert in the benchmark starts at such a parameter.

### The two test files

Each proposal comes with its own test file, written for its own entry points:

- On the fixture of this repository (`tests/fixtures/mcp-server`, one handler per row) the rows
  raise all 39 expected alerts and the class 19 of them. The 20 others are entry points the
  class does not model: bearer tokens, the low-level `Server`, `Tool.from_function`, HTTP
  headers, `add_prompt`. The class also raises one of the three misses the fixture documents for
  the rows, the one behind a decorator stack.
- On the test file of #22750 the class marks its 12 sources and the rows 10 of them. The two
  others import `tool` from the top-level `fastmcp` package. The rows also mark the `Context`
  parameter, which the class leaves out.

### Alerts

Alerts per run, counted as distinct (file, line, rule) and summed over the 56 runs (an alert
present in both versions of a case counts twice):

| | alerts | fix recognized |
|---|---:|---:|
| as shipped | 334 | 1 / 1 |
| with the class of #22750 | 1120 | 2 / 9 |
| with the rows of #22703 | 1078 | 2 / 13 |
| with both | 1261 | 2 / 13 |

In both proposals most of the added alerts are `py/path-injection` and `py/log-injection`. The
class adds 183 alerts the rows do not have: 139 `py/log-injection`, 34 `py/path-injection`, 9
`py/polynomial-redos`, 1 `py/command-line-injection`. The rows add 141 the class does not have:
103 `py/path-injection`, 27 `py/log-injection`, 5 `py/sql-injection`, 4
`py/command-line-injection`, 2 `py/regex-injection`. None of these alerts is judged here, apart
from the one in mcpvb-0014 described above.

### Per case

`D` detected, `.` not detected. All 112 runs of the experiment finished with status `ok`.

| Case | Half | Vulnerability | as shipped | class (#22750) | rows (#22703) | both |
|---|---|---|:-:|:-:|:-:|:-:|
| mcpvb-0001 | dev | command-injection | . | . | . | . |
| mcpvb-0002 | test | command-injection | . | . | D | D |
| mcpvb-0003 | test | command-injection | . | . | . | . |
| mcpvb-0004 | dev | path-traversal | . | . | . | . |
| mcpvb-0005 | dev | path-traversal | . | D | D | D |
| mcpvb-0006 | test | path-traversal | . | . | . | . |
| mcpvb-0007 | test | path-traversal | . | . | . | . |
| mcpvb-0008 | dev | path-traversal | . | . | . | . |
| mcpvb-0009 | test | ssrf | . | D | D | D |
| mcpvb-0010 | dev | ssrf | . | . | . | . |
| mcpvb-0011 | dev | sql-injection | . | . | . | . |
| mcpvb-0012 | dev | sql-injection | . | . | . | . |
| mcpvb-0013 | test | code-injection | . | . | . | . |
| mcpvb-0014 | dev | command-injection | D | D | D | D |
| mcpvb-0015 | test | path-traversal | . | D | D | D |
| mcpvb-0016 | dev | path-traversal | . | . | . | . |
| mcpvb-0017 | test | path-traversal | . | . | D | D |
| mcpvb-0018 | test | path-traversal | . | . | D | D |
| mcpvb-0019 | test | path-traversal | . | D | D | D |
| mcpvb-0020 | dev | path-traversal | . | D | D | D |
| mcpvb-0021 | dev | path-traversal | . | . | . | . |
| mcpvb-0022 | test | ssrf | . | . | . | . |
| mcpvb-0023 | dev | ssrf | . | D | D | D |
| mcpvb-0024 | test | ssrf | . | . | . | . |
| mcpvb-0025 | test | sql-injection | . | . | D | D |
| mcpvb-0026 | test | code-injection | . | . | . | . |
| mcpvb-0027 | test | command-injection | . | D | D | D |
| mcpvb-0028 | test | path-traversal | . | D | D | D |

## Method

The class is measured as the pull request has it, on the CodeQL version the benchmark pins. An
image derived from `mcpvb/codeql-mcp:2.27.1` applies the two library changes of the pull request
to `codeql/python-all` 7.2.6: it adds `semmle/python/frameworks/Mcp.qll` and the import of that
file in `semmle/python/Frameworks.qll`. Start script, query suite and resource limits are those
of the benchmark.

```dockerfile
FROM mcpvb/codeql-mcp:2.27.1
# Mcp.qll from github/codeql#22750, commit 21a5a92c
COPY Mcp.qll /tmp/Mcp.qll
# The bundle holds the library more than once: on its own, and as the copy the query pack is
# resolved against (python-queries/<version>/.codeql/libraries).
RUN set -eu; \
    for lib in /opt/codeql/qlpacks/codeql/python-all/* \
               /opt/codeql/qlpacks/codeql/python-queries/*/.codeql/libraries/codeql/python-all/*; do \
      test -f "$lib/semmle/python/Frameworks.qll"; \
      test ! -e "$lib/semmle/python/frameworks/Mcp.qll"; \
      cp /tmp/Mcp.qll "$lib/semmle/python/frameworks/Mcp.qll"; \
      sed -i '0,/^private import semmle\.python\.frameworks\./s//private import semmle.python.frameworks.Mcp\n&/' \
        "$lib/semmle/python/Frameworks.qll"; \
      echo "$lib: $(grep -c '^private import semmle.python.frameworks.Mcp$' "$lib/semmle/python/Frameworks.qll")"; \
    done
# The harness runs containers as uid 1000 with HOME=/tmp, so the compilation cache goes there.
RUN set -eu; \
    q="$(ls -d /opt/codeql/qlpacks/codeql/python-queries/*)"; \
    echo "precompiled files: $(find "$q" -name '*.qlx' | wc -l)"; \
    find "$q" -name '*.qlx' -delete; \
    HOME=/tmp codeql query compile --threads=0 --ram=8192 \
      "codeql/python-queries:codeql-suites/python-security-extended.qls" 2>&1 | tail -3; \
    chmod -R a+rwX /opt/codeql/qlpacks/codeql /tmp/.codeql; \
    du -sh /tmp/.codeql/compile-cache
```

Two variants use this image. They live in a tools directory outside the repository and differ
only in whether the command names the Python model pack:

```yaml
name: codeql-pr22750            # the class alone
tool: codeql
version: "2.27.1"
image: mcpvb/codeql-pr22750:2.27.1
base_image: mcpvb/codeql-mcp:2.27.1
dockerfile: models/codeql
languages: [python]
command: [run-codeql.sh, "{lang}", "{src}", "{out}"]
timeout_s: 3600
```

```yaml
name: codeql-pr22750-mcp        # the class and the rows
# ... as above, except:
command: [run-codeql.sh, "{lang}", "{src}", "{out}",
          "--additional-packs=/opt/mcpvb/models", "--model-packs=mcpvb/mcp-models"]
```

```sh
uv run mcpvb run --tools-dir <tools dir> --results-dir results/pr22750 \
  --variant codeql-pr22750 --variant codeql-pr22750-mcp --case mcpvb-0001 ... --case mcpvb-0028
uv run mcpvb score --tools-dir <tools dir> --results-dir results/pr22750 \
  --variant codeql-pr22750 --variant codeql-pr22750-mcp --case mcpvb-0001 ... --case mcpvb-0028
```

Two details of the image matter:

- The queries are resolved against the copy of the library inside the query pack, so that copy
  has to be patched too.
- The bundled queries are precompiled against the unchanged library. The precompiled files are
  removed so that the queries are compiled from source against the patched library. Compiling
  once in the image, with the `HOME` the harness uses, means that no run compiles a query again.

Checks that the image measures the pull request:

- On the patched library the test file of the pull request yields the same 12 sources as its
  `.expected` file.
- Two small files with one handler per pattern raise no alert as shipped, and with the class or
  the rows exactly the alerts each approach is expected to raise.
- Nothing the published images report is lost: every alert of `codeql` reappears with the class,
  and every alert of `codeql-mcp` with both, in each of the 56 runs. And every one of the 786
  alerts the class adds to CodeQL as shipped has a flow that starts in a function decorated with
  `tool`, `prompt` or `resource`.

## Limits

- The comparison was made by the author of the rows and of the benchmark.
- 28 cases from 23 repositories are a small sample, and the rows were developed on twelve of
  them.
- The rows are measured as the model pack of this repository, not as the files of #22703.
- The class is measured at one commit, on `codeql/python-all` 7.2.6 and not on the branch the
  pull request targets. A later version may cover the low-level `Server` or a decorator applied
  as a call.
- Only the `python-security-extended` suite is run.
- Detection means an alert of the right class in a function of the ground truth. That is coarse:
  in mcpvb-0014 all variants count as detecting the case, and only the class reports the flow
  from the tool argument.
- What the class gains for `py/xxe`, `py/xml-bomb`, `py/nosql-injection` and for `Context`
  parameters is shown on test files only.
- The raw results of the experiment are not part of the repository (`results/` is not
  versioned), so the alert figures on this page cannot be recomputed without running it.
