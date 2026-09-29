# mcp-vulnbench

An open benchmark of real, publicly disclosed vulnerabilities in open-source
[MCP](https://modelcontextprotocol.io) servers, and a harness that runs static analyzers on every
case in Docker and scores them.

Each case pins the vulnerable and the fixed commit, the CWE and the exact code location, so a tool
is measured on finding the bug *and* on recognizing the fix.

> Status: v0.1.0 – milestone 1 (26 Python cases; Semgrep, CodeQL, Bandit). Next: TypeScript
> cases and CodeQL models for MCP tool handlers.

## Results (v0.1.0)

26 publicly disclosed vulnerabilities in 21 open-source Python MCP server projects (12 path
traversal, 5 SSRF, 4 command injection, 3 SQL injection, 2 code injection), four analyzer variants
without any tuning (the [methodology](docs/methodology.md#tool-configuration) lists the few
deliberate settings):

| Variant | Cases (ok) | Detected | Recall | Fix recognized | Alarms/KLOC | Error rate |
|---|---:|---:|---:|---:|---:|---:|
| bandit | 25 | 4 | 16 % | 0 % (0/4) | 1.44 | 4 % |
| codeql | 26 | 1 | 4 % | 100 % (1/1) | 0.18 | 0 % |
| semgrep-default | 26 | 4 | 15 % | 0 % (0/4) | 1.19 | 0 % |
| semgrep-mcp | 26 | 5 | 19 % | 0 % (0/5) | 1.19 | 0 % |

![Recall per variant](docs/results-v0.1.0.svg)

- No variant finds any of the 12 path-traversal or the 2 code-injection cases; only the MCP rules
  find one of the 5 SSRF cases.
- What the tools do find is the textbook pattern: MCP input that ends up in a `subprocess` call
  or in an SQL string built with an f-string. Bandit and Semgrep then keep reporting the fixed code
  too: a specific warning such as `shell=True` disappears with the fix, but their generic rules
  fire on the call itself, whatever the fix changed around it.
- CodeQL's taint queries start from known sources such as the request objects of web frameworks.
  One query also treats the parameters of a package's public functions as input, which is how
  CodeQL finds mcpvb-0014 and recognizes its fix. Nothing tells CodeQL that an MCP tool argument is
  untrusted, so it reports nothing on the vulnerable paths of the other 25 servers.
- The Semgrep MCP rules (`ai/ai-best-practices/mcp-*`) treat the parameters of `@<server>.tool()`
  functions as sources, but Semgrep CE follows taint only within one function: as soon as a tool
  hands its argument to a helper, as most real servers do, the rules see nothing. The SSRF rule
  also knows only `requests` and `urllib` as sinks, not `httpx`, and there is no MCP rule for
  file paths.

Limitations: 26 cases is a small sample; one case moves a variant's recall by about four
percentage points, code injection is represented by two cases from one repository, and two of the
three SQL-injection cases (mcpvb-0011, mcpvb-0012) share a commit pair and their sink function,
so one finding there counts for both. Only Python servers and only static analyzers are measured;
MCP scanners that inspect the tool descriptions of running servers look for a different class of
problems and are not part of the benchmark. There is no precision column; the
[methodology](docs/methodology.md#why-there-is-no-precision) explains why and which figures
approximate false alarms instead. In two cases the fixed version
still contains a related weakness (mcpvb-0006: a second path traversal that was fixed later;
mcpvb-0022: private hosts stay reachable by design), so a persisting finding there is not
necessarily a missed fix. Bandit's two runs on fastmcp end in an error because its SARIF formatter
crashes on that repository ([PyCQA/bandit#1311](https://github.com/PyCQA/bandit/issues/1311)).

Full report with the per-case table: [docs/results-v0.1.0.md](docs/results-v0.1.0.md).

## Quick start

Requires [uv](https://docs.astral.sh/uv/) and a running Docker daemon.

```bash
uv sync
uv run mcpvb images          # builds the analyzer images locally (never pushed)
uv run mcpvb bench           # fetch -> run -> score -> report
# the report is written to results/latest/report.md
```

## Documentation

- [Design](docs/design.md)
- [Methodology](docs/methodology.md) – metric definitions
- [Adding a case](docs/curation.md)

## License

Code: MIT. Case annotations in `cases/`: CC BY 4.0 (see `LICENSE-DATA`). The analyzed projects keep
their own licenses; their code is not part of this repository.
