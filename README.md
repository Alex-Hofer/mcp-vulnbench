# mcp-vulnbench

An open benchmark of real, publicly disclosed vulnerabilities in open-source
[MCP](https://modelcontextprotocol.io) servers, and a harness that runs static analyzers on every
case in Docker and scores them.

Each case pins the vulnerable and the fixed commit, the CWE and the exact code location, so a tool
is measured on finding the bug *and* on recognizing the fix.

> Status: work in progress – milestone 1 (Python cases; Semgrep, CodeQL, Bandit).

## Quick start

```bash
uv sync
uv run mcpvb --help
```

## Documentation

- [Design](docs/design.md)
- [Methodology](docs/methodology.md) – metric definitions
- [Adding a case](docs/curation.md)

## License

Code: MIT. Case annotations in `cases/`: CC BY 4.0 (see `LICENSE-DATA`). The analyzed projects keep
their own licenses; their code is not part of this repository.
