# Adding a case

## Criteria
A case is added only if all of these hold:
1. There is a public advisory (CVE or GHSA), or the vulnerability is part of a published research
   dataset and has a public fix.
2. The repository has an OSI-approved license (SPDX id listed in `src/mcpvb/licenses.py`).
3. The vulnerable and the fixed commit can be identified exactly.
4. The vulnerability belongs to one of the five classes (see [design.md](design.md)).
5. It is in the server code and reachable from an MCP tool handler.
6. The fix changes code, not only documentation or configuration.

At most three cases per repository.

## Steps
1. Read the advisory:
   `gh api /advisories/<GHSA-id> --jq '{summary, cve_id, cwes: [.cwes[].cwe_id], vulnerabilities, references}'`
2. Mirror the repository once: `git clone --bare <repo-url> .cache/curate/<name>`
3. Find the fix commit (advisory references, the pull request, or the first patched release tag).
   For a single-commit fix the vulnerable commit is its parent:
   `git -C .cache/curate/<name> rev-parse <fix>^`. For squashed or multi-commit fixes take the last
   commit before the fix.
4. Get the function ranges of the affected file in both versions:
   `git -C .cache/curate/<name> show <sha>:<path> > .cache/curate/snippet.py`
   `uv run mcpvb functions .cache/curate/snippet.py`
   A location covers a function the fix changed, from its first decorator line to its last line.
   In monorepos set `subdir` to the server folder; `file` is then relative to `subdir`.
5. Write `cases/mcpvb-NNNN/case.yaml` (template below), then run
   `uv run mcpvb validate` and `uv run mcpvb fetch --case mcpvb-NNNN`.
6. Commit one case per commit: `data: add mcpvb-NNNN (CVE-...)`.

## Template
```yaml
id: mcpvb-NNNN
title: "Command injection in <tool> of <server>"
advisories: [CVE-YYYY-NNNNN, GHSA-xxxx-xxxx-xxxx]
repo: https://github.com/<owner>/<repo>
license: MIT
language: python
subdir: null
class: command-injection
cwe: CWE-78
mcp_tool: <tool name>
vulnerable:
  commit: <40-character sha>
  locations:
    - {file: <path>, function: <name>, lines: [<start>, <end>]}
fixed:
  commit: <40-character sha>
  locations:
    - {file: <path>, function: <name>, lines: [<start>, <end>]}
source: ghsa
split: null
notes: ""
```
