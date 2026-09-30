# mcp-vulnbench results (v0.2.0)

Tools: bandit (bandit 1.9.4), codeql (codeql 2.27.1), semgrep-default (semgrep 1.178.0), semgrep-mcp (semgrep 1.178.0), codeql-mcp (codeql 2.27.1)

Cases: 28

## Overview

| Variant | Cases (ok) | Detected | Recall | Fix recognized | Alarms/KLOC | Error rate |
|---|---:|---:|---:|---:|---:|---:|
| bandit | 27 | 5 | 19 % | 20 % (1/5) | 1.44 | 4 % |
| codeql | 28 | 1 | 4 % | 100 % (1/1) | 0.17 | 0 % |
| codeql-mcp | 28 | 13 | 46 % | 15 % (2/13) | 0.82 | 0 % |
| semgrep-default | 28 | 5 | 18 % | 20 % (1/5) | 1.22 | 0 % |
| semgrep-mcp | 28 | 6 | 21 % | 17 % (1/6) | 1.22 | 0 % |

## Recall by class

| Variant | command-injection | path-traversal | ssrf | sql-injection | code-injection |
|---|---:|---:|---:|---:|---:|
| bandit | 80 % (4/5) | 0 % (0/13) | 0 % (0/4) | 33 % (1/3) | 0 % (0/2) |
| codeql | 20 % (1/5) | 0 % (0/13) | 0 % (0/5) | 0 % (0/3) | 0 % (0/2) |
| codeql-mcp | 60 % (3/5) | 54 % (7/13) | 40 % (2/5) | 33 % (1/3) | 0 % (0/2) |
| semgrep-default | 80 % (4/5) | 0 % (0/13) | 0 % (0/5) | 33 % (1/3) | 0 % (0/2) |
| semgrep-mcp | 80 % (4/5) | 0 % (0/13) | 20 % (1/5) | 33 % (1/3) | 0 % (0/2) |

## By split

| Variant | Half | Cases (ok) | Detected | Recall | Fix recognized | Alarms/KLOC |
|---|---|---:|---:|---:|---:|---:|
| bandit | dev | 12 | 2 | 17 % | 0 % (0/2) | 2.00 |
| bandit | test | 15 | 3 | 20 % | 33 % (1/3) | 0.65 |
| codeql | dev | 12 | 1 | 8 % | 100 % (1/1) | 0.07 |
| codeql | test | 16 | 0 | 0 % | – | 0.27 |
| codeql-mcp | dev | 12 | 4 | 33 % | 25 % (1/4) | 0.54 |
| codeql-mcp | test | 16 | 9 | 56 % | 11 % (1/9) | 1.09 |
| semgrep-default | dev | 12 | 2 | 17 % | 0 % (0/2) | 2.00 |
| semgrep-default | test | 16 | 3 | 19 % | 33 % (1/3) | 0.49 |
| semgrep-mcp | dev | 12 | 3 | 25 % | 0 % (0/3) | 2.01 |
| semgrep-mcp | test | 16 | 3 | 19 % | 33 % (1/3) | 0.49 |

## Run status

| Variant | ok | error | timeout | unsupported | unavailable |
|---|---:|---:|---:|---:|---:|
| bandit | 54 | 2 | 0 | 0 | 0 |
| codeql | 56 | 0 | 0 | 0 | 0 |
| codeql-mcp | 56 | 0 | 0 | 0 | 0 |
| semgrep-default | 56 | 0 | 0 | 0 | 0 |
| semgrep-mcp | 56 | 0 | 0 | 0 | 0 |

## Details

| Variant | Recall (file level) | Recall (any class) | Recall (python) | Median alarms/case | Unclassified findings |
|---|---:|---:|---:|---:|---:|
| bandit | 26 % | 22 % | 19 % | 2.00 | 602 |
| codeql | 4 % | 4 % | 4 % | 0.00 | 88 |
| codeql-mcp | 54 % | 46 % | 46 % | 2.00 | 243 |
| semgrep-default | 18 % | 21 % | 18 % | 1.50 | 148 |
| semgrep-mcp | 21 % | 25 % | 21 % | 1.50 | 149 |

## Cases

✓ detected, fix recognized · ◐ detected, fix not recognized · ● detected, fixed version not assessed · ✗ missed · err / t/o / n/s / n/a: run of the vulnerable version failed, timed out, is unsupported or had no sources

| Case | Class | Half | bandit | codeql | codeql-mcp | semgrep-default | semgrep-mcp |
|---|---|---|---|---|---|---|---|
| mcpvb-0001 | command-injection | dev | ◐ | ✗ | ✗ | ◐ | ◐ |
| mcpvb-0002 | command-injection | test | ◐ | ✗ | ◐ | ◐ | ◐ |
| mcpvb-0003 | command-injection | test | ✗ | ✗ | ✗ | ✗ | ✗ |
| mcpvb-0004 | path-traversal | dev | ✗ | ✗ | ✗ | ✗ | ✗ |
| mcpvb-0005 | path-traversal | dev | ✗ | ✗ | ◐ | ✗ | ✗ |
| mcpvb-0006 | path-traversal | test | ✗ | ✗ | ✗ | ✗ | ✗ |
| mcpvb-0007 | path-traversal | test | ✗ | ✗ | ✗ | ✗ | ✗ |
| mcpvb-0008 | path-traversal | dev | ✗ | ✗ | ✗ | ✗ | ✗ |
| mcpvb-0009 | ssrf | test | ✗ | ✗ | ◐ | ✗ | ✗ |
| mcpvb-0010 | ssrf | dev | ✗ | ✗ | ✗ | ✗ | ✗ |
| mcpvb-0011 | sql-injection | dev | ✗ | ✗ | ✗ | ✗ | ✗ |
| mcpvb-0012 | sql-injection | dev | ✗ | ✗ | ✗ | ✗ | ✗ |
| mcpvb-0013 | code-injection | test | ✗ | ✗ | ✗ | ✗ | ✗ |
| mcpvb-0014 | command-injection | dev | ◐ | ✓ | ✓ | ◐ | ◐ |
| mcpvb-0015 | path-traversal | test | ✗ | ✗ | ◐ | ✗ | ✗ |
| mcpvb-0016 | path-traversal | dev | ✗ | ✗ | ✗ | ✗ | ✗ |
| mcpvb-0017 | path-traversal | test | ✗ | ✗ | ◐ | ✗ | ✗ |
| mcpvb-0018 | path-traversal | test | ✗ | ✗ | ◐ | ✗ | ✗ |
| mcpvb-0019 | path-traversal | test | ✗ | ✗ | ◐ | ✗ | ✗ |
| mcpvb-0020 | path-traversal | dev | ✗ | ✗ | ◐ | ✗ | ✗ |
| mcpvb-0021 | path-traversal | dev | ✗ | ✗ | ✗ | ✗ | ✗ |
| mcpvb-0022 | ssrf | test | ✗ | ✗ | ✗ | ✗ | ✗ |
| mcpvb-0023 | ssrf | dev | ✗ | ✗ | ◐ | ✗ | ◐ |
| mcpvb-0024 | ssrf | test | err | ✗ | ✗ | ✗ | ✗ |
| mcpvb-0025 | sql-injection | test | ◐ | ✗ | ◐ | ◐ | ◐ |
| mcpvb-0026 | code-injection | test | ✗ | ✗ | ✗ | ✗ | ✗ |
| mcpvb-0027 | command-injection | test | ✓ | ✗ | ✓ | ✓ | ✓ |
| mcpvb-0028 | path-traversal | test | ✗ | ✗ | ◐ | ✗ | ✗ |

![Recall per variant](results-v0.2.0.svg)

Metric definitions: [methodology.md](methodology.md)
