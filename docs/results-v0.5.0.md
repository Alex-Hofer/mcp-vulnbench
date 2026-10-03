# mcp-vulnbench results (v0.5.0)

Tools: bandit (bandit 1.9.4), codeql (codeql 2.27.1), semgrep-default (semgrep 1.178.0), semgrep-mcp (semgrep 1.178.0), codeql-mcp (codeql 2.27.1)

Cases: 66

## Overview

| Variant | Cases (ok) | Detected | Recall | Fix recognized | Alarms/KLOC | Error rate |
|---|---:|---:|---:|---:|---:|---:|
| bandit | 27 | 5 | 19 % | 20 % (1/5) | 1.44 | 4 % |
| codeql | 66 | 7 | 11 % | 86 % (6/7) | 0.16 | 0 % |
| codeql-mcp | 66 | 38 | 58 % | 50 % (19/38) | 1.32 | 0 % |
| semgrep-default | 66 | 12 | 18 % | 33 % (4/12) | 2.40 | 0 % |
| semgrep-mcp | 66 | 15 | 23 % | 27 % (4/15) | 3.67 | 0 % |

## Recall by class

| Variant | command-injection | path-traversal | ssrf | sql-injection | code-injection |
|---|---:|---:|---:|---:|---:|
| bandit | 80 % (4/5) | 0 % (0/13) | 0 % (0/4) | 33 % (1/3) | 0 % (0/2) |
| codeql | 25 % (6/24) | 5 % (1/20) | 0 % (0/17) | 0 % (0/3) | 0 % (0/2) |
| codeql-mcp | 88 % (21/24) | 50 % (10/20) | 35 % (6/17) | 33 % (1/3) | 0 % (0/2) |
| semgrep-default | 29 % (7/24) | 20 % (4/20) | 0 % (0/17) | 33 % (1/3) | 0 % (0/2) |
| semgrep-mcp | 29 % (7/24) | 20 % (4/20) | 18 % (3/17) | 33 % (1/3) | 0 % (0/2) |

## By split

| Variant | Half | Cases (ok) | Detected | Recall | Fix recognized | Alarms/KLOC |
|---|---|---:|---:|---:|---:|---:|
| bandit | dev | 12 | 2 | 17 % | 0 % (0/2) | 2.00 |
| bandit | test | 15 | 3 | 20 % | 33 % (1/3) | 0.65 |
| codeql | dev | 29 | 4 | 14 % | 75 % (3/4) | 0.15 |
| codeql | test | 37 | 3 | 8 % | 100 % (3/3) | 0.18 |
| codeql-mcp | dev | 29 | 15 | 52 % | 47 % (7/15) | 0.93 |
| codeql-mcp | test | 37 | 23 | 62 % | 52 % (12/23) | 1.78 |
| semgrep-default | dev | 29 | 5 | 17 % | 0 % (0/5) | 3.09 |
| semgrep-default | test | 37 | 7 | 19 % | 57 % (4/7) | 1.59 |
| semgrep-mcp | dev | 29 | 6 | 21 % | 0 % (0/6) | 4.72 |
| semgrep-mcp | test | 37 | 9 | 24 % | 44 % (4/9) | 2.45 |

## By language and split

| Variant | Language | Half | Cases (ok) | Detected | Recall | Fix recognized | Alarms/KLOC |
|---|---|---|---:|---:|---:|---:|---:|
| bandit | javascript/typescript | dev | 0 | 0 | – | – | – |
| bandit | javascript/typescript | test | 0 | 0 | – | – | – |
| bandit | python | dev | 12 | 2 | 17 % | 0 % (0/2) | 2.00 |
| bandit | python | test | 15 | 3 | 20 % | 33 % (1/3) | 0.65 |
| codeql | javascript/typescript | dev | 17 | 3 | 18 % | 67 % (2/3) | 0.20 |
| codeql | javascript/typescript | test | 21 | 3 | 14 % | 100 % (3/3) | 0.08 |
| codeql | python | dev | 12 | 1 | 8 % | 100 % (1/1) | 0.07 |
| codeql | python | test | 16 | 0 | 0 % | – | 0.27 |
| codeql-mcp | javascript/typescript | dev | 17 | 11 | 65 % | 55 % (6/11) | 1.23 |
| codeql-mcp | javascript/typescript | test | 21 | 14 | 67 % | 79 % (11/14) | 2.62 |
| codeql-mcp | python | dev | 12 | 4 | 33 % | 25 % (1/4) | 0.54 |
| codeql-mcp | python | test | 16 | 9 | 56 % | 11 % (1/9) | 1.09 |
| semgrep-default | javascript/typescript | dev | 17 | 3 | 18 % | 0 % (0/3) | 3.93 |
| semgrep-default | javascript/typescript | test | 21 | 4 | 19 % | 75 % (3/4) | 2.94 |
| semgrep-default | python | dev | 12 | 2 | 17 % | 0 % (0/2) | 2.00 |
| semgrep-default | python | test | 16 | 3 | 19 % | 33 % (1/3) | 0.49 |
| semgrep-mcp | javascript/typescript | dev | 17 | 3 | 18 % | 0 % (0/3) | 6.81 |
| semgrep-mcp | javascript/typescript | test | 21 | 6 | 29 % | 50 % (3/6) | 4.82 |
| semgrep-mcp | python | dev | 12 | 3 | 25 % | 0 % (0/3) | 2.01 |
| semgrep-mcp | python | test | 16 | 3 | 19 % | 33 % (1/3) | 0.49 |

## Run status

| Variant | ok | error | timeout | unsupported | unavailable |
|---|---:|---:|---:|---:|---:|
| bandit | 54 | 2 | 0 | 76 | 0 |
| codeql | 132 | 0 | 0 | 0 | 0 |
| codeql-mcp | 132 | 0 | 0 | 0 | 0 |
| semgrep-default | 132 | 0 | 0 | 0 | 0 |
| semgrep-mcp | 132 | 0 | 0 | 0 | 0 |

## Details

| Variant | Recall (file level) | Recall (any class) | Recall (javascript) | Recall (python) | Recall (typescript) | Fix recognized (no caveat) | Median alarms/case | Unclassified findings |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| bandit | 26 % | 22 % | – | 19 % | – | 20 % (1/5) | 2.00 | 602 |
| codeql | 14 % | 11 % | 33 % | 4 % | 14 % | 100 % (4/4) | 0.00 | 436 |
| codeql-mcp | 64 % | 61 % | 100 % | 46 % | 63 % | 48 % (14/29) | 3.00 | 696 |
| semgrep-default | 18 % | 27 % | 0 % | 18 % | 20 % | 25 % (2/8) | 2.50 | 427 |
| semgrep-mcp | 27 % | 35 % | 0 % | 21 % | 26 % | 20 % (2/10) | 12.50 | 430 |

## Cases

✓ detected, fix recognized · ◐ detected, fix not recognized · ● detected, fixed version not assessed · ✗ missed · err / t/o / n/s / n/a: run of the vulnerable version failed, timed out, is unsupported or had no sources

† 14 of 66 cases: the notes of the case carry a caveat, mostly a fixed version that keeps a weakness of the same class, so a finding that persists there is not necessarily a missed fix ([curation.md](curation.md#fixes-that-leave-something-behind)).

| Case | Class | Half | bandit | codeql | codeql-mcp | semgrep-default | semgrep-mcp |
|---|---|---|---|---|---|---|---|
| mcpvb-0001 | command-injection | dev | ◐ | ✗ | ✗ | ◐ | ◐ |
| mcpvb-0002 | command-injection | test | ◐ | ✗ | ◐ | ◐ | ◐ |
| mcpvb-0003 | command-injection | test | ✗ | ✗ | ✗ | ✗ | ✗ |
| mcpvb-0004 | path-traversal | dev | ✗ | ✗ | ✗ | ✗ | ✗ |
| mcpvb-0005 | path-traversal | dev | ✗ | ✗ | ◐ | ✗ | ✗ |
| mcpvb-0006 † | path-traversal | test | ✗ | ✗ | ✗ | ✗ | ✗ |
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
| mcpvb-0022 † | ssrf | test | ✗ | ✗ | ✗ | ✗ | ✗ |
| mcpvb-0023 | ssrf | dev | ✗ | ✗ | ◐ | ✗ | ◐ |
| mcpvb-0024 | ssrf | test | err | ✗ | ✗ | ✗ | ✗ |
| mcpvb-0025 | sql-injection | test | ◐ | ✗ | ◐ | ◐ | ◐ |
| mcpvb-0026 | code-injection | test | ✗ | ✗ | ✗ | ✗ | ✗ |
| mcpvb-0027 | command-injection | test | ✓ | ✗ | ✓ | ✓ | ✓ |
| mcpvb-0028 | path-traversal | test | ✗ | ✗ | ◐ | ✗ | ✗ |
| mcpvb-0029 † | command-injection | test | n/s | ✗ | ✓ | ✗ | ✗ |
| mcpvb-0030 | command-injection | test | n/s | ✓ | ✓ | ✗ | ✗ |
| mcpvb-0031 | command-injection | test | n/s | ✗ | ✓ | ✓ | ✓ |
| mcpvb-0032 | command-injection | dev | n/s | ✓ | ✓ | ✗ | ✗ |
| mcpvb-0033 | command-injection | test | n/s | ✗ | ✓ | ✗ | ✗ |
| mcpvb-0034 | command-injection | test | n/s | ✗ | ✓ | ✗ | ✗ |
| mcpvb-0035 † | command-injection | test | n/s | ✓ | ✓ | ✗ | ✗ |
| mcpvb-0036 † | command-injection | test | n/s | ✗ | ✓ | ✓ | ✓ |
| mcpvb-0037 † | command-injection | test | n/s | ✗ | ✓ | ✓ | ✓ |
| mcpvb-0038 | command-injection | dev | n/s | ✗ | ✓ | ✗ | ✗ |
| mcpvb-0039 | command-injection | test | n/s | ✗ | ✓ | ✗ | ✗ |
| mcpvb-0040 | command-injection | dev | n/s | ✗ | ✓ | ✗ | ✗ |
| mcpvb-0041 † | command-injection | dev | n/s | ✗ | ✓ | ✗ | ✗ |
| mcpvb-0042 | command-injection | dev | n/s | ✗ | ✗ | ✗ | ✗ |
| mcpvb-0043 | command-injection | dev | n/s | ✗ | ✓ | ✗ | ✗ |
| mcpvb-0044 | command-injection | dev | n/s | ✗ | ✓ | ✗ | ✗ |
| mcpvb-0045 | command-injection | test | n/s | ✗ | ✓ | ✗ | ✗ |
| mcpvb-0046 | command-injection | test | n/s | ✓ | ✓ | ✗ | ✗ |
| mcpvb-0047 † | command-injection | dev | n/s | ✓ | ◐ | ✗ | ✗ |
| mcpvb-0048 | path-traversal | test | n/s | ✗ | ✗ | ✗ | ✗ |
| mcpvb-0049 † | path-traversal | dev | n/s | ✗ | ◐ | ◐ | ◐ |
| mcpvb-0050 | path-traversal | test | n/s | ✗ | ✗ | ✗ | ✗ |
| mcpvb-0051 † | path-traversal | dev | n/s | ◐ | ◐ | ◐ | ◐ |
| mcpvb-0052 | path-traversal | dev | n/s | ✗ | ✗ | ◐ | ◐ |
| mcpvb-0053 | path-traversal | test | n/s | ✗ | ◐ | ◐ | ◐ |
| mcpvb-0054 † | path-traversal | test | n/s | ✗ | ✗ | ✗ | ✗ |
| mcpvb-0055 | ssrf | dev | n/s | ✗ | ✗ | ✗ | ✗ |
| mcpvb-0056 | ssrf | test | n/s | ✗ | ✗ | ✗ | ✗ |
| mcpvb-0057 † | ssrf | dev | n/s | ✗ | ✗ | ✗ | ✗ |
| mcpvb-0058 | ssrf | dev | n/s | ✗ | ✗ | ✗ | ✗ |
| mcpvb-0059 | ssrf | dev | n/s | ✗ | ◐ | ✗ | ✗ |
| mcpvb-0060 | ssrf | test | n/s | ✗ | ◐ | ✗ | ✗ |
| mcpvb-0061 | ssrf | test | n/s | ✗ | ✗ | ✗ | ◐ |
| mcpvb-0062 † | ssrf | test | n/s | ✗ | ✗ | ✗ | ◐ |
| mcpvb-0063 | ssrf | dev | n/s | ✗ | ✗ | ✗ | ✗ |
| mcpvb-0064 † | ssrf | test | n/s | ✗ | ◐ | ✗ | ✗ |
| mcpvb-0065 | ssrf | dev | n/s | ✗ | ◐ | ✗ | ✗ |
| mcpvb-0066 | ssrf | test | n/s | ✗ | ✗ | ✗ | ✗ |

![Recall per variant](results-v0.5.0.svg)

Metric definitions: [methodology.md](methodology.md)
