# 0002 – No naive precision

Status: accepted, 2026-09

## Context
The ground truth marks where the known vulnerability is. Other findings in the same repository may
be real unknown vulnerabilities or true but unrelated issues. Counting them as false positives
would punish tools for finding real bugs.

## Decision
Do not report precision. Approximate false alarms from two directions instead: fix recognition
(does the tool still report the fixed code?) and alarm volume (classified findings per KLOC).

## Consequences
- No single F1 score; the report shows recall, fix recognition and alarm volume side by side.
- No manual labeling of every finding is needed, which keeps the benchmark scalable.
