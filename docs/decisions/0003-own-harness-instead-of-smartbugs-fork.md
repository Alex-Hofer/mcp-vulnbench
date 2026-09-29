# 0003 – Own lean harness instead of a SmartBugs fork

Status: accepted, 2026-09

## Context
SmartBugs runs analyzers on Solidity contracts in Docker and normalizes their output. Its design
fits, but most of its code handles Solidity specifics (compiler versions, bytecode versus source
modes, one parser per tool).

## Decision
Build a small harness that keeps the SmartBugs principles – tool configurations as data, one
container per run, explicit statuses – and nothing Solidity-specific.

## Consequences
- Less code, and every part is explainable; tools plug in through `tools/<variant>/tool.yaml`.
- No reuse of SmartBugs parsers: all analyzers here write SARIF (ADR 0001).
