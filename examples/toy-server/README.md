# Toy server

Two versions of a tiny MCP server used by the tests: `vulnerable/` has a command injection in
`ping` and a path traversal in `read_note`; `fixed/` repairs both. The tests turn them into a git
repository with two commits. Line numbers are part of the test ground truth: do not reformat these
files (ruff excludes `examples/`).
