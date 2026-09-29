#!/bin/sh
# Usage: run-codeql.sh <codeql-language> <source-root> <output-dir> [analyze options...]
# The analyze options are how codeql-mcp adds its model pack; everything else is identical.
set -eu
lang="$1"
src="$2"
out="$3"
shift 3
db="$(mktemp -d)/db"
codeql database create "$db" --language="$lang" --source-root="$src" \
  --threads=0 --ram=3072 --overwrite 1>&2
codeql database analyze "$db" "codeql/${lang}-queries:codeql-suites/${lang}-security-extended.qls" \
  --format=sarif-latest --output="$out/raw.sarif" --threads=0 --ram=3072 "$@" 1>&2
