# CodeQL plus the MCP models of this repository (variant codeql-mcp). It builds on the local image
# of the codeql variant; `mcpvb images` refuses to build it while that image is missing, so the
# base is never pulled from a registry.
FROM mcpvb/codeql:2.27.1
# A base built before run-codeql.sh passed analyze options through would silently ignore the model
# pack and make codeql-mcp identical to codeql: refuse to build on it.
RUN grep -q 'shift 3' /usr/local/bin/run-codeql.sh \
 || { echo "mcpvb/codeql:2.27.1 is outdated: run 'uv run mcpvb images --variant codeql'" >&2; exit 1; }
COPY mcp /opt/mcpvb/models/mcp
RUN chmod -R a+rX /opt/mcpvb/models
