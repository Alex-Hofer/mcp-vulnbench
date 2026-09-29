# CodeQL plus the MCP models of this repository (variant codeql-mcp). It builds on the local image
# of the codeql variant; `mcpvb images` refuses to build it while that image is missing, so the
# base is never pulled from a registry.
FROM mcpvb/codeql:2.27.1
COPY mcp /opt/mcpvb/models/mcp
RUN chmod -R a+rX /opt/mcpvb/models
