# Semgrep CE plus rules from semgrep/semgrep-rules, both pinned.
# The rules are licensed under the Semgrep Rules License v1.0: they are downloaded while this image
# is built and must never be committed to the repository or pushed in a public image.
FROM semgrep/semgrep:1.178.0

ARG RULES_COMMIT=a84ff9cc2453ca91d581380de4b8b3f272f6f4be
ADD https://github.com/semgrep/semgrep-rules/archive/${RULES_COMMIT}.tar.gz /tmp/semgrep-rules.tar.gz

USER root
RUN set -eu; \
    mkdir -p /tmp/sr /rules/default /rules/mcp; \
    tar -xzf /tmp/semgrep-rules.tar.gz -C /tmp/sr; \
    cd "/tmp/sr/semgrep-rules-${RULES_COMMIT}"; \
    for dir in python/*/security; do mkdir -p "/rules/default/$dir"; cp -R "$dir/." "/rules/default/$dir/"; done; \
    for dir in ai/ai-best-practices/mcp-*; do mkdir -p "/rules/mcp/$dir"; cp -R "$dir/." "/rules/mcp/$dir/"; done; \
    find /rules -type f ! -name '*.yaml' ! -name '*.yml' -delete; \
    rm -rf /tmp/sr /tmp/semgrep-rules.tar.gz; \
    chmod -R a+rX /rules
