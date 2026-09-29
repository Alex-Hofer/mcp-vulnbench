# CodeQL CLI bundle (CLI plus standard query packs), pinned.
# Licence: the CodeQL CLI may be used on OSI-licensed open-source code and for academic research
# (https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md).
FROM debian:trixie-slim

ARG CODEQL_BUNDLE=codeql-bundle-v2.27.1
# Containers run as a non-root user: the bundle, including the precompiled queries, must be
# readable for everyone, otherwise CodeQL recompiles every query on every run.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl python3 \
 && rm -rf /var/lib/apt/lists/* \
 && curl -fsSL "https://github.com/github/codeql-action/releases/download/${CODEQL_BUNDLE}/codeql-bundle-linux64.tar.gz" \
    | tar -xz --no-same-owner -C /opt \
 && chmod -R a+rX /opt/codeql \
 && ln -s /opt/codeql/codeql /usr/local/bin/codeql
COPY run-codeql.sh /usr/local/bin/run-codeql.sh
RUN chmod 0755 /usr/local/bin/run-codeql.sh
