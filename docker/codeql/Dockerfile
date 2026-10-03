# CodeQL CLI bundle (CLI plus standard query packs), pinned.
# Licence: the CodeQL CLI may be used on OSI-licensed open-source code and for academic research
# (https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md).
FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a

# The checksum is published next to the bundle (codeql-bundle-linux64.tar.gz.checksum.txt).
ARG CODEQL_BUNDLE=codeql-bundle-v2.27.1
ARG CODEQL_SHA256=1d380f79896ededc654c7b21fafb3360136f1aeb678ad4df4df9af3910c6b815
# Containers run as a non-root user: the bundle, including the precompiled queries, must be
# readable for everyone, otherwise CodeQL recompiles every query on every run.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl python3 \
 && rm -rf /var/lib/apt/lists/* \
 && curl -fsSL -o /tmp/codeql.tar.gz \
    "https://github.com/github/codeql-action/releases/download/${CODEQL_BUNDLE}/codeql-bundle-linux64.tar.gz" \
 && echo "${CODEQL_SHA256}  /tmp/codeql.tar.gz" | sha256sum -c - \
 && tar -xzf /tmp/codeql.tar.gz --no-same-owner -C /opt \
 && rm /tmp/codeql.tar.gz \
 && chmod -R a+rX /opt/codeql \
 && ln -s /opt/codeql/codeql /usr/local/bin/codeql

# CodeQL's TypeScript extractor needs Node.js. The checksum is published in
# https://nodejs.org/dist/v<version>/SHASUMS256.txt: change both together.
ARG NODE_VERSION=22.23.3
ARG NODE_SHA256=1084aa36196bba4c3a5e69a1ee388a6e4ff729dad09445fbcd434b28fe3c24af
RUN curl -fsSL -o /tmp/node.tar.gz \
    "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-x64.tar.gz" \
 && echo "${NODE_SHA256}  /tmp/node.tar.gz" | sha256sum -c - \
 && mkdir -p /opt/node \
 && tar -xzf /tmp/node.tar.gz --no-same-owner --strip-components=1 -C /opt/node \
 && rm /tmp/node.tar.gz \
 && chmod -R a+rX /opt/node \
 && ln -s /opt/node/bin/node /usr/local/bin/node
COPY run-codeql.sh /usr/local/bin/run-codeql.sh
RUN chmod 0755 /usr/local/bin/run-codeql.sh
