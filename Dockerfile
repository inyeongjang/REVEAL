FROM node:22-bookworm-slim AS node-runtime

FROM python:3.12-slim-bookworm

ARG SYFT_VERSION=v1.44.0
ARG GRYPE_VERSION=v0.112.0
ARG CODEQL_VERSION=2.25.5

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    REVEAL_SYFT_PATH=/usr/local/bin/syft \
    REVEAL_GRYPE_PATH=/usr/local/bin/grype \
    REVEAL_CODEQL_PATH=/usr/local/bin/codeql \
    REVEAL_DOCKER_PATH=/usr/bin/docker

# Install Node.js 22 and npm from the official Node image.
COPY --from=node-runtime /usr/local/bin/node /usr/local/bin/node
COPY --from=node-runtime /usr/local/lib/node_modules /usr/local/lib/node_modules

RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && ln -s /usr/local/lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx

# Install system packages and Docker CLI.
RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        bash \
        ca-certificates \
        curl \
        git \
        gnupg \
        libatomic1 \
        unzip \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg \
        -o /etc/apt/keyrings/docker.asc \
    && chmod a+r /etc/apt/keyrings/docker.asc \
    && printf '%s\n' \
        'Types: deb' \
        'URIs: https://download.docker.com/linux/debian' \
        'Suites: bookworm' \
        'Components: stable' \
        "Architectures: $(dpkg --print-architecture)" \
        'Signed-By: /etc/apt/keyrings/docker.asc' \
        > /etc/apt/sources.list.d/docker.sources \
    && apt-get update \
    && apt-get install --yes --no-install-recommends docker-ce-cli \
    && rm -rf /var/lib/apt/lists/*

# Install Syft and Grype.
RUN curl -sSfL https://get.anchore.io/syft \
        | sh -s -- -b /usr/local/bin "${SYFT_VERSION}" \
    && curl -sSfL https://get.anchore.io/grype \
        | sh -s -- -b /usr/local/bin "${GRYPE_VERSION}"

# Install CodeQL CLI.
RUN architecture="$(dpkg --print-architecture)" \
    && if [ "${architecture}" != "amd64" ]; then \
        echo "CodeQL image currently supports amd64 only; got ${architecture}." >&2; \
        exit 1; \
    fi \
    && curl -fsSL \
        "https://github.com/github/codeql-cli-binaries/releases/download/v${CODEQL_VERSION}/codeql-linux64.zip" \
        -o /tmp/codeql.zip \
    && unzip -q /tmp/codeql.zip -d /opt \
    && ln -s /opt/codeql/codeql /usr/local/bin/codeql \
    && rm /tmp/codeql.zip

WORKDIR /workspace

# Install REVEAL and its development dependencies.
COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN python -m pip install --upgrade pip \
    && python -m pip install --editable ".[dev]"

# Pre-fetch CodeQL taint pack dependencies at build time (persists in image)
RUN codeql pack install -- src/reveal/resources/codeql/javascript/taint

# Verify all required development tools.
RUN python --version \
    && node --version \
    && npm --version \
    && reveal --version \
    && syft version \
    && grype version \
    && codeql version \
    && docker --version

CMD ["bash"]
