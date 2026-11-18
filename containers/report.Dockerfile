ARG MAVEN_IMAGE=maven:3.9.11-eclipse-temurin-21
ARG SCANNER_IMAGE=ghcr.io/google/osv-scanner:v2.7.1
FROM ${SCANNER_IMAGE} AS scanner
FROM ${MAVEN_IMAGE}
ARG STRANDS_VERSION=
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/fletcher/venv \
    && if [ -n "$STRANDS_VERSION" ]; then /opt/fletcher/venv/bin/pip install "strands-agents==$STRANDS_VERSION"; fi
ENV PATH="/opt/fletcher/venv/bin:$PATH"
COPY --from=scanner /osv-scanner /usr/local/bin/osv-scanner
COPY fletcher.py /opt/fletcher/fletcher.py
