FROM python:3.12-slim-bookworm

ARG GO_VERSION=1.23.7
ARG FFUF_VERSION=v2.1.0
ARG SUBFINDER_VERSION=v2.6.8
ARG HTTPX_VERSION=v1.6.10
ARG NUCLEI_VERSION=v3.3.8
ARG KATANA_VERSION=v1.1.2
ARG ZAP_VERSION=2.16.1

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_BREAK_SYSTEM_PACKAGES=1 \
    GOPATH=/go \
    GOBIN=/usr/local/bin \
    PATH="/usr/local/go/bin:/go/bin:${PATH}" \
    NUCLEI_TEMPLATES=/opt/nuclei-templates

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    build-essential \
    ca-certificates \
    chromium \
    curl \
    dnsutils \
    git \
    jq \
    libffi-dev \
    libpcap-dev \
    libssl-dev \
    netcat-openbsd \
    nmap \
    nodejs \
    npm \
    openjdk-17-jre-headless \
    perl \
    procps \
    python3-dev \
    ruby-full \
    unzip \
    wget \
    && rm -rf /var/lib/apt/lists/*

RUN arch="$(dpkg --print-architecture)" && \
    case "$arch" in \
      amd64) go_arch="amd64" ;; \
      arm64) go_arch="arm64" ;; \
      *) echo "Unsupported architecture: $arch" >&2; exit 1 ;; \
    esac && \
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${go_arch}.tar.gz" -o /tmp/go.tgz && \
    tar -C /usr/local -xzf /tmp/go.tgz && \
    rm -f /tmp/go.tgz

RUN python3 -m pip install --no-cache-dir --upgrade pip setuptools wheel && \
    python3 -m pip install --no-cache-dir \
      arjun \
      httpie \
      mitmproxy \
      wafw00f

RUN npm install -g newman wscat

RUN go install "github.com/ffuf/ffuf/v2@${FFUF_VERSION}" && \
    go install "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION}" && \
    go install "github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION}" && \
    go install "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION}" && \
    go install "github.com/projectdiscovery/katana/cmd/katana@${KATANA_VERSION}"

RUN mkdir -p /opt/tools /opt/wordlists /opt/runtime && \
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git /opt/wordlists/SecLists && \
    git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git /opt/nuclei-templates && \
    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/tools/sqlmap && \
    ln -s /opt/tools/sqlmap/sqlmap.py /usr/local/bin/sqlmap && \
    git clone --depth 1 https://github.com/sullo/nikto.git /opt/tools/nikto && \
    ln -s /opt/tools/nikto/program/nikto.pl /usr/local/bin/nikto && \
    git clone --depth 1 https://github.com/maurosoria/dirsearch.git /opt/tools/dirsearch && \
    printf '#!/usr/bin/env bash\npython3 /opt/tools/dirsearch/dirsearch.py "$@"\n' > /usr/local/bin/dirsearch && \
    chmod +x /usr/local/bin/dirsearch && \
    git clone --depth 1 https://github.com/GerbenJavado/LinkFinder.git /opt/tools/LinkFinder && \
    python3 -m pip install --no-cache-dir -r /opt/tools/LinkFinder/requirements.txt && \
    printf '#!/usr/bin/env bash\npython3 /opt/tools/LinkFinder/linkfinder.py "$@"\n' > /usr/local/bin/linkfinder && \
    chmod +x /usr/local/bin/linkfinder && \
    git clone --depth 1 https://github.com/ticarpi/jwt_tool.git /opt/tools/jwt_tool && \
    printf '#!/usr/bin/env bash\npython3 /opt/tools/jwt_tool/jwt_tool.py "$@"\n' > /usr/local/bin/jwt_tool && \
    chmod +x /usr/local/bin/jwt_tool && \
    git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/tools/testssl.sh && \
    ln -s /opt/tools/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

RUN curl -fsSL "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz" -o /tmp/zap.tgz && \
    tar -xzf /tmp/zap.tgz -C /opt && \
    mv "/opt/ZAP_${ZAP_VERSION}" /opt/zap && \
    ln -s /opt/zap/zap.sh /usr/local/bin/zap.sh && \
    ln -s /opt/zap/zap-baseline.py /usr/local/bin/zap-baseline.py && \
    ln -s /opt/zap/zap-full-scan.py /usr/local/bin/zap-full-scan.py && \
    ln -s /opt/zap/zap-api-scan.py /usr/local/bin/zap-api-scan.py && \
    rm -f /tmp/zap.tgz

COPY runtime/entrypoint.sh /opt/runtime/entrypoint.sh
COPY runtime/healthcheck.sh /opt/runtime/healthcheck.sh

RUN chmod +x /opt/runtime/entrypoint.sh /opt/runtime/healthcheck.sh

WORKDIR /workspace

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=5 CMD ["/opt/runtime/healthcheck.sh"]
ENTRYPOINT ["/opt/runtime/entrypoint.sh"]
