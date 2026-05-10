FROM golang:1.23-bookworm AS go-tools

ARG FFUF_VERSION=v2.1.0
ARG SUBFINDER_VERSION=v2.6.8
ARG HTTPX_VERSION=v1.6.10
ARG DNSX_VERSION=v1.2.1
ARG NUCLEI_VERSION=v3.3.8
ARG KATANA_VERSION=v1.1.2
ARG GRPCURL_VERSION=v1.9.2

RUN go install "github.com/ffuf/ffuf/v2@${FFUF_VERSION}" && \
    go install "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@${SUBFINDER_VERSION}" && \
    go install "github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION}" && \
    go install "github.com/projectdiscovery/dnsx/cmd/dnsx@${DNSX_VERSION}" && \
    go install "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION}" && \
    go install "github.com/projectdiscovery/katana/cmd/katana@${KATANA_VERSION}" && \
    go install "github.com/fullstorydev/grpcurl/cmd/grpcurl@${GRPCURL_VERSION}"

FROM alpine/git:2.45.2 AS wordlists

RUN git clone --depth 1 https://github.com/danielmiessler/SecLists.git /SecLists

FROM python:3.12-slim-bookworm AS runtime
ARG WEBSOCAT_VERSION=v1.14.1

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_BREAK_SYSTEM_PACKAGES=1 \
    PLAYWRIGHT_BROWSERS_PATH=0 \
    NUCLEI_TEMPLATES=/opt/nuclei-templates

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    chromium \
    curl \
    dnsutils \
    git \
    hashcat \
    jq \
    libpcap0.8 \
    netcat-openbsd \
    nmap \
    openssl \
    ocl-icd-libopencl1 \
    pocl-opencl-icd \
    perl \
    procps \
    unzip \
    wget \
    whois \
    && rm -rf /var/lib/apt/lists/*

COPY --from=go-tools /go/bin/* /usr/local/bin/

RUN arch="$(dpkg --print-architecture)" && \
    case "$arch" in \
      amd64) websocat_arch="x86_64-unknown-linux-musl" ;; \
      arm64) websocat_arch="aarch64-unknown-linux-musl" ;; \
      *) echo "Unsupported architecture for websocat: $arch" >&2; exit 1 ;; \
    esac && \
    curl -fsSL "https://github.com/vi/websocat/releases/download/${WEBSOCAT_VERSION}/websocat.${websocat_arch}" -o /usr/local/bin/websocat && \
    chmod +x /usr/local/bin/websocat

RUN python3 -m pip install --no-cache-dir --upgrade pip setuptools wheel && \
    python3 -m pip install --no-cache-dir \
      arjun \
      beautifulsoup4 \
      cryptography \
      httpie \
      lxml \
      playwright \
      pyjwt \
      pyyaml \
      requests \
      wafw00f \
      websocket-client

RUN mkdir -p /opt/tools /opt/nuclei-templates /usr/share/seclists/Discovery/Web-Content/api \
    /usr/share/seclists/Discovery/DNS /usr/share/seclists/Fuzzing/LFI \
    /usr/share/seclists/Fuzzing/XSS /usr/share/seclists/Passwords/Common-Credentials \
    /usr/share/wordlists && \
    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/tools/sqlmap && \
    ln -s /opt/tools/sqlmap/sqlmap.py /usr/local/bin/sqlmap && \
    git clone --depth 1 https://github.com/sullo/nikto.git /opt/tools/nikto && \
    ln -s /opt/tools/nikto/program/nikto.pl /usr/local/bin/nikto && \
    git clone --depth 1 https://github.com/maurosoria/dirsearch.git /opt/tools/dirsearch && \
    printf '#!/usr/bin/env bash\npython3 /opt/tools/dirsearch/dirsearch.py "$@"\n' > /usr/local/bin/dirsearch && \
    chmod +x /usr/local/bin/dirsearch && \
    git clone --depth 1 https://github.com/ticarpi/jwt_tool.git /opt/tools/jwt_tool && \
    printf '#!/usr/bin/env bash\npython3 /opt/tools/jwt_tool/jwt_tool.py "$@"\n' > /usr/local/bin/jwt_tool && \
    chmod +x /usr/local/bin/jwt_tool && \
    git clone --depth 1 https://github.com/GerbenJavado/LinkFinder.git /opt/tools/LinkFinder && \
    python3 -m pip install --no-cache-dir -r /opt/tools/LinkFinder/requirements.txt && \
    printf '#!/usr/bin/env bash\npython3 /opt/tools/LinkFinder/linkfinder.py "$@"\n' > /usr/local/bin/linkfinder && \
    chmod +x /usr/local/bin/linkfinder && \
    git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/tools/testssl.sh && \
    ln -s /opt/tools/testssl.sh/testssl.sh /usr/local/bin/testssl.sh && \
    git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git /opt/nuclei-templates

COPY --from=wordlists /SecLists/Discovery/Web-Content/common.txt /usr/share/seclists/Discovery/Web-Content/common.txt
COPY --from=wordlists /SecLists/Discovery/Web-Content/raft-medium-directories.txt /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
COPY --from=wordlists /SecLists/Discovery/Web-Content/raft-medium-files.txt /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt
COPY --from=wordlists /SecLists/Discovery/Web-Content/api/api-endpoints.txt /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt
COPY --from=wordlists /SecLists/Discovery/DNS/subdomains-top1million-5000.txt /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
COPY --from=wordlists /SecLists/Fuzzing/LFI/LFI-Jhaddix.txt /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
COPY --from=wordlists /SecLists/Fuzzing/XSS/XSS-Jhaddix.txt /usr/share/seclists/Fuzzing/XSS/XSS-Jhaddix.txt
COPY --from=wordlists /SecLists/Passwords/Common-Credentials/10k-most-common.txt /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt

RUN ln -s /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt /usr/share/wordlists/rockyou.txt

COPY healthcheck.sh /opt/healthcheck.sh
RUN chmod +x /opt/healthcheck.sh

WORKDIR /workspace

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=5 CMD ["/opt/healthcheck.sh"]
CMD ["sleep", "infinity"]
