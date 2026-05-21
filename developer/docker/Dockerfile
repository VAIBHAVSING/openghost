FROM python:3.12-slim-bookworm AS runtime
ARG FFUF_VERSION=v2.1.0
ARG SUBFINDER_VERSION=v2.6.8
ARG HTTPX_VERSION=v1.6.10
ARG DNSX_VERSION=v1.2.1
ARG NUCLEI_VERSION=v3.3.8
ARG KATANA_VERSION=v1.1.2
ARG GRPCURL_VERSION=v1.9.2
ARG WEBSOCAT_VERSION=v1.14.1
ARG ZAP_VERSION=2.17.0
ARG ZAP_LINUX_SHA256=efe799aaa3627db683b43f00c9c210aea0b75c00cc8f0a0f0434d12bb3ddde5a

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_BREAK_SYSTEM_PACKAGES=1 \
    PLAYWRIGHT_BROWSERS_PATH=0 \
    NUCLEI_TEMPLATES=/opt/nuclei-templates \
    ZAP_HOME=/opt/zap \
    ZAP_MAX_MEMORY=1024m

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
    openjdk-17-jre-headless \
    openssl \
    ocl-icd-libopencl1 \
    pocl-opencl-icd \
    perl \
    procps \
    unzip \
    wget \
    whois \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    fetch() { curl --retry 5 --retry-all-errors --retry-delay 2 -fsSL "$1" -o "$2"; }; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) tool_arch="amd64"; grpcurl_arch="x86_64" ;; \
      arm64) tool_arch="arm64"; grpcurl_arch="arm64" ;; \
      *) echo "Unsupported architecture: $arch" >&2; exit 1 ;; \
    esac; \
    tmpdir="$(mktemp -d)"; \
    ffuf_version="${FFUF_VERSION#v}"; \
    subfinder_version="${SUBFINDER_VERSION#v}"; \
    httpx_version="${HTTPX_VERSION#v}"; \
    dnsx_version="${DNSX_VERSION#v}"; \
    nuclei_version="${NUCLEI_VERSION#v}"; \
    katana_version="${KATANA_VERSION#v}"; \
    grpcurl_version="${GRPCURL_VERSION#v}"; \
    fetch "https://github.com/ffuf/ffuf/releases/download/${FFUF_VERSION}/ffuf_${ffuf_version}_linux_${tool_arch}.tar.gz" "$tmpdir/ffuf.tar.gz"; \
    tar -xzf "$tmpdir/ffuf.tar.gz" -C "$tmpdir" ffuf; \
    install -m 0755 "$tmpdir/ffuf" /usr/local/bin/ffuf; \
    fetch "https://github.com/projectdiscovery/subfinder/releases/download/${SUBFINDER_VERSION}/subfinder_${subfinder_version}_linux_${tool_arch}.zip" "$tmpdir/subfinder.zip"; \
    unzip -q "$tmpdir/subfinder.zip" -d "$tmpdir/subfinder"; \
    install -m 0755 "$tmpdir/subfinder/subfinder" /usr/local/bin/subfinder; \
    fetch "https://github.com/projectdiscovery/httpx/releases/download/${HTTPX_VERSION}/httpx_${httpx_version}_linux_${tool_arch}.zip" "$tmpdir/httpx.zip"; \
    unzip -q "$tmpdir/httpx.zip" -d "$tmpdir/httpx"; \
    install -m 0755 "$tmpdir/httpx/httpx" /usr/local/bin/httpx; \
    fetch "https://github.com/projectdiscovery/dnsx/releases/download/${DNSX_VERSION}/dnsx_${dnsx_version}_linux_${tool_arch}.zip" "$tmpdir/dnsx.zip"; \
    unzip -q "$tmpdir/dnsx.zip" -d "$tmpdir/dnsx"; \
    install -m 0755 "$tmpdir/dnsx/dnsx" /usr/local/bin/dnsx; \
    fetch "https://github.com/projectdiscovery/nuclei/releases/download/${NUCLEI_VERSION}/nuclei_${nuclei_version}_linux_${tool_arch}.zip" "$tmpdir/nuclei.zip"; \
    unzip -q "$tmpdir/nuclei.zip" -d "$tmpdir/nuclei"; \
    install -m 0755 "$tmpdir/nuclei/nuclei" /usr/local/bin/nuclei; \
    fetch "https://github.com/projectdiscovery/katana/releases/download/${KATANA_VERSION}/katana_${katana_version}_linux_${tool_arch}.zip" "$tmpdir/katana.zip"; \
    unzip -q "$tmpdir/katana.zip" -d "$tmpdir/katana"; \
    install -m 0755 "$tmpdir/katana/katana" /usr/local/bin/katana; \
    fetch "https://github.com/fullstorydev/grpcurl/releases/download/${GRPCURL_VERSION}/grpcurl_${grpcurl_version}_linux_${grpcurl_arch}.tar.gz" "$tmpdir/grpcurl.tar.gz"; \
    tar -xzf "$tmpdir/grpcurl.tar.gz" -C "$tmpdir" grpcurl; \
    install -m 0755 "$tmpdir/grpcurl" /usr/local/bin/grpcurl; \
    rm -rf "$tmpdir"

RUN arch="$(dpkg --print-architecture)" && \
    case "$arch" in \
      amd64) websocat_arch="x86_64-unknown-linux-musl" ;; \
      arm64) websocat_arch="aarch64-unknown-linux-musl" ;; \
      *) echo "Unsupported architecture for websocat: $arch" >&2; exit 1 ;; \
    esac && \
    curl -fsSL "https://github.com/vi/websocat/releases/download/${WEBSOCAT_VERSION}/websocat.${websocat_arch}" -o /usr/local/bin/websocat && \
    chmod +x /usr/local/bin/websocat

RUN set -eux; \
    tmpdir="$(mktemp -d)"; \
    curl --retry 5 --retry-all-errors --retry-delay 2 -fsSL \
      "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VERSION}/ZAP_${ZAP_VERSION}_Linux.tar.gz" \
      -o "$tmpdir/zap.tar.gz"; \
    echo "${ZAP_LINUX_SHA256}  $tmpdir/zap.tar.gz" | sha256sum -c -; \
    tar -xzf "$tmpdir/zap.tar.gz" -C /opt; \
    mv "/opt/ZAP_${ZAP_VERSION}" /opt/zap; \
    ln -s /opt/zap/zap.sh /usr/local/bin/zap.sh; \
    rm -rf "$tmpdir" /root/.ZAP

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
    git -c http.version=HTTP/1.1 clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/tools/sqlmap && \
    ln -s /opt/tools/sqlmap/sqlmap.py /usr/local/bin/sqlmap && \
    git -c http.version=HTTP/1.1 clone --depth 1 https://github.com/sullo/nikto.git /opt/tools/nikto && \
    ln -s /opt/tools/nikto/program/nikto.pl /usr/local/bin/nikto && \
    git -c http.version=HTTP/1.1 clone --depth 1 https://github.com/maurosoria/dirsearch.git /opt/tools/dirsearch && \
    printf '#!/usr/bin/env bash\npython3 /opt/tools/dirsearch/dirsearch.py "$@"\n' > /usr/local/bin/dirsearch && \
    chmod +x /usr/local/bin/dirsearch && \
    git -c http.version=HTTP/1.1 clone --depth 1 https://github.com/ticarpi/jwt_tool.git /opt/tools/jwt_tool && \
    printf '#!/usr/bin/env bash\npython3 /opt/tools/jwt_tool/jwt_tool.py "$@"\n' > /usr/local/bin/jwt_tool && \
    chmod +x /usr/local/bin/jwt_tool && \
    git -c http.version=HTTP/1.1 clone --depth 1 https://github.com/GerbenJavado/LinkFinder.git /opt/tools/LinkFinder && \
    python3 -m pip install --no-cache-dir -r /opt/tools/LinkFinder/requirements.txt && \
    printf '#!/usr/bin/env bash\npython3 /opt/tools/LinkFinder/linkfinder.py "$@"\n' > /usr/local/bin/linkfinder && \
    chmod +x /usr/local/bin/linkfinder && \
    git -c http.version=HTTP/1.1 clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/tools/testssl.sh && \
    ln -s /opt/tools/testssl.sh/testssl.sh /usr/local/bin/testssl.sh && \
    git -c http.version=HTTP/1.1 clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git /opt/nuclei-templates

RUN fetch() { curl --retry 5 --retry-all-errors --retry-delay 2 -fsSL "$1" -o "$2"; }; \
    seclists_base="https://raw.githubusercontent.com/danielmiessler/SecLists/master" && \
    fetch "$seclists_base/Discovery/Web-Content/common.txt" /usr/share/seclists/Discovery/Web-Content/common.txt && \
    fetch "$seclists_base/Discovery/Web-Content/raft-medium-directories.txt" /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt && \
    fetch "$seclists_base/Discovery/Web-Content/raft-medium-files.txt" /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt && \
    fetch "$seclists_base/Discovery/Web-Content/api/api-endpoints.txt" /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt && \
    fetch "$seclists_base/Discovery/DNS/subdomains-top1million-5000.txt" /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt && \
    fetch "$seclists_base/Fuzzing/LFI/LFI-Jhaddix.txt" /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt && \
    fetch "$seclists_base/Fuzzing/XSS/robot-friendly/XSS-Jhaddix.txt" /usr/share/seclists/Fuzzing/XSS/XSS-Jhaddix.txt && \
    fetch "$seclists_base/Passwords/Common-Credentials/10k-most-common.txt" /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt

RUN ln -s /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt /usr/share/wordlists/rockyou.txt

COPY healthcheck.sh /opt/healthcheck.sh
RUN chmod +x /opt/healthcheck.sh

WORKDIR /workspace

HEALTHCHECK --interval=30s --timeout=10s --start-period=20s --retries=5 CMD ["/opt/healthcheck.sh"]
CMD ["sleep", "infinity"]
