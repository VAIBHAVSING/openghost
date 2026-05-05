FROM kalilinux/kali-rolling AS base

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap nikto sqlmap curl wget jq dnsutils whois netcat-traditional \
    python3 python3-pip python3-venv \
    chromium testssl.sh git ca-certificates unzip \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --break-system-packages --no-cache-dir \
    requests pyjwt cryptography sslyze wafw00f arjun dirsearch linkfinder

FROM golang:1.22-bookworm AS go-tools
RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    go install github.com/ffuf/ffuf/v2@latest && \
    go install github.com/OJ/gobuster/v3@latest

FROM base AS final
COPY --from=go-tools /go/bin/* /usr/local/bin/
RUN nuclei -update-templates 2>/dev/null || true

COPY healthcheck.sh /opt/healthcheck.sh
RUN chmod +x /opt/healthcheck.sh

HEALTHCHECK --interval=30s --timeout=10s CMD /opt/healthcheck.sh

WORKDIR /workspace
CMD ["sleep", "infinity"]
