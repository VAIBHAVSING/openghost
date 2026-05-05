#!/usr/bin/env bash
set -euo pipefail

required_tools=(
  bash
  curl
  jq
  python3
  git
  nmap
  ffuf
  nuclei
  subfinder
  httpx
  katana
  sqlmap
  nikto
  dirsearch
  jwt_tool
  newman
  wscat
  mitmproxy
  wafw00f
  testssl.sh
  zap.sh
)

for tool in "${required_tools[@]}"; do
  command -v "${tool}" >/dev/null 2>&1 || exit 1
done

curl -fsS "http://127.0.0.1:${ZAP_PORT:-8080}/JSON/core/view/version/" >/dev/null 2>&1
