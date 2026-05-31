#!/usr/bin/env bash
set -euo pipefail

required_tools=(
  bash
  python3
  curl
  jq
  openssl
  dig
  nc
  nmap
  nikto
  sqlmap
  nuclei
  ffuf
  katana
  httpx
  subfinder
  dnsx
  arjun
  dirsearch
  linkfinder
  jwt_tool
  testssl.sh
  wafw00f
  hashcat
  chromium
  java
  zap.sh
  websocat
  grpcurl
)

missing=0
for tool in "${required_tools[@]}"; do
  if command -v "$tool" >/dev/null 2>&1; then
    printf '%s: ok\n' "$tool"
  else
    printf '%s: missing\n' "$tool"
    missing=1
  fi
done

exit "$missing"
