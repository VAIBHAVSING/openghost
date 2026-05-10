#!/usr/bin/env bash
set -euo pipefail

required_tools=(
  bash
  python3
  curl
  jq
  nmap
  sqlmap
  nuclei
  ffuf
  httpx
  subfinder
  katana
  hashcat
  chromium
)

missing=0
for tool in "${required_tools[@]}"; do
  command -v "$tool" >/dev/null 2>&1 || missing=1
done

exit "$missing"
