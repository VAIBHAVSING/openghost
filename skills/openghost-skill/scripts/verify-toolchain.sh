#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAUNCHER="${SCRIPT_DIR}/openghost.sh"

required_tools=(
  bash
  curl
  http
  jq
  python3
  nmap
  ffuf
  nuclei
  dnsx
  subfinder
  httpx
  katana
  sqlmap
  nikto
  dirsearch
  jwt_tool
  wafw00f
  testssl.sh
  linkfinder
  arjun
  hashcat
  chromium
  java
  zap.sh
  websocat
  grpcurl
)

missing=()

"${LAUNCHER}" sandbox start >/dev/null

for tool in "${required_tools[@]}"; do
  if ! "${LAUNCHER}" bash "command -v ${tool}" >/dev/null 2>&1; then
    missing+=("${tool}")
  fi
done

if ! "${LAUNCHER}" bash 'test -f /usr/share/seclists/Discovery/Web-Content/common.txt' >/dev/null 2>&1; then
  missing+=("selected SecLists wordlists")
fi

if ! "${LAUNCHER}" bash 'test -d /opt/nuclei-templates' >/dev/null 2>&1; then
  missing+=("/opt/nuclei-templates")
fi

if ((${#missing[@]} > 0)); then
  printf 'missing required runtime tools: %s\n' "${missing[*]}" >&2
  exit 1
fi

printf 'runtime toolchain: ok\n'
