#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAUNCHER="${SCRIPT_DIR}/openghost-skill.sh"

required_tools=(
  bash
  curl
  http
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
  linkfinder
  arjun
)

missing=()

"${LAUNCHER}" start >/dev/null

for tool in "${required_tools[@]}"; do
  if ! "${LAUNCHER}" exec-bash "command -v ${tool}" >/dev/null 2>&1; then
    missing+=("${tool}")
  fi
done

if ! "${LAUNCHER}" exec-bash 'test -d /opt/wordlists/SecLists' >/dev/null 2>&1; then
  missing+=("/opt/wordlists/SecLists")
fi

if ! "${LAUNCHER}" exec-bash 'test -d /opt/nuclei-templates' >/dev/null 2>&1; then
  missing+=("/opt/nuclei-templates")
fi

if ! "${LAUNCHER}" exec-tool zap-version >/dev/null 2>&1; then
  missing+=("OWASP ZAP API")
fi

if ((${#missing[@]} > 0)); then
  printf 'missing required runtime tools: %s\n' "${missing[*]}" >&2
  exit 1
fi

printf 'runtime toolchain: ok\n'
