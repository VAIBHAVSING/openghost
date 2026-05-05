#!/usr/bin/env bash
set -euo pipefail
ok=true
for tool in nmap sqlmap nuclei ffuf httpx subfinder curl python3 jq; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "MISSING: $tool"
    ok=false
  fi
done
$ok && echo "OK" && exit 0 || exit 1
