#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAUNCHER="${SCRIPT_DIR}/openghost.sh"

usage() {
  cat <<'USAGE'
Usage: init-engagement.sh --url URL --out DIR [--scope scope.yaml] [--auth auth.yaml]
USAGE
}

url=""
out=""
scope=""
auth=""

while (($#)); do
  case "$1" in
    --url) url="${2:-}"; shift 2 ;;
    --out) out="${2:-}"; shift 2 ;;
    --scope) scope="${2:-}"; shift 2 ;;
    --auth) auth="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; usage; exit 1 ;;
  esac
done

[[ -n "${url}" ]] || { printf 'missing --url\n' >&2; exit 1; }
[[ -n "${out}" ]] || { printf 'missing --out\n' >&2; exit 1; }
[[ -f "${LAUNCHER}" ]] || { printf 'missing launcher: %s\n' "${LAUNCHER}" >&2; exit 1; }

"${LAUNCHER}" engagement init --url "${url}" --out "${out}"

[[ -n "${scope}" && -f "${scope}" ]] && cp "${scope}" "${out}/scope.yaml"
[[ -n "${auth}" && -f "${auth}" ]] && cp "${auth}" "${out}/auth.yaml"

printf 'created engagement run: %s\n' "${out}"
