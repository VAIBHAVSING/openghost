#!/usr/bin/env bash
set -euo pipefail

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

mkdir -p "${out}/notes" "${out}/evidence/http" "${out}/evidence/screenshots" \
  "${out}/evidence/raw" "${out}/traffic" "${out}/findings" "${out}/reports" "${out}/artifacts"

cat > "${out}/engagement.yaml" <<EOF
target_url: "${url}"
created_at: "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
scope_file: "${scope}"
auth_file: "${auth}"
EOF

[[ -n "${scope}" && -f "${scope}" ]] && cp "${scope}" "${out}/scope.yaml"
[[ -n "${auth}" && -f "${auth}" ]] && cp "${auth}" "${out}/auth.yaml"

printf 'created engagement run: %s\n' "${out}"
