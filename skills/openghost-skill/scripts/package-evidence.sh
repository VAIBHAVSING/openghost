#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: package-evidence.sh --run DIR [--name archive-name]
USAGE
}

run_dir=""
name=""

while (($#)); do
  case "$1" in
    --run) run_dir="${2:-}"; shift 2 ;;
    --name) name="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; usage; exit 1 ;;
  esac
done

[[ -n "${run_dir}" ]] || { printf 'missing --run\n' >&2; exit 1; }
[[ -d "${run_dir}" ]] || { printf 'run directory not found: %s\n' "${run_dir}" >&2; exit 1; }
[[ -d "${run_dir}/findings" ]] || { printf 'missing findings directory\n' >&2; exit 1; }
[[ -d "${run_dir}/reports" ]] || { printf 'missing reports directory\n' >&2; exit 1; }

mkdir -p "${run_dir}/artifacts"
archive="${run_dir}/artifacts/${name:-evidence-$(date -u +%Y%m%dT%H%M%SZ)}.tar.gz"
tar -czf "${archive}" -C "${run_dir}" notes evidence traffic findings reports engagement.yaml 2>/dev/null
printf '%s\n' "${archive}"
