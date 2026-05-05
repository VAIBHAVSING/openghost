#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${SKILL_DIR}/../.." && pwd)"

IMAGE_NAME="${OPENGHOST_SKILL_IMAGE:-openghost-skill-runtime:latest}"
CONTAINER_NAME="${OPENGHOST_SKILL_CONTAINER:-openghost-skill-runtime}"
WORKSPACE_DIR="${OPENGHOST_SKILL_WORKSPACE:-${REPO_ROOT}}"
ZAP_PORT="${OPENGHOST_SKILL_ZAP_PORT:-8080}"

usage() {
  cat <<'USAGE'
Usage: openghost-skill.sh <command> [args...]

Commands:
  preflight                         Check host prerequisites and runtime image state
  start                             Build image if needed and start the isolated runtime
  status                            Show runtime status and toolchain health
  init --url URL --out DIR          Create a basic engagement folder
  exec-tool TOOL [args...]          Run an approved named tool inside the runtime
  exec-bash COMMAND                 Run a shell command inside the runtime
  exec-python SCRIPT                Run an inline Python script inside the runtime
  stop                              Stop and remove the runtime

Special exec-tool names:
  zap-version                       Print OWASP ZAP API version
  zap-spider URL                    Start a basic ZAP spider against URL
USAGE
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_host_tool() {
  command -v "$1" >/dev/null 2>&1 || die "missing host tool: $1"
}

container_running() {
  docker inspect --format '{{.State.Running}}' "${CONTAINER_NAME}" >/dev/null 2>&1 && \
    [[ "$(docker inspect --format '{{.State.Running}}' "${CONTAINER_NAME}")" == "true" ]]
}

ensure_image() {
  if ! docker image inspect "${IMAGE_NAME}" >/dev/null 2>&1; then
    docker build -t "${IMAGE_NAME}" "${REPO_ROOT}"
  fi
}

start_runtime() {
  require_host_tool docker
  ensure_image

  if container_running; then
    printf 'runtime already running: %s\n' "${CONTAINER_NAME}"
    return
  fi

  if docker inspect "${CONTAINER_NAME}" >/dev/null 2>&1; then
    docker rm -f "${CONTAINER_NAME}" >/dev/null
  fi

  docker run -d \
    --name "${CONTAINER_NAME}" \
    --security-opt no-new-privileges:true \
    --add-host host.docker.internal:host-gateway \
    -e "ZAP_PORT=${ZAP_PORT}" \
    -v "${WORKSPACE_DIR}:/workspace" \
    -w /workspace \
    "${IMAGE_NAME}" >/dev/null

  printf 'runtime started: %s\n' "${CONTAINER_NAME}"
}

ensure_running() {
  require_host_tool docker
  if ! container_running; then
    start_runtime >/dev/null
  fi
}

preflight() {
  require_host_tool docker
  docker info >/dev/null
  if docker image inspect "${IMAGE_NAME}" >/dev/null 2>&1; then
    printf 'image: present (%s)\n' "${IMAGE_NAME}"
  else
    printf 'image: missing (%s); start will build it\n' "${IMAGE_NAME}"
  fi
  printf 'container: %s\n' "${CONTAINER_NAME}"
}

status() {
  require_host_tool docker
  if ! docker inspect "${CONTAINER_NAME}" >/dev/null 2>&1; then
    printf 'runtime: not created\n'
    return
  fi

  docker inspect --format 'runtime: {{.State.Status}} health={{if .State.Health}}{{.State.Health.Status}}{{else}}n/a{{end}}' "${CONTAINER_NAME}"
  if container_running; then
    docker exec "${CONTAINER_NAME}" /opt/runtime/healthcheck.sh >/dev/null && printf 'toolchain: ok\n'
  fi
}

init_run() {
  local url=""
  local out=""

  while (($#)); do
    case "$1" in
      --url) url="${2:-}"; shift 2 ;;
      --out) out="${2:-}"; shift 2 ;;
      *) die "unknown init argument: $1" ;;
    esac
  done

  [[ -n "${url}" ]] || die "init requires --url"
  [[ -n "${out}" ]] || die "init requires --out"

  mkdir -p "${out}/notes" "${out}/evidence/http" "${out}/evidence/screenshots" \
    "${out}/evidence/raw" "${out}/traffic" "${out}/findings" "${out}/reports" "${out}/artifacts"
  printf 'target_url: "%s"\ncreated_at: "%s"\n' "${url}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "${out}/engagement.yaml"
  printf '%s\n' "${out}"
}

exec_bash() {
  (($# == 1)) || die "exec-bash requires one command string"
  ensure_running
  docker exec "${CONTAINER_NAME}" /bin/bash -lc "$1"
}

exec_python() {
  (($# == 1)) || die "exec-python requires one script string"
  ensure_running
  docker exec -i "${CONTAINER_NAME}" python3 -c "$1"
}

urlencode() {
  python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"
}

exec_tool() {
  (($# >= 1)) || die "exec-tool requires a tool name"
  local tool="$1"
  shift
  ensure_running

  case "${tool}" in
    zap-version)
      docker exec "${CONTAINER_NAME}" curl -fsS "http://127.0.0.1:${ZAP_PORT}/JSON/core/view/version/"
      ;;
    zap-spider)
      (($# == 1)) || die "zap-spider requires a URL"
      docker exec "${CONTAINER_NAME}" curl -fsS \
        "http://127.0.0.1:${ZAP_PORT}/JSON/spider/action/scan/?url=$(urlencode "$1")"
      ;;
    bash|sh|python|python3|ruby|perl|node|npm|nmap|nuclei|ffuf|dirsearch|katana|httpx|subfinder|sqlmap|nikto|jwt_tool|wscat|newman|mitmproxy|wafw00f|testssl.sh|linkfinder|arjun|curl|http|jq|dig|nc)
      docker exec "${CONTAINER_NAME}" "${tool}" "$@"
      ;;
    *)
      die "tool is not in the approved launcher allowlist: ${tool}"
      ;;
  esac
}

stop_runtime() {
  require_host_tool docker
  if docker inspect "${CONTAINER_NAME}" >/dev/null 2>&1; then
    docker rm -f "${CONTAINER_NAME}" >/dev/null
    printf 'runtime stopped: %s\n' "${CONTAINER_NAME}"
  else
    printf 'runtime not present: %s\n' "${CONTAINER_NAME}"
  fi
}

main() {
  local command="${1:-}"
  [[ -n "${command}" ]] || { usage; exit 1; }
  shift || true

  case "${command}" in
    preflight) preflight "$@" ;;
    start) start_runtime "$@" ;;
    status) status "$@" ;;
    init) init_run "$@" ;;
    exec-tool) exec_tool "$@" ;;
    exec-bash) exec_bash "$@" ;;
    exec-python) exec_python "$@" ;;
    stop) stop_runtime "$@" ;;
    -h|--help|help) usage ;;
    *) usage; die "unknown command: ${command}" ;;
  esac
}

main "$@"
