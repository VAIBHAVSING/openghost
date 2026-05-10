#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${SKILL_DIR}/../.." && pwd)"

DEFAULT_IMAGE="ghcr.io/openghost/openghost-sandbox:latest"
IMAGE_NAME="${OPENGHOST_IMAGE:-${DEFAULT_IMAGE}}"
CONTAINER_NAME="${OPENGHOST_CONTAINER:-openghost-sandbox}"
WORKSPACE_DIR="${OPENGHOST_WORKSPACE:-${PWD}}"
OPENGHOST_HOME="${OPENGHOST_HOME:-${PWD}/.openghost}"
DEV_DOCKER_DIR="${REPO_ROOT}/developer/docker"
DOCKERFILE_PATH="${OPENGHOST_DOCKERFILE:-${DEV_DOCKER_DIR}/Dockerfile}"
BUILD_CONTEXT="${OPENGHOST_BUILD_CONTEXT:-${DEV_DOCKER_DIR}}"

ALLOWED_TOOLS=(
  bash sh python python3
  curl wget http jq openssl dig whois nc
  nmap nikto sqlmap nuclei ffuf katana httpx subfinder dnsx
  arjun dirsearch linkfinder jwt_tool testssl.sh wafw00f
  hashcat chromium websocat grpcurl
)

BLOCKED_BASH_PATTERNS=(
  'rm -rf /'
  'rm -rf /*'
  'mkfs'
  'dd if='
  ':(){:|:&};:'
  'shutdown'
  'reboot'
  'halt'
  'poweroff'
  'init 0'
  'init 6'
  'chmod -R 777 /'
  '> /dev/sd'
  'nc -e'
  'ncat -e'
)

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

info() {
  printf '%s\n' "$*" >&2
}

usage() {
  cat <<'EOF'
Usage: openghost <command> [args...]

Sandbox lifecycle:
  openghost sandbox start              Pull and start the Docker sandbox
  openghost sandbox status             Show container and toolchain status
  openghost sandbox stop               Stop and remove the sandbox
  openghost sandbox logs               Show container logs
  openghost sandbox pull               Pull the configured image
  openghost sandbox update             Pull latest image and recreate container
  openghost sandbox shell              Open an interactive shell in the sandbox

Execution:
  openghost run TOOL [args...]          Run an allowlisted tool inside Docker
  openghost bash 'COMMAND'              Run bash inside Docker
  openghost python code 'SCRIPT'        Run inline Python inside Docker
  openghost python file PATH [-- args]  Run a workspace Python file inside Docker
  openghost python repl                 Open an interactive Python REPL in Docker

Engagement helpers:
  openghost engagement init --url URL [--name NAME] [--out DIR]
  openghost finding add [--engagement NAME|--dir DIR] --title TITLE --severity SEVERITY [...]
  openghost finding list [--engagement NAME|--dir DIR]
  openghost todo add [--engagement NAME|--dir DIR] --task TASK [--module MOD] [--priority P]
  openghost todo list [--engagement NAME|--dir DIR] [--status STATUS]
  openghost todo update [--engagement NAME|--dir DIR] --id ID --status STATUS [--notes TEXT]
  openghost report generate [--engagement NAME|--dir DIR]

Compatibility aliases:
  openghost preflight                   Same as sandbox status/pull information
  openghost start                       Same as sandbox start
  openghost status                      Same as sandbox status
  openghost stop                        Same as sandbox stop
  openghost exec-tool TOOL [args...]    Same as run TOOL [args...]
  openghost exec-bash 'COMMAND'         Same as bash 'COMMAND'
  openghost exec-python 'SCRIPT'        Same as python code 'SCRIPT'

Environment:
  OPENGHOST_IMAGE                       Default: ghcr.io/openghost/openghost-sandbox:latest
  OPENGHOST_CONTAINER                   Default: openghost-sandbox
  OPENGHOST_WORKSPACE                   Default: current working directory
  OPENGHOST_HOME                        Default: $PWD/.openghost
  OPENGHOST_BUILD=1                     Developer-only: build a local Dockerfile
  OPENGHOST_DOCKERFILE                  Developer-only Dockerfile path
  OPENGHOST_BUILD_CONTEXT               Developer-only Docker build context
EOF
}

require_host_tool() {
  command -v "$1" >/dev/null 2>&1 || die "missing host tool: $1"
}

docker_daemon_available() {
  docker info >/dev/null 2>&1
}

try_start_docker_daemon() {
  if docker_daemon_available; then
    return 0
  fi

  info 'Docker daemon is not reachable; trying to start it if the platform allows it...'

  if command -v systemctl >/dev/null 2>&1; then
    systemctl --user start docker >/dev/null 2>&1 || systemctl start docker >/dev/null 2>&1 || true
  fi

  if [[ "${OSTYPE:-}" == darwin* ]] && command -v open >/dev/null 2>&1; then
    open -a Docker >/dev/null 2>&1 || true
  fi

  for _ in 1 2 3 4 5; do
    docker_daemon_available && return 0
    sleep 2
  done

  return 1
}

require_docker() {
  require_host_tool docker
  try_start_docker_daemon || die 'Docker daemon is not running or is not accessible'
}

container_exists() {
  docker inspect "$CONTAINER_NAME" >/dev/null 2>&1
}

container_running() {
  docker inspect --format '{{.State.Running}}' "$CONTAINER_NAME" 2>/dev/null | grep -q '^true$'
}

image_exists() {
  docker image inspect "$IMAGE_NAME" >/dev/null 2>&1
}

pull_image() {
  require_docker
  info "Pulling sandbox image: ${IMAGE_NAME}"
  docker pull "$IMAGE_NAME"
}

build_image() {
  require_docker
  [[ -f "$DOCKERFILE_PATH" ]] || die "Dockerfile not found: $DOCKERFILE_PATH"
  info "Building developer sandbox image locally: ${IMAGE_NAME}"
  docker build -t "$IMAGE_NAME" -f "$DOCKERFILE_PATH" "$BUILD_CONTEXT"
}

ensure_image() {
  image_exists && return 0

  if [[ "${OPENGHOST_BUILD:-}" == "1" ]]; then
    build_image
    return 0
  fi

  if pull_image; then
    return 0
  fi

  die "image not available: $IMAGE_NAME. Normal installs pull the published GHCR image; developers can set OPENGHOST_BUILD=1 to build locally."
}

workspace_abs() {
  realpath "$WORKSPACE_DIR"
}

container_path_for_existing() {
  local input="$1"
  local abs ws
  abs="$(realpath "$input")"
  ws="$(workspace_abs)"
  case "$abs" in
    "$ws") printf '/workspace' ;;
    "$ws"/*) printf '/workspace/%s' "${abs#"$ws"/}" ;;
    *) die "path is outside OPENGHOST_WORKSPACE: $input" ;;
  esac
}

container_path_for_dir() {
  local input="$1"
  local parent base parent_abs ws
  parent="$(dirname "$input")"
  base="$(basename "$input")"
  mkdir -p "$parent"
  parent_abs="$(realpath "$parent")"
  ws="$(workspace_abs)"
  case "$parent_abs" in
    "$ws") printf '/workspace/%s' "$base" ;;
    "$ws"/*) printf '/workspace/%s/%s' "${parent_abs#"$ws"/}" "$base" ;;
    *) die "path is outside OPENGHOST_WORKSPACE: $input" ;;
  esac
}

state_root_abs() {
  mkdir -p "$OPENGHOST_HOME"
  realpath "$OPENGHOST_HOME"
}

slugify() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9._-]+/-/g; s/^-+//; s/-+$//; s/-+/-/g'
}

engagement_dir_for_name() {
  local name="$1"
  [[ -n "$name" ]] || die 'engagement name is empty'
  printf '%s/engagements/%s' "$(state_root_abs)" "$(slugify "$name")"
}

set_current_engagement() {
  local dir="$1"
  mkdir -p "$(state_root_abs)"
  realpath "$dir" > "$(state_root_abs)/current"
}

current_engagement_dir() {
  local current_file
  current_file="$(state_root_abs)/current"
  [[ -f "$current_file" ]] || die 'no active engagement; run: openghost engagement init --url <url> --name <name>'
  local dir
  dir="$(<"$current_file")"
  [[ -d "$dir" ]] || die "active engagement directory does not exist: $dir"
  printf '%s' "$dir"
}

resolve_engagement_dir() {
  local dir="$1"
  local engagement="$2"
  if [[ -n "$dir" ]]; then
    printf '%s' "$dir"
  elif [[ -n "$engagement" ]]; then
    engagement_dir_for_name "$engagement"
  else
    current_engagement_dir
  fi
}

docker_exec() {
  ensure_running
  docker exec "$CONTAINER_NAME" "$@"
}

docker_exec_interactive() {
  ensure_running
  if [[ -t 0 && -t 1 ]]; then
    docker exec -it "$CONTAINER_NAME" "$@"
  else
    docker exec -i "$CONTAINER_NAME" "$@"
  fi
}

sandbox_start() {
  require_docker

  if container_running; then
    printf 'sandbox already running: %s\n' "$CONTAINER_NAME"
    return 0
  fi

  ensure_image

  if container_exists; then
    docker start "$CONTAINER_NAME" >/dev/null
    printf 'sandbox started: %s\n' "$CONTAINER_NAME"
    return 0
  fi

  local ws
  ws="$(workspace_abs)"

  docker run -d \
    --name "$CONTAINER_NAME" \
    --security-opt no-new-privileges:true \
    --cap-drop ALL \
    --cap-add NET_RAW \
    --cap-add NET_BIND_SERVICE \
    --add-host host.docker.internal:host-gateway \
    -v "${ws}:/workspace" \
    -w /workspace \
    "$IMAGE_NAME" >/dev/null

  printf 'sandbox started: %s\n' "$CONTAINER_NAME"
}

ensure_running() {
  require_docker
  container_running || sandbox_start >/dev/null
}

sandbox_status() {
  require_docker
  printf 'image: %s\n' "$IMAGE_NAME"
  if image_exists; then
    printf 'image_status: present\n'
  else
    printf 'image_status: missing\n'
  fi

  if ! container_exists; then
    printf 'container: %s\nstatus: not_created\n' "$CONTAINER_NAME"
    return 0
  fi

  docker inspect --format 'container: {{.Name}}
status: {{.State.Status}}
health: {{if .State.Health}}{{.State.Health.Status}}{{else}}n/a{{end}}' "$CONTAINER_NAME" | sed 's|container: /|container: |'

  if container_running; then
    docker exec "$CONTAINER_NAME" /opt/healthcheck.sh || true
  fi
}

sandbox_stop() {
  require_docker
  if container_exists; then
    docker rm -f "$CONTAINER_NAME" >/dev/null
    printf 'sandbox stopped: %s\n' "$CONTAINER_NAME"
  else
    printf 'sandbox not present: %s\n' "$CONTAINER_NAME"
  fi
}

sandbox_logs() {
  require_docker
  container_exists || die "sandbox not present: $CONTAINER_NAME"
  docker logs "$CONTAINER_NAME" "$@"
}

sandbox_update() {
  if [[ "${OPENGHOST_BUILD:-}" == "1" ]]; then
    build_image
  else
    pull_image
  fi
  if container_exists; then
    docker rm -f "$CONTAINER_NAME" >/dev/null
  fi
  sandbox_start
}

is_allowed_tool() {
  local tool="$1"
  local allowed
  for allowed in "${ALLOWED_TOOLS[@]}"; do
    [[ "$tool" == "$allowed" ]] && return 0
  done
  return 1
}

check_bash_blocklist() {
  local cmd="$1"
  local lower pattern
  lower="$(printf '%s' "$cmd" | tr '[:upper:]' '[:lower:]')"
  for pattern in "${BLOCKED_BASH_PATTERNS[@]}"; do
    if [[ "$lower" == *"$pattern"* ]]; then
      die "bash command blocked by pattern: $pattern"
    fi
  done
}

cmd_run() {
  (($# >= 1)) || die 'run requires a tool name'
  local tool="$1"
  shift
  is_allowed_tool "$tool" || die "tool is not allowlisted: $tool"
  docker_exec "$tool" "$@"
}

cmd_bash() {
  (($# == 1)) || die "bash requires one command string"
  check_bash_blocklist "$1"
  docker_exec bash -lc "$1"
}

cmd_python() {
  local subcommand="${1:-}"
  [[ -n "$subcommand" ]] || die 'python requires: code, file, or repl'
  shift || true

  case "$subcommand" in
    code)
      (($# == 1)) || die "python code requires one script string"
      local encoded
      encoded="$(printf '%s' "$1" | base64 | tr -d '\n')"
      docker_exec python3 -c "import base64; exec(base64.b64decode('${encoded}').decode())"
      ;;
    file)
      (($# >= 1)) || die "python file requires a file path"
      local file_path container_file
      file_path="$1"
      shift
      if [[ "${1:-}" == "--" ]]; then
        shift
      fi
      [[ -f "$file_path" ]] || die "python file not found: $file_path"
      container_file="$(container_path_for_existing "$file_path")"
      docker_exec python3 "$container_file" "$@"
      ;;
    repl)
      (($# == 0)) || die "python repl does not accept arguments"
      docker_exec_interactive python3
      ;;
    *)
      die "unknown python subcommand: $subcommand"
      ;;
  esac
}

cmd_sandbox() {
  local subcommand="${1:-}"
  [[ -n "$subcommand" ]] || die 'sandbox requires: start, status, stop, logs, pull, update, or shell'
  shift || true

  case "$subcommand" in
    start) sandbox_start "$@" ;;
    status) sandbox_status "$@" ;;
    stop) sandbox_stop "$@" ;;
    logs) sandbox_logs "$@" ;;
    pull) pull_image "$@" ;;
    update) sandbox_update "$@" ;;
    shell) docker_exec_interactive bash ;;
    *) die "unknown sandbox subcommand: $subcommand" ;;
  esac
}

cmd_engagement_init() {
  local url="" out="" name=""
  while (($#)); do
    case "$1" in
      --url) url="${2:-}"; shift 2 ;;
      --name) name="${2:-}"; shift 2 ;;
      --out) out="${2:-}"; shift 2 ;;
      *) die "unknown engagement init argument: $1" ;;
    esac
  done
  [[ -n "$url" ]] || die 'engagement init requires --url'

  local host
  host="$(printf '%s' "$url" | sed -E 's|https?://||;s|/.*||;s|:.*||')"
  name="${name:-$(slugify "$host")}"
  [[ -n "$name" ]] || die 'could not derive engagement name; pass --name'
  if [[ -z "$out" ]]; then
    out="$(engagement_dir_for_name "$name")"
  fi

  mkdir -p "$(state_root_abs)/engagements" "$(state_root_abs)/cache" "$(state_root_abs)/tmp"
  mkdir -p "$out"/notes "$out"/evidence/http "$out"/evidence/screenshots "$out"/evidence/raw \
    "$out"/findings "$out"/reports "$out"/artifacts "$out"/scripts "$out"/browser "$out"/runs

  if [[ ! -f "$(state_root_abs)/config.json" ]]; then
    printf '{"version":"1","created_at":"%s"}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$(state_root_abs)/config.json"
  fi

  cat > "$out/scope.yaml" <<SCOPE
target_url: "$url"
allowed_hosts:
  - "$host"
exclusions:
  paths:
    - /logout
  hosts: []
rate_limits:
  requests_per_second: 5
notes: "Edit this file before testing. Add every authorized host and exclusion."
SCOPE

  printf '[]\n' > "$out/findings.json"
  printf '[]\n' > "$out/todos.json"
  printf '{"name":"%s","target_url":"%s","created_at":"%s","status":"active"}\n' \
    "$name" "$url" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$out/engagement.json"
  set_current_engagement "$out"
  printf 'engagement created: %s\n' "$out"
}

run_json_helper() {
  local script="$1"
  shift
  require_host_tool python3
  env OG_HELPER_SCRIPT="$script" "$@" python3 - <<'PY'
import os
script = os.environ.pop('OG_HELPER_SCRIPT')
exec(script)
PY
}

cmd_finding_add() {
  local dir="" engagement="" title="" severity="" module="" url="" evidence="" confidence="" impact="" remediation="" wstg=""
  while (($#)); do
    case "$1" in
      --dir) dir="${2:-}"; shift 2 ;;
      --engagement) engagement="${2:-}"; shift 2 ;;
      --title) title="${2:-}"; shift 2 ;;
      --severity) severity="${2:-}"; shift 2 ;;
      --module) module="${2:-}"; shift 2 ;;
      --url) url="${2:-}"; shift 2 ;;
      --evidence) evidence="${2:-}"; shift 2 ;;
      --confidence) confidence="${2:-}"; shift 2 ;;
      --impact) impact="${2:-}"; shift 2 ;;
      --remediation) remediation="${2:-}"; shift 2 ;;
      --wstg) wstg="${2:-}"; shift 2 ;;
      *) die "unknown finding add argument: $1" ;;
    esac
  done
  [[ -n "$title" && -n "$severity" ]] || die 'finding add requires --title and --severity'
  dir="$(resolve_engagement_dir "$dir" "$engagement")"
  mkdir -p "$dir"
  [[ -f "$dir/findings.json" ]] || printf '[]\n' > "$dir/findings.json"
  local helper
  read -r -d '' helper <<'PY' || true
import json, os
from datetime import datetime, timezone
path = os.environ["OG_DIR"] + "/findings.json"
with open(path, "r", encoding="utf-8") as f:
    findings = json.load(f)
fid = f"F-{len(findings) + 1:03d}"
conf = os.environ.get("OG_CONFIDENCE", "0")
finding = {
    "id": fid,
    "title": os.environ["OG_TITLE"],
    "severity": os.environ["OG_SEVERITY"],
    "module": os.environ.get("OG_MODULE", ""),
    "url": os.environ.get("OG_URL", ""),
    "evidence": [x for x in os.environ.get("OG_EVIDENCE", "").split(",") if x],
    "confidence": int(conf) if conf.isdigit() else 0,
    "impact": os.environ.get("OG_IMPACT", ""),
    "remediation": os.environ.get("OG_REMEDIATION", ""),
    "wstg_id": os.environ.get("OG_WSTG", ""),
    "status": "confirmed",
    "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
}
findings.append(finding)
with open(path, "w", encoding="utf-8") as f:
    json.dump(findings, f, indent=2)
print(json.dumps({"saved": fid, "title": finding["title"], "severity": finding["severity"]}))
PY
  run_json_helper "$helper" OG_DIR="$dir" OG_TITLE="$title" OG_SEVERITY="$severity" \
    OG_MODULE="$module" OG_URL="$url" OG_EVIDENCE="$evidence" OG_CONFIDENCE="${confidence:-0}" \
    OG_IMPACT="$impact" OG_REMEDIATION="$remediation" OG_WSTG="$wstg"
}

cmd_finding_list() {
  local dir="" engagement=""
  while (($#)); do
    case "$1" in
      --dir) dir="${2:-}"; shift 2 ;;
      --engagement) engagement="${2:-}"; shift 2 ;;
      *) die "unknown finding list argument: $1" ;;
    esac
  done
  dir="$(resolve_engagement_dir "$dir" "$engagement")"
  [[ -f "$dir/findings.json" ]] || { printf '[]\n'; return 0; }
  local helper
  read -r -d '' helper <<'PY' || true
import json, os
path = os.environ["OG_DIR"] + "/findings.json"
with open(path, "r", encoding="utf-8") as f:
    findings = json.load(f)
for item in findings:
    print(f"[{item.get('id','?')}] {item.get('severity','?').upper()} {item.get('title','')}")
print(f"Total: {len(findings)}")
PY
  run_json_helper "$helper" OG_DIR="$dir"
}

cmd_todo_add() {
  local dir="" engagement="" task="" module="" priority="medium"
  while (($#)); do
    case "$1" in
      --dir) dir="${2:-}"; shift 2 ;;
      --engagement) engagement="${2:-}"; shift 2 ;;
      --task) task="${2:-}"; shift 2 ;;
      --module) module="${2:-}"; shift 2 ;;
      --priority) priority="${2:-}"; shift 2 ;;
      *) die "unknown todo add argument: $1" ;;
    esac
  done
  [[ -n "$task" ]] || die 'todo add requires --task'
  dir="$(resolve_engagement_dir "$dir" "$engagement")"
  mkdir -p "$dir"
  [[ -f "$dir/todos.json" ]] || printf '[]\n' > "$dir/todos.json"
  local helper
  read -r -d '' helper <<'PY' || true
import json, os
from datetime import datetime, timezone
path = os.environ["OG_DIR"] + "/todos.json"
with open(path, "r", encoding="utf-8") as f:
    todos = json.load(f)
tid = f"T-{len(todos) + 1:03d}"
todo = {
    "id": tid,
    "task": os.environ["OG_TASK"],
    "module": os.environ.get("OG_MODULE", ""),
    "priority": os.environ.get("OG_PRIORITY", "medium"),
    "status": "pending",
    "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "completed_at": None,
}
todos.append(todo)
with open(path, "w", encoding="utf-8") as f:
    json.dump(todos, f, indent=2)
print(json.dumps({"saved": tid, "task": todo["task"]}))
PY
  run_json_helper "$helper" OG_DIR="$dir" OG_TASK="$task" OG_MODULE="$module" OG_PRIORITY="$priority"
}

cmd_todo_list() {
  local dir="" engagement="" status_filter=""
  while (($#)); do
    case "$1" in
      --dir) dir="${2:-}"; shift 2 ;;
      --engagement) engagement="${2:-}"; shift 2 ;;
      --status) status_filter="${2:-}"; shift 2 ;;
      *) die "unknown todo list argument: $1" ;;
    esac
  done
  dir="$(resolve_engagement_dir "$dir" "$engagement")"
  [[ -f "$dir/todos.json" ]] || { printf '[]\n'; return 0; }
  local helper
  read -r -d '' helper <<'PY' || true
import json, os
path = os.environ["OG_DIR"] + "/todos.json"
sf = os.environ.get("OG_STATUS", "")
with open(path, "r", encoding="utf-8") as f:
    todos = json.load(f)
shown = 0
for item in todos:
    if sf and item.get("status") != sf:
        continue
    shown += 1
    print(f"[{item.get('id','?')}] {item.get('status','?')} {item.get('priority','medium')} {item.get('task','')}")
print(f"Total: {shown}/{len(todos)}")
PY
  run_json_helper "$helper" OG_DIR="$dir" OG_STATUS="$status_filter"
}

cmd_todo_update() {
  local dir="" engagement="" id="" status="" notes=""
  while (($#)); do
    case "$1" in
      --dir) dir="${2:-}"; shift 2 ;;
      --engagement) engagement="${2:-}"; shift 2 ;;
      --id) id="${2:-}"; shift 2 ;;
      --status) status="${2:-}"; shift 2 ;;
      --notes) notes="${2:-}"; shift 2 ;;
      *) die "unknown todo update argument: $1" ;;
    esac
  done
  [[ -n "$id" && -n "$status" ]] || die 'todo update requires --id and --status'
  dir="$(resolve_engagement_dir "$dir" "$engagement")"
  [[ -f "$dir/todos.json" ]] || die "todos.json not found in $dir"
  local helper
  read -r -d '' helper <<'PY' || true
import json, os
from datetime import datetime, timezone
path = os.environ["OG_DIR"] + "/todos.json"
with open(path, "r", encoding="utf-8") as f:
    todos = json.load(f)
found = False
for item in todos:
    if item.get("id") == os.environ["OG_ID"]:
        item["status"] = os.environ["OG_NEW_STATUS"]
        if os.environ.get("OG_NOTES"):
            item["notes"] = os.environ["OG_NOTES"]
        if item["status"] in ("done", "skip", "cancelled"):
            item["completed_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        found = True
        break
if not found:
    raise SystemExit(f"todo not found: {os.environ['OG_ID']}")
with open(path, "w", encoding="utf-8") as f:
    json.dump(todos, f, indent=2)
print(json.dumps({"updated": os.environ["OG_ID"], "status": os.environ["OG_NEW_STATUS"]}))
PY
  run_json_helper "$helper" OG_DIR="$dir" OG_ID="$id" OG_NEW_STATUS="$status" OG_NOTES="$notes"
}

cmd_report_generate() {
  local dir="" engagement=""
  while (($#)); do
    case "$1" in
      --dir) dir="${2:-}"; shift 2 ;;
      --engagement) engagement="${2:-}"; shift 2 ;;
      *) die "unknown report generate argument: $1" ;;
    esac
  done
  dir="$(resolve_engagement_dir "$dir" "$engagement")"
  mkdir -p "$dir/reports"
  local helper
  read -r -d '' helper <<'PY' || true
import json, os
from datetime import datetime, timezone
d = os.environ["OG_DIR"]
eng_path = d + "/engagement.json"
findings_path = d + "/findings.json"
todos_path = d + "/todos.json"
eng = json.load(open(eng_path, encoding="utf-8")) if os.path.exists(eng_path) else {}
findings = json.load(open(findings_path, encoding="utf-8")) if os.path.exists(findings_path) else []
todos = json.load(open(todos_path, encoding="utf-8")) if os.path.exists(todos_path) else []
sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
findings.sort(key=lambda x: sev_order.get(x.get("severity", "info"), 5))
report_path = f"{d}/reports/report-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.md"
lines = ["# OpenGhost Penetration Test Report", ""]
lines.append(f"Target: {eng.get('target_url', 'N/A')}")
lines.append(f"Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
lines.append("")
lines.append("## Executive Summary")
lines.append(f"Total findings: {len(findings)}")
for sev in ["critical", "high", "medium", "low", "info"]:
    count = sum(1 for f in findings if f.get("severity") == sev)
    if count:
        lines.append(f"- {sev.upper()}: {count}")
lines.append("")
lines.append("## Findings")
if not findings:
    lines.append("No confirmed findings recorded.")
for f in findings:
    lines.append(f"### {f.get('id','?')}: {f.get('title','')}")
    lines.append("")
    lines.append(f"Severity: {f.get('severity','N/A').upper()}")
    lines.append(f"Module: {f.get('module','N/A')}")
    lines.append(f"URL: {f.get('url','N/A')}")
    lines.append(f"Confidence: {f.get('confidence',0)}%")
    lines.append("")
    lines.append(f"Impact: {f.get('impact','N/A')}")
    lines.append(f"Remediation: {f.get('remediation','N/A')}")
    lines.append("")
pending = [t for t in todos if t.get("status") == "pending"]
if pending:
    lines.append("## Outstanding Testing Items")
    for t in pending:
        lines.append(f"- [{t.get('id','?')}] {t.get('task','')} ({t.get('module','')})")
with open(report_path, "w", encoding="utf-8") as f:
    f.write("\n".join(lines))
print(f"report generated: {report_path}")
PY
  run_json_helper "$helper" OG_DIR="$dir"
}

cmd_engagement() {
  local subcommand="${1:-}"
  [[ -n "$subcommand" ]] || die 'engagement requires: init'
  shift || true
  case "$subcommand" in
    init) cmd_engagement_init "$@" ;;
    *) die "unknown engagement subcommand: $subcommand" ;;
  esac
}

cmd_finding() {
  local subcommand="${1:-}"
  [[ -n "$subcommand" ]] || die 'finding requires: add or list'
  shift || true
  case "$subcommand" in
    add) cmd_finding_add "$@" ;;
    list) cmd_finding_list "$@" ;;
    *) die "unknown finding subcommand: $subcommand" ;;
  esac
}

cmd_todo() {
  local subcommand="${1:-}"
  [[ -n "$subcommand" ]] || die 'todo requires: add, list, or update'
  shift || true
  case "$subcommand" in
    add) cmd_todo_add "$@" ;;
    list) cmd_todo_list "$@" ;;
    update) cmd_todo_update "$@" ;;
    *) die "unknown todo subcommand: $subcommand" ;;
  esac
}

cmd_report() {
  local subcommand="${1:-}"
  [[ -n "$subcommand" ]] || die 'report requires: generate'
  shift || true
  case "$subcommand" in
    generate) cmd_report_generate "$@" ;;
    *) die "unknown report subcommand: $subcommand" ;;
  esac
}

main() {
  local command="${1:-}"
  [[ -n "$command" ]] || { usage; exit 1; }
  shift || true

  case "$command" in
    sandbox) cmd_sandbox "$@" ;;
    run) cmd_run "$@" ;;
    bash) cmd_bash "$@" ;;
    python) cmd_python "$@" ;;
    engagement) cmd_engagement "$@" ;;
    finding) cmd_finding "$@" ;;
    todo) cmd_todo "$@" ;;
    report) cmd_report "$@" ;;

    preflight) sandbox_status "$@" ;;
    start) sandbox_start "$@" ;;
    status) sandbox_status "$@" ;;
    stop) sandbox_stop "$@" ;;
    init) cmd_engagement_init "$@" ;;
    exec-tool) cmd_run "$@" ;;
    exec-bash) cmd_bash "$@" ;;
    exec-python) cmd_python code "$@" ;;
    save-finding) cmd_finding_add "$@" ;;
    get-findings) cmd_finding_list "$@" ;;
    save-todo) cmd_todo_add "$@" ;;
    get-todos) cmd_todo_list "$@" ;;
    update-todo) cmd_todo_update "$@" ;;
    generate-report) cmd_report_generate "$@" ;;

    -h|--help|help) usage ;;
    *) usage; die "unknown command: $command" ;;
  esac
}

main "$@"
