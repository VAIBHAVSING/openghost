#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${SKILL_DIR}/../.." && pwd)"
STATE_HELPER="${SCRIPT_DIR}/openghost-state.py"

DEFAULT_IMAGE="ghcr.io/vaibhavsing/openghost-sandbox:latest"
IMAGE_NAME="${OPENGHOST_IMAGE:-${DEFAULT_IMAGE}}"
CONTAINER_NAME="${OPENGHOST_CONTAINER:-openghost-sandbox}"
ZAP_PORT="${OPENGHOST_ZAP_PORT:-8080}"
ZAP_SCAN_PORT="${OPENGHOST_ZAP_SCAN_PORT:-8090}"
ZAP_API_KEY="${OPENGHOST_ZAP_API_KEY:-openghost}"
ZAP_MAX_MEMORY="${OPENGHOST_ZAP_MAX_MEMORY:-1024m}"
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
  openghost zap start                   Start a headless ZAP daemon in the sandbox
  openghost zap status                  Show ZAP daemon status
  openghost zap stop                    Stop the ZAP daemon
  openghost zap proxy-url               Print Playwright proxy URL for ZAP
  openghost zap baseline --target URL   Run a passive ZAP spider/baseline plan
  openghost zap api-scan --target SPEC --format openapi|graphql [--target-url URL] [--confirm-active]
  openghost zap alerts [--format json|md] [--out FILE]
  openghost zap report [--format json|html|md] [--out FILE]
  openghost zap plan FILE               Run a ZAP Automation Framework plan
  openghost browser devtools --url URL [--zap|--proxy URL] [--headed]

Pentest script templates:
  openghost script list [--json]        List bundled Python pentest templates
  openghost script show NAME            Show metadata for one template
  openghost script copy NAME [...]      Copy a template into the active engagement scripts dir
  openghost script run NAME [-- args]   Run a bundled template inside Docker

Engagement helpers:
  openghost engagement init --url URL [--name NAME] [--out DIR]
  openghost evidence add [--engagement NAME|--dir DIR] --path FILE --kind KIND --title TITLE [...]
  openghost evidence list [--engagement NAME|--dir DIR]
  openghost artifact add [--engagement NAME|--dir DIR] --path FILE --kind KIND --title TITLE [...]
  openghost artifact list [--engagement NAME|--dir DIR]
  openghost finding add [--engagement NAME|--dir DIR] --title TITLE --severity SEVERITY --evidence E-001 --step STEP [...]
  openghost finding list [--engagement NAME|--dir DIR] [--status STATUS]
  openghost todo add [--engagement NAME|--dir DIR] --task TASK [--module MOD] [--priority P] [...]
  openghost todo list [--engagement NAME|--dir DIR] [--status STATUS]
  openghost todo update [--engagement NAME|--dir DIR] --id ID --status STATUS [--notes TEXT]
  openghost report generate [--engagement NAME|--dir DIR]
  openghost report list [--engagement NAME|--dir DIR]

Compatibility aliases:
  openghost preflight                   Same as sandbox status/pull information
  openghost start                       Same as sandbox start
  openghost status                      Same as sandbox status
  openghost stop                        Same as sandbox stop
  openghost exec-tool TOOL [args...]    Same as run TOOL [args...]
  openghost exec-bash 'COMMAND'         Same as bash 'COMMAND'
  openghost exec-python 'SCRIPT'        Same as python code 'SCRIPT'

Environment:
  OPENGHOST_IMAGE                       Default: ghcr.io/vaibhavsing/openghost-sandbox:latest
  OPENGHOST_CONTAINER                   Default: openghost-sandbox
  OPENGHOST_ZAP_PORT                    Default: 8080
  OPENGHOST_ZAP_SCAN_PORT               Default: 8090
  OPENGHOST_ZAP_API_KEY                 Default: openghost
  OPENGHOST_ZAP_MAX_MEMORY              Default: 1024m
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

state_helper() {
  require_host_tool python3
  [[ -f "$STATE_HELPER" ]] || die "state helper not found: $STATE_HELPER"
  python3 "$STATE_HELPER" "$@"
}

append_arg_if_set() {
  local -n target_args="$1"
  local flag="$2"
  local value="$3"
  if [[ -n "$value" ]]; then
    target_args+=("$flag" "$value")
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

script_manifest() {
  printf '%s/scripts/pentest/manifest.json' "$SKILL_DIR"
}

script_template_dir() {
  printf '%s/scripts/pentest' "$SKILL_DIR"
}

script_lookup() {
  local name="$1" field="$2"
  require_host_tool python3
  python3 - "$(script_manifest)" "$name" "$field" <<'PY'
import json
import sys

manifest, name, field = sys.argv[1:4]
with open(manifest, encoding="utf-8") as fh:
    data = json.load(fh)
for item in data.get("scripts", []):
    if item.get("name") == name:
        value = item.get(field, "")
        if isinstance(value, (dict, list)):
            print(json.dumps(value))
        else:
            print(value)
        raise SystemExit(0)
raise SystemExit(1)
PY
}

cmd_script_list() {
  local json=0
  while (($#)); do
    case "$1" in
      --json) json=1; shift ;;
      *) die "unknown script list argument: $1" ;;
    esac
  done

  [[ -f "$(script_manifest)" ]] || die "script manifest not found: $(script_manifest)"
  if [[ "$json" == "1" ]]; then
    cat "$(script_manifest)"
    return 0
  fi

  require_host_tool python3
  python3 - "$(script_manifest)" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as fh:
    data = json.load(fh)
for item in data.get("scripts", []):
    print(f"{item['name']}\t{item.get('module','')}\t{item.get('safety','')}\t{item.get('description','')}")
PY
}

cmd_script_show() {
  (($# == 1)) || die 'script show requires one template name'
  local name="$1"
  require_host_tool python3
  python3 - "$(script_manifest)" "$name" <<'PY' || die "unknown script template: $name"
import json
import sys

manifest, name = sys.argv[1:3]
with open(manifest, encoding="utf-8") as fh:
    data = json.load(fh)
for item in data.get("scripts", []):
    if item.get("name") != name:
        continue
    print(f"name: {item['name']}")
    print(f"file: {item.get('file','')}")
    print(f"module: {item.get('module','')}")
    print(f"safety: {item.get('safety','')}")
    print(f"source: {item.get('source','')}")
    print(f"description: {item.get('description','')}")
    print("")
    print(f"copy: openghost script copy {item['name']}")
    print(f"run:  openghost script run {item['name']} -- --help")
    raise SystemExit(0)
raise SystemExit(1)
PY
}

copy_script_support_files() {
  local dest_dir="$1"
  cp "$(script_template_dir)/og_pentest.py" "$dest_dir/og_pentest.py"
  cp "$(script_template_dir)/NOTICE" "$dest_dir/NOTICE.openghost-pentest-scripts"
}

cmd_script_copy() {
  (($# >= 1)) || die 'script copy requires a template name'
  local name="$1" dir="" engagement="" as_name="" force=0
  shift
  while (($#)); do
    case "$1" in
      --dir) dir="${2:-}"; shift 2 ;;
      --engagement) engagement="${2:-}"; shift 2 ;;
      --as) as_name="${2:-}"; shift 2 ;;
      --force) force=1; shift ;;
      *) die "unknown script copy argument: $1" ;;
    esac
  done

  local file src target_dir dest_name dest
  file="$(script_lookup "$name" file)" || die "unknown script template: $name"
  src="$(script_template_dir)/$file"
  [[ -f "$src" ]] || die "script template file not found: $src"

  dir="$(resolve_engagement_dir "$dir" "$engagement")"
  target_dir="$dir/scripts"
  mkdir -p "$target_dir"
  dest_name="${as_name:-$file}"
  [[ "$dest_name" != */* ]] || die '--as must be a filename, not a path'
  dest="$target_dir/$dest_name"
  if [[ -e "$dest" && "$force" != "1" ]]; then
    die "script already exists: $dest (pass --force to overwrite)"
  fi

  cp "$src" "$dest"
  chmod +x "$dest"
  copy_script_support_files "$target_dir"
  printf 'script copied: %s\n' "$dest"
}

current_engagement_dir_optional() {
  local current_file
  current_file="$(state_root_abs)/current"
  if [[ -f "$current_file" ]]; then
    local dir
    dir="$(<"$current_file")"
    if [[ -d "$dir" ]]; then
      printf '%s' "$dir"
    fi
  fi
}

cmd_script_run() {
  (($# >= 1)) || die 'script run requires a template name'
  local name="$1" dir="" engagement=""
  shift
  while (($#)); do
    case "$1" in
      --dir) dir="${2:-}"; shift 2 ;;
      --engagement) engagement="${2:-}"; shift 2 ;;
      --) shift; break ;;
      *) break ;;
    esac
  done

  local file src cache script_path container_script scope_set=0
  local -a env_args=()
  file="$(script_lookup "$name" file)" || die "unknown script template: $name"
  src="$(script_template_dir)/$file"
  [[ -f "$src" ]] || die "script template file not found: $src"

  cache="$(state_root_abs)/cache/scripts/$name"
  mkdir -p "$cache"
  cp "$src" "$cache/$file"
  cp "$(script_template_dir)/og_pentest.py" "$cache/og_pentest.py"
  cp "$(script_template_dir)/NOTICE" "$cache/NOTICE.openghost-pentest-scripts"
  script_path="$cache/$file"
  container_script="$(container_path_for_existing "$script_path")"

  if [[ -n "$dir" || -n "$engagement" ]]; then
    local resolved_dir container_dir
    resolved_dir="$(resolve_engagement_dir "$dir" "$engagement")"
    [[ -d "$resolved_dir" ]] || die "engagement directory not found: $resolved_dir"
    container_dir="$(container_path_for_existing "$resolved_dir")"
    env_args+=("OPENGHOST_ENGAGEMENT_DIR=$container_dir")
    if [[ -f "$resolved_dir/scope.yaml" ]]; then
      env_args+=("OPENGHOST_SCOPE=$container_dir/scope.yaml")
      scope_set=1
    fi
  else
    local active_dir
    active_dir="$(current_engagement_dir_optional)"
    if [[ -n "$active_dir" ]]; then
      local active_container_dir
      active_container_dir="$(container_path_for_existing "$active_dir")"
      env_args+=("OPENGHOST_ENGAGEMENT_DIR=$active_container_dir")
      if [[ -f "$active_dir/scope.yaml" ]]; then
        env_args+=("OPENGHOST_SCOPE=$active_container_dir/scope.yaml")
        scope_set=1
      fi
    fi
  fi

  if [[ -n "${OPENGHOST_SCOPE:-}" && "$scope_set" != "1" ]]; then
    if [[ -f "$OPENGHOST_SCOPE" ]]; then
      local cscope
      cscope="$(container_path_for_existing "$OPENGHOST_SCOPE")"
      env_args+=("OPENGHOST_SCOPE=$cscope")
    else
      env_args+=("OPENGHOST_SCOPE=$OPENGHOST_SCOPE")
    fi
    scope_set=1
  fi
  env_args+=("OPENGHOST_SCRIPT_NAME=$name")

  docker_exec env "${env_args[@]}" python3 "$container_script" "$@"
}

cmd_script() {
  local subcommand="${1:-}"
  [[ -n "$subcommand" ]] || die 'script requires: list, show, copy, or run'
  shift || true
  case "$subcommand" in
    list) cmd_script_list "$@" ;;
    show) cmd_script_show "$@" ;;
    copy) cmd_script_copy "$@" ;;
    run) cmd_script_run "$@" ;;
    *) die "unknown script subcommand: $subcommand" ;;
  esac
}

url_encode() {
  require_host_tool python3
  python3 -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"
}

timestamp_slug() {
  date -u +%Y%m%d-%H%M%S
}

zap_state_dir() {
  local dir
  dir="$(current_engagement_dir)"
  mkdir -p "$dir/zap"/home "$dir/zap"/logs "$dir/zap"/runs "$dir/zap"/reports
  printf '%s/zap' "$dir"
}

zap_api_get() {
  local path="$1" query="${2:-}" port="${3:-$ZAP_PORT}" key url
  key="$(url_encode "$ZAP_API_KEY")"
  url="http://127.0.0.1:${port}${path}?apikey=${key}"
  if [[ -n "$query" ]]; then
    url="${url}&${query}"
  fi
  docker_exec curl -fsS "$url"
}

zap_start_impl() {
  local port="${1:-$ZAP_PORT}" memory="${2:-$ZAP_MAX_MEMORY}" timeout="${3:-60}" quiet="${4:-0}"
  local zdir home log chome clog qhome qlog qmemory qkey
  zdir="$(zap_state_dir)"
  home="$zdir/home"
  log="$zdir/logs/zap-daemon.log"
  chome="$(container_path_for_existing "$home")"
  clog="$(container_path_for_dir "$log")"

  if zap_api_get /JSON/core/view/version/ "" "$port" >/dev/null 2>&1; then
    [[ "$quiet" == "1" ]] || printf 'zap already running: %s\n' "http://127.0.0.1:${port}"
    return 0
  fi

  printf -v qhome '%q' "$chome"
  printf -v qlog '%q' "$clog"
  printf -v qmemory '%q' "$memory"
  printf -v qkey '%q' "$ZAP_API_KEY"

  docker_exec bash -lc "mkdir -p ${qhome} && nohup env ZAP_MAX_MEMORY=${qmemory} zap.sh -daemon -host 127.0.0.1 -port ${port} -dir ${qhome} -silent -config api.disablekey=false -config api.key=${qkey} -config api.addrs.addr.name=127.0.0.1 -config api.addrs.addr.regex=false > ${qlog} 2>&1 &"

  for _ in $(seq 1 "$timeout"); do
    if zap_api_get /JSON/core/view/version/ "" "$port" >/dev/null 2>&1; then
      [[ "$quiet" == "1" ]] || printf 'zap started: %s\n' "http://127.0.0.1:${port}"
      return 0
    fi
    sleep 1
  done

  docker_exec bash -lc "tail -n 80 ${qlog}" >&2 || true
  die "ZAP did not become ready on 127.0.0.1:${port}"
}

zap_run_plan() {
  local plan="$1" run_dir="$2" port="${3:-$ZAP_SCAN_PORT}"
  local home log cplan chome
  mkdir -p "$run_dir/home"
  home="$run_dir/home"
  log="$run_dir/zap.log"
  cplan="$(container_path_for_existing "$plan")"
  chome="$(container_path_for_existing "$home")"

  local rc=0
  docker_exec zap.sh -cmd -silent -port "$port" -dir "$chome" \
    -config api.disablekey=true \
    -autorun "$cplan" > "$log" 2>&1 || rc=$?

  if ((rc != 0)); then
    tail -n 80 "$log" >&2 || true
    die "ZAP automation plan failed: $plan"
  fi

  printf 'zap plan completed: %s\n' "$run_dir"
}

cmd_zap_start() {
  local port="$ZAP_PORT" memory="$ZAP_MAX_MEMORY" timeout=60
  while (($#)); do
    case "$1" in
      --port) port="${2:-}"; shift 2 ;;
      --memory) memory="${2:-}"; shift 2 ;;
      --timeout) timeout="${2:-}"; shift 2 ;;
      *) die "unknown zap start argument: $1" ;;
    esac
  done
  zap_start_impl "$port" "$memory" "$timeout" 0
}

cmd_zap_status() {
  local port="$ZAP_PORT"
  while (($#)); do
    case "$1" in
      --port) port="${2:-}"; shift 2 ;;
      *) die "unknown zap status argument: $1" ;;
    esac
  done
  if zap_api_get /JSON/core/view/version/ "" "$port"; then
    printf '\nzap_status: running\nproxy_url: http://127.0.0.1:%s\n' "$port"
  else
    printf 'zap_status: not_running\n'
  fi
}

cmd_zap_stop() {
  local port="$ZAP_PORT"
  while (($#)); do
    case "$1" in
      --port) port="${2:-}"; shift 2 ;;
      *) die "unknown zap stop argument: $1" ;;
    esac
  done
  zap_api_get /JSON/core/action/shutdown/ "" "$port" >/dev/null 2>&1 || docker_exec bash -lc "pkill -f 'org.zaproxy.zap.ZAP|zap.sh' || true"
  printf 'zap stopped\n'
}

cmd_zap_baseline() {
  local target="" minutes=5 port="$ZAP_SCAN_PORT"
  while (($#)); do
    case "$1" in
      --target) target="${2:-}"; shift 2 ;;
      --minutes) minutes="${2:-}"; shift 2 ;;
      --port) port="${2:-}"; shift 2 ;;
      *) die "unknown zap baseline argument: $1" ;;
    esac
  done
  [[ -n "$target" ]] || die 'zap baseline requires --target URL'

  local zdir run_dir plan crun
  zdir="$(zap_state_dir)"
  run_dir="$zdir/runs/baseline-$(timestamp_slug)"
  mkdir -p "$run_dir"
  crun="$(container_path_for_existing "$run_dir")"
  plan="$run_dir/plan.yaml"
  cat > "$plan" <<PLAN
env:
  contexts:
    - name: OpenGhost
      urls:
        - "${target}"
      includePaths:
        - "${target}.*"
jobs:
  - type: spider
    parameters:
      context: OpenGhost
      url: "${target}"
      maxDuration: ${minutes}
  - type: passiveScan-wait
    parameters:
      maxDuration: 10
  - type: report
    parameters:
      template: traditional-json
      reportDir: "${crun}"
      reportFile: zap-report.json
      reportTitle: OpenGhost ZAP Baseline
  - type: report
    parameters:
      template: traditional-html
      reportDir: "${crun}"
      reportFile: zap-report.html
      reportTitle: OpenGhost ZAP Baseline
  - type: report
    parameters:
      template: traditional-md
      reportDir: "${crun}"
      reportFile: zap-report.md
      reportTitle: OpenGhost ZAP Baseline
PLAN
  zap_run_plan "$plan" "$run_dir" "$port"
}

cmd_zap_api_scan() {
  local target="" format="openapi" target_url="" minutes=5 active=0 port="$ZAP_SCAN_PORT"
  while (($#)); do
    case "$1" in
      --target) target="${2:-}"; shift 2 ;;
      --format) format="${2:-}"; shift 2 ;;
      --target-url) target_url="${2:-}"; shift 2 ;;
      --minutes) minutes="${2:-}"; shift 2 ;;
      --port) port="${2:-}"; shift 2 ;;
      --confirm-active) active=1; shift ;;
      *) die "unknown zap api-scan argument: $1" ;;
    esac
  done
  [[ -n "$target" ]] || die 'zap api-scan requires --target SPEC_OR_ENDPOINT'
  case "$format" in openapi|graphql) ;; *) die 'zap api-scan --format must be openapi or graphql' ;; esac

  local zdir run_dir plan crun target_value target_key active_job=""
  zdir="$(zap_state_dir)"
  run_dir="$zdir/runs/api-${format}-$(timestamp_slug)"
  mkdir -p "$run_dir"
  crun="$(container_path_for_existing "$run_dir")"
  plan="$run_dir/plan.yaml"

  if [[ "$format" == "openapi" ]]; then
    if [[ -f "$target" ]]; then
      target_key="apiFile"
      target_value="$(container_path_for_existing "$target")"
    else
      target_key="apiUrl"
      target_value="$target"
    fi
  fi

  if [[ "$active" == "1" ]]; then
    active_job='  - type: activeScan
    parameters:
      context: OpenGhost
      maxScanDurationInMins: '"${minutes}"
  fi

  cat > "$plan" <<PLAN
env:
  contexts:
    - name: OpenGhost
      urls:
        - "${target_url:-$target}"
jobs:
PLAN
  if [[ "$format" == "openapi" ]]; then
    cat >> "$plan" <<PLAN
  - type: openapi
    parameters:
      ${target_key}: "${target_value}"
      targetUrl: "${target_url:-$target}"
PLAN
  else
    cat >> "$plan" <<PLAN
  - type: graphql
    parameters:
      endpoint: "${target}"
      maxQueryDepth: 5
PLAN
  fi
  cat >> "$plan" <<PLAN
  - type: passiveScan-wait
    parameters:
      maxDuration: 10
${active_job}
  - type: report
    parameters:
      template: traditional-json
      reportDir: "${crun}"
      reportFile: zap-report.json
      reportTitle: OpenGhost ZAP API Scan
  - type: report
    parameters:
      template: traditional-html
      reportDir: "${crun}"
      reportFile: zap-report.html
      reportTitle: OpenGhost ZAP API Scan
  - type: report
    parameters:
      template: traditional-md
      reportDir: "${crun}"
      reportFile: zap-report.md
      reportTitle: OpenGhost ZAP API Scan
PLAN
  zap_run_plan "$plan" "$run_dir" "$port"
}

cmd_zap_alerts() {
  local format="json" out="" port="$ZAP_PORT" tmp zdir
  while (($#)); do
    case "$1" in
      --format) format="${2:-}"; shift 2 ;;
      --out) out="${2:-}"; shift 2 ;;
      --port) port="${2:-}"; shift 2 ;;
      *) die "unknown zap alerts argument: $1" ;;
    esac
  done
  case "$format" in json|md) ;; *) die 'zap alerts --format must be json or md' ;; esac
  zdir="$(zap_state_dir)"
  out="${out:-$zdir/reports/alerts.$format}"
  mkdir -p "$(dirname "$out")"
  tmp="$(mktemp)"
  zap_api_get /JSON/core/view/alerts/ "" "$port" > "$tmp"
  if [[ "$format" == "json" ]]; then
    cp "$tmp" "$out"
  else
    OG_JSON="$tmp" OG_OUT="$out" python3 - <<'PY'
import json, os
data = json.load(open(os.environ["OG_JSON"], encoding="utf-8"))
alerts = data.get("alerts", [])
lines = ["# ZAP Alerts", ""]
if not alerts:
    lines.append("No ZAP alerts returned.")
for alert in alerts:
    risk = alert.get("risk", "Unknown")
    name = alert.get("alert", "Unnamed alert")
    url = alert.get("url", "")
    evidence = alert.get("evidence", "")
    lines += [f"## {risk}: {name}", "", f"- URL: {url}", f"- CWE: {alert.get('cweid', '')}", f"- WASC: {alert.get('wascid', '')}"]
    if evidence:
        lines.append(f"- Evidence: {evidence}")
    lines.append("")
open(os.environ["OG_OUT"], "w", encoding="utf-8").write("\n".join(lines))
PY
  fi
  rm -f "$tmp"
  printf 'zap alerts saved: %s\n' "$out"
}

cmd_zap_report() {
  local format="json" out="" port="$ZAP_PORT" endpoint zdir
  while (($#)); do
    case "$1" in
      --format) format="${2:-}"; shift 2 ;;
      --out) out="${2:-}"; shift 2 ;;
      --port) port="${2:-}"; shift 2 ;;
      *) die "unknown zap report argument: $1" ;;
    esac
  done
  case "$format" in
    json) endpoint=/OTHER/core/other/jsonreport/ ;;
    html) endpoint=/OTHER/core/other/htmlreport/ ;;
    md) endpoint=/OTHER/core/other/mdreport/ ;;
    *) die 'zap report --format must be json, html, or md' ;;
  esac
  zdir="$(zap_state_dir)"
  out="${out:-$zdir/reports/zap-report.$format}"
  mkdir -p "$(dirname "$out")"
  zap_api_get "$endpoint" "" "$port" > "$out"
  printf 'zap report saved: %s\n' "$out"
}

cmd_zap_plan() {
  (($# == 1)) || die 'zap plan requires a plan file'
  local plan="$1" zdir run_dir
  [[ -f "$plan" ]] || die "ZAP plan not found: $plan"
  zdir="$(zap_state_dir)"
  run_dir="$zdir/runs/plan-$(timestamp_slug)"
  mkdir -p "$run_dir"
  cp "$plan" "$run_dir/plan.yaml"
  zap_run_plan "$run_dir/plan.yaml" "$run_dir" "$ZAP_SCAN_PORT"
}

cmd_zap() {
  local subcommand="${1:-}"
  [[ -n "$subcommand" ]] || die 'zap requires: start, status, stop, proxy-url, baseline, api-scan, alerts, report, or plan'
  shift || true
  case "$subcommand" in
    start) cmd_zap_start "$@" ;;
    status) cmd_zap_status "$@" ;;
    stop) cmd_zap_stop "$@" ;;
    proxy-url) printf 'http://127.0.0.1:%s\n' "$ZAP_PORT" ;;
    baseline) cmd_zap_baseline "$@" ;;
    api-scan) cmd_zap_api_scan "$@" ;;
    alerts) cmd_zap_alerts "$@" ;;
    report) cmd_zap_report "$@" ;;
    plan) cmd_zap_plan "$@" ;;
    *) die "unknown zap subcommand: $subcommand" ;;
  esac
}

cmd_browser_devtools() {
  local url="" proxy="" use_zap=0 headed=0 wait_ms=3000 name=""
  while (($#)); do
    case "$1" in
      --url) url="${2:-}"; shift 2 ;;
      --proxy) proxy="${2:-}"; shift 2 ;;
      --zap) use_zap=1; shift ;;
      --headed) headed=1; shift ;;
      --wait-ms) wait_ms="${2:-}"; shift 2 ;;
      --name) name="${2:-}"; shift 2 ;;
      *) die "unknown browser devtools argument: $1" ;;
    esac
  done
  [[ -n "$url" ]] || die 'browser devtools requires --url'
  if [[ "$use_zap" == "1" ]]; then
    zap_start_impl "$ZAP_PORT" "$ZAP_MAX_MEMORY" 60 1
    proxy="http://127.0.0.1:${ZAP_PORT}"
  fi

  local dir out script cout cscript
  dir="$(current_engagement_dir)"
  out="$dir/browser/${name:-devtools-$(timestamp_slug)}"
  mkdir -p "$out"
  script="$SKILL_DIR/scripts/playwright-zap-capture.py"
  [[ -f "$script" ]] || die "browser helper not found: $script"
  cout="$(container_path_for_existing "$out")"
  cscript="$(container_path_for_existing "$script")"

  local args=(python3 "$cscript" --url "$url" --out "$cout" --wait-ms "$wait_ms")
  if [[ -n "$proxy" ]]; then
    args+=(--proxy "$proxy")
  fi
  if [[ "$headed" == "1" ]]; then
    args+=(--headed)
  fi
  docker_exec "${args[@]}"
}

cmd_browser() {
  local subcommand="${1:-}"
  [[ -n "$subcommand" ]] || die 'browser requires: devtools'
  shift || true
  case "$subcommand" in
    devtools) cmd_browser_devtools "$@" ;;
    *) die "unknown browser subcommand: $subcommand" ;;
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

  if [[ ! -f "$(state_root_abs)/config.json" ]]; then
    printf '{"version":"2","created_at":"%s"}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$(state_root_abs)/config.json"
  fi

  state_helper engagement-init --dir "$out" --name "$name" --url "$url" --host "$host"
  set_current_engagement "$out"
}

cmd_evidence_add() {
  local dir="" engagement="" path="" kind="" title="" finding="" module="" url="" method="" role="" command="" notes=""
  while (($#)); do
    case "$1" in
      --dir) dir="${2:-}"; shift 2 ;;
      --engagement) engagement="${2:-}"; shift 2 ;;
      --path) path="${2:-}"; shift 2 ;;
      --kind) kind="${2:-}"; shift 2 ;;
      --title) title="${2:-}"; shift 2 ;;
      --finding) finding="${2:-}"; shift 2 ;;
      --module) module="${2:-}"; shift 2 ;;
      --url) url="${2:-}"; shift 2 ;;
      --method) method="${2:-}"; shift 2 ;;
      --role) role="${2:-}"; shift 2 ;;
      --command) command="${2:-}"; shift 2 ;;
      --notes) notes="${2:-}"; shift 2 ;;
      *) die "unknown evidence add argument: $1" ;;
    esac
  done
  [[ -n "$path" && -n "$kind" && -n "$title" ]] || die 'evidence add requires --path, --kind, and --title'
  dir="$(resolve_engagement_dir "$dir" "$engagement")"
  local args=(evidence-add --dir "$dir" --path "$path" --kind "$kind" --title "$title")
  append_arg_if_set args --finding "$finding"
  append_arg_if_set args --module "$module"
  append_arg_if_set args --url "$url"
  append_arg_if_set args --method "$method"
  append_arg_if_set args --role "$role"
  append_arg_if_set args --command "$command"
  append_arg_if_set args --notes "$notes"
  state_helper "${args[@]}"
}

cmd_evidence_list() {
  local dir="" engagement=""
  while (($#)); do
    case "$1" in
      --dir) dir="${2:-}"; shift 2 ;;
      --engagement) engagement="${2:-}"; shift 2 ;;
      *) die "unknown evidence list argument: $1" ;;
    esac
  done
  dir="$(resolve_engagement_dir "$dir" "$engagement")"
  state_helper evidence-list --dir "$dir"
}

cmd_evidence() {
  local subcommand="${1:-}"
  [[ -n "$subcommand" ]] || die 'evidence requires: add or list'
  shift || true
  case "$subcommand" in
    add) cmd_evidence_add "$@" ;;
    list) cmd_evidence_list "$@" ;;
    *) die "unknown evidence subcommand: $subcommand" ;;
  esac
}

cmd_artifact_add() {
  local dir="" engagement="" path="" kind="" title="" finding="" module="" notes=""
  while (($#)); do
    case "$1" in
      --dir) dir="${2:-}"; shift 2 ;;
      --engagement) engagement="${2:-}"; shift 2 ;;
      --path) path="${2:-}"; shift 2 ;;
      --kind) kind="${2:-}"; shift 2 ;;
      --title) title="${2:-}"; shift 2 ;;
      --finding) finding="${2:-}"; shift 2 ;;
      --module) module="${2:-}"; shift 2 ;;
      --notes) notes="${2:-}"; shift 2 ;;
      *) die "unknown artifact add argument: $1" ;;
    esac
  done
  [[ -n "$path" && -n "$kind" && -n "$title" ]] || die 'artifact add requires --path, --kind, and --title'
  dir="$(resolve_engagement_dir "$dir" "$engagement")"
  local args=(artifact-add --dir "$dir" --path "$path" --kind "$kind" --title "$title")
  append_arg_if_set args --finding "$finding"
  append_arg_if_set args --module "$module"
  append_arg_if_set args --notes "$notes"
  state_helper "${args[@]}"
}

cmd_artifact_list() {
  local dir="" engagement=""
  while (($#)); do
    case "$1" in
      --dir) dir="${2:-}"; shift 2 ;;
      --engagement) engagement="${2:-}"; shift 2 ;;
      *) die "unknown artifact list argument: $1" ;;
    esac
  done
  dir="$(resolve_engagement_dir "$dir" "$engagement")"
  state_helper artifact-list --dir "$dir"
}

cmd_artifact() {
  local subcommand="${1:-}"
  [[ -n "$subcommand" ]] || die 'artifact requires: add or list'
  shift || true
  case "$subcommand" in
    add) cmd_artifact_add "$@" ;;
    list) cmd_artifact_list "$@" ;;
    *) die "unknown artifact subcommand: $subcommand" ;;
  esac
}

cmd_finding_add() {
  local dir="" engagement="" title="" severity="" status="confirmed" module="" asset="" url="" method="" path="" parameter="" role="" object="" confidence="" summary="" impact="" exploitability="" remediation="" cvss="" owasp="" cwe="" wstg="" notes=""
  local evidence_args=() step_args=() reference_args=()
  while (($#)); do
    case "$1" in
      --dir) dir="${2:-}"; shift 2 ;;
      --engagement) engagement="${2:-}"; shift 2 ;;
      --title) title="${2:-}"; shift 2 ;;
      --severity) severity="${2:-}"; shift 2 ;;
      --status) status="${2:-}"; shift 2 ;;
      --module) module="${2:-}"; shift 2 ;;
      --asset) asset="${2:-}"; shift 2 ;;
      --url) url="${2:-}"; shift 2 ;;
      --method) method="${2:-}"; shift 2 ;;
      --path) path="${2:-}"; shift 2 ;;
      --parameter) parameter="${2:-}"; shift 2 ;;
      --role) role="${2:-}"; shift 2 ;;
      --object) object="${2:-}"; shift 2 ;;
      --evidence) evidence_args+=(--evidence "${2:-}"); shift 2 ;;
      --confidence) confidence="${2:-}"; shift 2 ;;
      --summary) summary="${2:-}"; shift 2 ;;
      --step) step_args+=(--step "${2:-}"); shift 2 ;;
      --impact) impact="${2:-}"; shift 2 ;;
      --exploitability) exploitability="${2:-}"; shift 2 ;;
      --remediation) remediation="${2:-}"; shift 2 ;;
      --cvss) cvss="${2:-}"; shift 2 ;;
      --owasp) owasp="${2:-}"; shift 2 ;;
      --cwe) cwe="${2:-}"; shift 2 ;;
      --wstg) wstg="${2:-}"; shift 2 ;;
      --reference) reference_args+=(--reference "${2:-}"); shift 2 ;;
      --notes) notes="${2:-}"; shift 2 ;;
      *) die "unknown finding add argument: $1" ;;
    esac
  done
  [[ -n "$title" && -n "$severity" ]] || die 'finding add requires --title and --severity'
  dir="$(resolve_engagement_dir "$dir" "$engagement")"
  local args=(finding-add --dir "$dir" --title "$title" --severity "$severity" --status "$status")
  args+=("${evidence_args[@]}" "${step_args[@]}" "${reference_args[@]}")
  append_arg_if_set args --module "$module"
  append_arg_if_set args --asset "$asset"
  append_arg_if_set args --url "$url"
  append_arg_if_set args --method "$method"
  append_arg_if_set args --path "$path"
  append_arg_if_set args --parameter "$parameter"
  append_arg_if_set args --role "$role"
  append_arg_if_set args --object "$object"
  append_arg_if_set args --confidence "$confidence"
  append_arg_if_set args --summary "$summary"
  append_arg_if_set args --impact "$impact"
  append_arg_if_set args --exploitability "$exploitability"
  append_arg_if_set args --remediation "$remediation"
  append_arg_if_set args --cvss "$cvss"
  append_arg_if_set args --owasp "$owasp"
  append_arg_if_set args --cwe "$cwe"
  append_arg_if_set args --wstg "$wstg"
  append_arg_if_set args --notes "$notes"
  state_helper "${args[@]}"
}

cmd_finding_list() {
  local dir="" engagement="" status_filter=""
  while (($#)); do
    case "$1" in
      --dir) dir="${2:-}"; shift 2 ;;
      --engagement) engagement="${2:-}"; shift 2 ;;
      --status) status_filter="${2:-}"; shift 2 ;;
      *) die "unknown finding list argument: $1" ;;
    esac
  done
  dir="$(resolve_engagement_dir "$dir" "$engagement")"
  local args=(finding-list --dir "$dir")
  append_arg_if_set args --status "$status_filter"
  state_helper "${args[@]}"
}

cmd_todo_add() {
  local dir="" engagement="" task="" module="" priority="medium" finding="" notes=""
  local evidence_args=()
  while (($#)); do
    case "$1" in
      --dir) dir="${2:-}"; shift 2 ;;
      --engagement) engagement="${2:-}"; shift 2 ;;
      --task) task="${2:-}"; shift 2 ;;
      --module) module="${2:-}"; shift 2 ;;
      --priority) priority="${2:-}"; shift 2 ;;
      --finding) finding="${2:-}"; shift 2 ;;
      --evidence) evidence_args+=(--evidence "${2:-}"); shift 2 ;;
      --notes) notes="${2:-}"; shift 2 ;;
      *) die "unknown todo add argument: $1" ;;
    esac
  done
  [[ -n "$task" ]] || die 'todo add requires --task'
  dir="$(resolve_engagement_dir "$dir" "$engagement")"
  local args=(todo-add --dir "$dir" --task "$task" --priority "$priority")
  args+=("${evidence_args[@]}")
  append_arg_if_set args --module "$module"
  append_arg_if_set args --finding "$finding"
  append_arg_if_set args --notes "$notes"
  state_helper "${args[@]}"
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
  local args=(todo-list --dir "$dir")
  append_arg_if_set args --status "$status_filter"
  state_helper "${args[@]}"
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
  local args=(todo-update --dir "$dir" --id "$id" --status "$status")
  append_arg_if_set args --notes "$notes"
  state_helper "${args[@]}"
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
  state_helper report-generate --dir "$dir"
}

cmd_report_list() {
  local dir="" engagement=""
  while (($#)); do
    case "$1" in
      --dir) dir="${2:-}"; shift 2 ;;
      --engagement) engagement="${2:-}"; shift 2 ;;
      *) die "unknown report list argument: $1" ;;
    esac
  done
  dir="$(resolve_engagement_dir "$dir" "$engagement")"
  state_helper report-list --dir "$dir"
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
  [[ -n "$subcommand" ]] || die 'report requires: generate or list'
  shift || true
  case "$subcommand" in
    generate) cmd_report_generate "$@" ;;
    list) cmd_report_list "$@" ;;
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
    script) cmd_script "$@" ;;
    zap) cmd_zap "$@" ;;
    browser) cmd_browser "$@" ;;
    engagement) cmd_engagement "$@" ;;
    evidence) cmd_evidence "$@" ;;
    artifact) cmd_artifact "$@" ;;
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
    save-evidence) cmd_evidence_add "$@" ;;
    get-evidence) cmd_evidence_list "$@" ;;
    save-artifact) cmd_artifact_add "$@" ;;
    get-artifacts) cmd_artifact_list "$@" ;;
    save-finding) cmd_finding_add "$@" ;;
    get-findings) cmd_finding_list "$@" ;;
    save-todo) cmd_todo_add "$@" ;;
    get-todos) cmd_todo_list "$@" ;;
    update-todo) cmd_todo_update "$@" ;;
    generate-report) cmd_report_generate "$@" ;;
    get-reports) cmd_report_list "$@" ;;

    -h|--help|help) usage ;;
    *) usage; die "unknown command: $command" ;;
  esac
}

main "$@"
