#!/usr/bin/env bash
set -euo pipefail

# ─── OpenGhost Unified Pentest Launcher ──────────────────────────────────────
# Central entry point for ALL tool execution. Enforces:
#   1. Command blocklist (dangerous commands rejected)
#   2. Scope checking (out-of-scope targets rejected)
#   3. Rate limiting (token bucket per target)
#   4. Circuit breaker (unreachable targets auto-paused)
#   5. Output truncation (caps stdout/stderr)
# ─────────────────────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${SKILL_DIR}/../.." && pwd)"

IMAGE_NAME="${OPENGHOST_IMAGE:-openghost-runtime:latest}"
CONTAINER_NAME="${OPENGHOST_CONTAINER:-openghost-runtime}"
WORKSPACE_DIR="${OPENGHOST_WORKSPACE:-${REPO_ROOT}}"

MAX_STDOUT=15000
MAX_STDERR=5000

# ─── Blocklist ───────────────────────────────────────────────────────────────
BLOCKED_PATTERNS=(
  'rm -rf /'  'rm -rf /*'  'mkfs'  'dd if='  ':(){:|:&};:'
  'shutdown'  'reboot'  'halt'  'poweroff'  'init 0'  'init 6'
  'chmod -R 777 /'  'chown -R'  '> /dev/sd'  'mv / '  'wget.*|.*sh'
  'curl.*|.*sh'  'nc -e'  'ncat -e'  '/dev/tcp/'  'telnet.*|'
)

check_blocklist() {
  local cmd="$1"
  local cmd_lower
  cmd_lower="$(echo "$cmd" | tr '[:upper:]' '[:lower:]')"
  for pattern in "${BLOCKED_PATTERNS[@]}"; do
    if [[ "$cmd_lower" == *"$pattern"* ]]; then
      printf '{"error":"Command blocked","reason":"matches blocklist pattern: %s"}\n' "$pattern" >&2
      return 1
    fi
  done
  return 0
}

# ─── Scope Checker ───────────────────────────────────────────────────────────
extract_targets() {
  local cmd="$1"
  grep -oE '(https?://[^ "'\'']+|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})' <<< "$cmd" 2>/dev/null | while read -r url; do
    echo "$url" | sed -E 's|https?://||;s|/.*||;s|:.*||'
  done | sort -u
}

check_scope() {
  local cmd="$1"
  local scope_file="${2:-}"
  [[ -z "$scope_file" || ! -f "$scope_file" ]] && return 0

  local targets
  targets="$(extract_targets "$cmd")"
  [[ -z "$targets" ]] && return 0

  while IFS= read -r target; do
    [[ -z "$target" ]] && continue
    if ! grep -qiF "$target" "$scope_file" 2>/dev/null; then
      local found=false
      while IFS= read -r pattern; do
        pattern="$(echo "$pattern" | sed 's/^[- ]*//' | tr -d '"' | tr -d "'")"
        [[ -z "$pattern" || "$pattern" == "#"* ]] && continue
        if [[ "$pattern" == "*."* ]]; then
          local suffix="${pattern#\*.}"
          if [[ "$target" == *".$suffix" || "$target" == "$suffix" ]]; then
            found=true; break
          fi
        elif [[ "$target" == "$pattern" ]]; then
          found=true; break
        fi
      done < <(grep -E '^\s*-\s' "$scope_file" 2>/dev/null || true)
      if [[ "$found" == "false" ]]; then
        printf '{"error":"Target out of scope","target":"%s"}\n' "$target" >&2
        return 1
      fi
    fi
  done <<< "$targets"
  return 0
}

# ─── Rate Limiter (file-based token bucket) ──────────────────────────────────
RATE_STATE_DIR="/tmp/openghost-rate"
RATE_LIMIT="${OPENGHOST_RATE_LIMIT:-5}"
RATE_WINDOW=1

check_rate_limit() {
  local target="${1:-default}"
  mkdir -p "$RATE_STATE_DIR"
  local state_file="$RATE_STATE_DIR/$(echo "$target" | tr -c '[:alnum:]' '_')"
  local now
  now="$(date +%s)"

  if [[ -f "$state_file" ]]; then
    local last_time count
    read -r last_time count < "$state_file" 2>/dev/null || { last_time=0; count=0; }
    if (( now - last_time < RATE_WINDOW )); then
      if (( count >= RATE_LIMIT )); then
        printf '{"error":"Rate limit exceeded","target":"%s","limit":"%s/s"}\n' "$target" "$RATE_LIMIT" >&2
        return 1
      fi
      echo "$last_time $((count + 1))" > "$state_file"
    else
      echo "$now 1" > "$state_file"
    fi
  else
    echo "$now 1" > "$state_file"
  fi
  return 0
}

# ─── Circuit Breaker ─────────────────────────────────────────────────────────
CIRCUIT_STATE_DIR="/tmp/openghost-circuit"
CIRCUIT_THRESHOLD=5
CIRCUIT_RESET_SEC=60

check_circuit() {
  local target="${1:-default}"
  mkdir -p "$CIRCUIT_STATE_DIR"
  local state_file="$CIRCUIT_STATE_DIR/$(echo "$target" | tr -c '[:alnum:]' '_')"
  local now
  now="$(date +%s)"

  if [[ -f "$state_file" ]]; then
    local failures last_fail
    read -r failures last_fail < "$state_file" 2>/dev/null || { failures=0; last_fail=0; }
    if (( failures >= CIRCUIT_THRESHOLD )); then
      if (( now - last_fail < CIRCUIT_RESET_SEC )); then
        local remaining=$(( CIRCUIT_RESET_SEC - (now - last_fail) ))
        printf '{"error":"Circuit breaker open","target":"%s","failures":%d,"retry_in":"%ds"}\n' \
          "$target" "$failures" "$remaining" >&2
        return 1
      else
        rm -f "$state_file"
      fi
    fi
  fi
  return 0
}

update_circuit() {
  local target="${1:-default}" exit_code="${2:-0}"
  mkdir -p "$CIRCUIT_STATE_DIR"
  local state_file="$CIRCUIT_STATE_DIR/$(echo "$target" | tr -c '[:alnum:]' '_')"
  local now
  now="$(date +%s)"

  if (( exit_code != 0 )); then
    local failures=0
    [[ -f "$state_file" ]] && { read -r failures _ < "$state_file" 2>/dev/null || failures=0; }
    echo "$((failures + 1)) $now" > "$state_file"
  else
    rm -f "$state_file" 2>/dev/null || true
  fi
}

# ─── Output Truncation ──────────────────────────────────────────────────────
truncate_output() {
  local text="$1" max="$2"
  if (( ${#text} > max )); then
    echo "${text:0:$max}"
    printf '\n[TRUNCATED — %d bytes total, showing first %d]\n' "${#text}" "$max"
  else
    echo "$text"
  fi
}

# ─── Safety Pipeline ────────────────────────────────────────────────────────
# Runs: blocklist → scope → circuit → rate limit → execute → circuit update → truncate
run_safe() {
  local cmd="$1"
  local scope_file="${OPENGHOST_SCOPE:-}"

  check_blocklist "$cmd" || return 1
  check_scope "$cmd" "$scope_file" || return 1

  local targets
  targets="$(extract_targets "$cmd")"
  local primary_target
  primary_target="$(echo "$targets" | head -1)"
  primary_target="${primary_target:-default}"

  check_circuit "$primary_target" || return 1
  check_rate_limit "$primary_target" || return 1

  local stdout stderr exit_code
  stdout="$(docker exec "$CONTAINER_NAME" /bin/bash -lc "$cmd" 2>/tmp/openghost_stderr)" && exit_code=0 || exit_code=$?
  stderr="$(cat /tmp/openghost_stderr 2>/dev/null || true)"

  update_circuit "$primary_target" "$exit_code"

  truncate_output "$stdout" "$MAX_STDOUT"
  if [[ -n "$stderr" ]]; then
    truncate_output "$stderr" "$MAX_STDERR" >&2
  fi

  return "$exit_code"
}

# ─── Container Management ───────────────────────────────────────────────────
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

require_docker() { command -v docker >/dev/null 2>&1 || die "Docker not found"; }

container_running() {
  docker inspect --format '{{.State.Running}}' "$CONTAINER_NAME" 2>/dev/null | grep -q "true"
}

ensure_image() {
  if ! docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
    local dockerfile="${SKILL_DIR}/docker/Dockerfile"
    if [[ -f "$dockerfile" ]]; then
      docker build -t "$IMAGE_NAME" -f "$dockerfile" "${SKILL_DIR}/docker"
    else
      die "Image $IMAGE_NAME not found and no Dockerfile at $dockerfile"
    fi
  fi
}

start_runtime() {
  require_docker
  ensure_image
  if container_running; then
    printf 'runtime already running: %s\n' "$CONTAINER_NAME"
    return
  fi
  docker inspect "$CONTAINER_NAME" >/dev/null 2>&1 && docker rm -f "$CONTAINER_NAME" >/dev/null
  docker run -d \
    --name "$CONTAINER_NAME" \
    --security-opt no-new-privileges:true \
    --cap-drop ALL \
    --cap-add NET_RAW \
    --add-host host.docker.internal:host-gateway \
    -v "${WORKSPACE_DIR}:/workspace" \
    -w /workspace \
    "$IMAGE_NAME" >/dev/null
  printf 'runtime started: %s\n' "$CONTAINER_NAME"
}

ensure_running() {
  require_docker
  container_running || start_runtime >/dev/null
}

# ─── Tool Allowlist ──────────────────────────────────────────────────────────
ALLOWED_TOOLS=(
  bash sh python python3 ruby perl node npm
  nmap nuclei ffuf gobuster dirsearch katana httpx subfinder dnsx
  nikto sqlmap arjun wafw00f testssl.sh
  curl wget http jq dig whois nc ncat
  jwt_tool hashcat hydra
  wscat websocat
  linkfinder
  mitmproxy
  ysoserial tplmap ssti ssrfmap nosqlmap
  graphql-cop
)

is_allowed_tool() {
  local tool="$1"
  for allowed in "${ALLOWED_TOOLS[@]}"; do
    [[ "$tool" == "$allowed" ]] && return 0
  done
  return 1
}

# ─── Commands ────────────────────────────────────────────────────────────────
usage() {
  cat <<'EOF'
Usage: openghost.sh <command> [args...]

Container:
  preflight              Check Docker and image status
  start                  Build image if needed and start runtime
  status                 Show runtime and toolchain health
  stop                   Stop and remove runtime

Execution (all go through safety pipeline):
  exec-tool TOOL [args]  Run an approved tool in the sandbox
  exec-bash 'COMMAND'    Run a shell command in the sandbox
  exec-python 'SCRIPT'   Run a Python script in the sandbox

Engagement:
  init --url URL --out DIR   Create engagement directory
  save-finding --dir DIR ... Save a finding to findings.json
  get-findings --dir DIR     List findings
  save-todo --dir DIR ...    Save a todo item
  get-todos --dir DIR        List todos
  update-todo --dir DIR ...  Update a todo status
  generate-report --dir DIR  Compile findings into report

Environment:
  OPENGHOST_SCOPE=path/to/scope.yaml  Enforce scope checking
  OPENGHOST_RATE_LIMIT=5              Requests per second per target
  OPENGHOST_IMAGE=name:tag            Docker image name
  OPENGHOST_CONTAINER=name            Container name
EOF
}

cmd_preflight() {
  require_docker
  docker info >/dev/null
  if docker image inspect "$IMAGE_NAME" >/dev/null 2>&1; then
    printf 'image: present (%s)\n' "$IMAGE_NAME"
  else
    printf 'image: missing (%s); start will build it\n' "$IMAGE_NAME"
  fi
  printf 'container: %s\n' "$CONTAINER_NAME"
}

cmd_status() {
  require_docker
  if ! docker inspect "$CONTAINER_NAME" >/dev/null 2>&1; then
    printf 'runtime: not created\n'; return
  fi
  docker inspect --format 'runtime: {{.State.Status}}' "$CONTAINER_NAME"
  if container_running; then
    docker exec "$CONTAINER_NAME" bash -c 'echo "tools:"; for t in nmap sqlmap nuclei ffuf httpx curl python3; do command -v $t >/dev/null 2>&1 && echo "  $t: ok" || echo "  $t: missing"; done'
  fi
}

cmd_init() {
  local url="" out=""
  while (($#)); do
    case "$1" in
      --url) url="${2:-}"; shift 2 ;;
      --out) out="${2:-}"; shift 2 ;;
      *) die "unknown init argument: $1" ;;
    esac
  done
  [[ -n "$url" ]] || die "init requires --url"
  [[ -n "$out" ]] || die "init requires --out"

  mkdir -p "$out"/{notes,evidence/{http,screenshots,raw},findings,reports,artifacts}

  cat > "$out/scope.yaml" <<SCOPE
target_url: "$url"
allowed_hosts:
  - "$(echo "$url" | sed -E 's|https?://||;s|/.*||;s|:.*||')"
exclusions:
  paths: [/logout]
  hosts: []
rate_limits:
  requests_per_second: 5
notes: "Edit this file before testing."
SCOPE

  echo '[]' > "$out/findings.json"
  echo '[]' > "$out/todos.json"
  printf '{"target_url":"%s","created_at":"%s","status":"active"}\n' \
    "$url" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$out/engagement.json"
  printf 'Engagement created: %s\n' "$out"
}

cmd_exec_tool() {
  (($# >= 1)) || die "exec-tool requires a tool name"
  local tool="$1"; shift
  ensure_running
  is_allowed_tool "$tool" || die "tool not in allowlist: $tool"
  # Build a properly quoted command string preserving argument boundaries
  local cmd="$tool"
  local arg
  for arg in "$@"; do
    # Escape single quotes inside each argument and wrap in single quotes
    cmd+=" '$(printf '%s' "$arg" | sed "s/'/'\\\\''/g")'"
  done
  run_safe "$cmd"
}

cmd_exec_bash() {
  (($# == 1)) || die "exec-bash requires one command string"
  ensure_running
  run_safe "$1"
}

cmd_exec_python() {
  (($# == 1)) || die "exec-python requires one script string"
  ensure_running
  # Pass script via base64 to avoid quote-escaping issues
  local encoded
  encoded="$(printf '%s' "$1" | base64 -w0)"
  run_safe "python3 -c \"import base64,sys;exec(base64.b64decode('$encoded').decode())\""
}

cmd_stop() {
  require_docker
  if docker inspect "$CONTAINER_NAME" >/dev/null 2>&1; then
    docker rm -f "$CONTAINER_NAME" >/dev/null
    printf 'runtime stopped: %s\n' "$CONTAINER_NAME"
  else
    printf 'runtime not present\n'
  fi
}

# ─── Finding Management ─────────────────────────────────────────────────────
cmd_save_finding() {
  local dir="" title="" severity="" module="" url="" evidence="" confidence="" impact="" remediation="" wstg=""
  while (($#)); do
    case "$1" in
      --dir) dir="$2"; shift 2 ;;
      --title) title="$2"; shift 2 ;;
      --severity) severity="$2"; shift 2 ;;
      --module) module="$2"; shift 2 ;;
      --url) url="$2"; shift 2 ;;
      --evidence) evidence="$2"; shift 2 ;;
      --confidence) confidence="$2"; shift 2 ;;
      --impact) impact="$2"; shift 2 ;;
      --remediation) remediation="$2"; shift 2 ;;
      --wstg) wstg="$2"; shift 2 ;;
      *) die "unknown save-finding argument: $1" ;;
    esac
  done
  [[ -n "$dir" && -n "$title" && -n "$severity" ]] || die "save-finding requires --dir, --title, --severity"

  local file="$dir/findings.json"
  [[ -f "$file" ]] || echo '[]' > "$file"

  local count
  count="$(python3 -c "import json,sys; print(len(json.load(open(sys.argv[1]))))" "$file" 2>/dev/null || echo 0)"
  local id="F-$(printf '%03d' $((count + 1)))"
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  # Pass values via env vars to avoid shell injection through inline Python
  OG_FILE="$file" OG_ID="$id" OG_TITLE="$title" OG_SEVERITY="$severity" \
  OG_MODULE="$module" OG_URL="$url" OG_EVIDENCE="$evidence" \
  OG_CONFIDENCE="${confidence:-0}" OG_IMPACT="$impact" \
  OG_REMEDIATION="$remediation" OG_WSTG="$wstg" OG_TS="$ts" \
  python3 -c "
import json, os
f = json.load(open(os.environ['OG_FILE']))
ev = os.environ['OG_EVIDENCE']
conf_str = os.environ['OG_CONFIDENCE']
f.append({
    'id': os.environ['OG_ID'],
    'title': os.environ['OG_TITLE'],
    'severity': os.environ['OG_SEVERITY'],
    'module': os.environ['OG_MODULE'],
    'url': os.environ['OG_URL'],
    'evidence': ev.split(',') if ev else [],
    'confidence': int(conf_str) if conf_str.isdigit() else 0,
    'impact': os.environ['OG_IMPACT'],
    'remediation': os.environ['OG_REMEDIATION'],
    'wstg_id': os.environ['OG_WSTG'],
    'status': 'confirmed',
    'created_at': os.environ['OG_TS']
})
json.dump(f, open(os.environ['OG_FILE'], 'w'), indent=2)
print(json.dumps({'saved': os.environ['OG_ID'], 'title': os.environ['OG_TITLE'], 'severity': os.environ['OG_SEVERITY']}))
"
}

cmd_get_findings() {
  local dir=""
  while (($#)); do
    case "$1" in
      --dir) dir="$2"; shift 2 ;;
      *) shift ;;
    esac
  done
  [[ -n "$dir" ]] || die "get-findings requires --dir"
  local file="$dir/findings.json"
  [[ -f "$file" ]] || { echo '[]'; return; }
  OG_FILE="$file" python3 -c "
import json, os
findings = json.load(open(os.environ['OG_FILE']))
for f in findings:
    sev = f.get('severity','?').upper()
    badge = {'CRITICAL':'🔴','HIGH':'🟠','MEDIUM':'🟡','LOW':'🔵','INFO':'⚪'}.get(sev,'⚪')
    print(f\"{badge} [{f['id']}] {f['title']} ({sev}) — confidence:{f.get('confidence',0)}%\")
print(f'\\nTotal: {len(findings)} findings')
"
}

# ─── Todo Management ─────────────────────────────────────────────────────────
cmd_save_todo() {
  local dir="" task="" module="" priority="medium"
  while (($#)); do
    case "$1" in
      --dir) dir="$2"; shift 2 ;;
      --task) task="$2"; shift 2 ;;
      --module) module="$2"; shift 2 ;;
      --priority) priority="$2"; shift 2 ;;
      *) die "unknown save-todo argument: $1" ;;
    esac
  done
  [[ -n "$dir" && -n "$task" ]] || die "save-todo requires --dir, --task"

  local file="$dir/todos.json"
  [[ -f "$file" ]] || echo '[]' > "$file"

  local count
  count="$(python3 -c "import json,sys; print(len(json.load(open(sys.argv[1]))))" "$file" 2>/dev/null || echo 0)"
  local id="T-$(printf '%03d' $((count + 1)))"
  local ts
  ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  # Pass values via env vars to avoid shell injection through inline Python
  OG_FILE="$file" OG_ID="$id" OG_TASK="$task" OG_MODULE="$module" \
  OG_PRIORITY="$priority" OG_TS="$ts" \
  python3 -c "
import json, os
f = json.load(open(os.environ['OG_FILE']))
f.append({
    'id': os.environ['OG_ID'],
    'task': os.environ['OG_TASK'],
    'module': os.environ['OG_MODULE'],
    'priority': os.environ['OG_PRIORITY'],
    'status': 'pending',
    'created_at': os.environ['OG_TS'],
    'completed_at': None
})
json.dump(f, open(os.environ['OG_FILE'], 'w'), indent=2)
print(json.dumps({'saved': os.environ['OG_ID'], 'task': os.environ['OG_TASK']}))
"
}

cmd_get_todos() {
  local dir="" status_filter=""
  while (($#)); do
    case "$1" in
      --dir) dir="$2"; shift 2 ;;
      --status) status_filter="$2"; shift 2 ;;
      *) shift ;;
    esac
  done
  [[ -n "$dir" ]] || die "get-todos requires --dir"
  local file="$dir/todos.json"
  [[ -f "$file" ]] || { echo '[]'; return; }
  OG_FILE="$file" OG_SF="$status_filter" python3 -c "
import json, os
todos = json.load(open(os.environ['OG_FILE']))
sf = os.environ.get('OG_SF', '')
for t in todos:
    if sf and t['status'] != sf: continue
    icon = {'pending':'⬜','done':'✅','skip':'⏭','blocked':'🚫'}.get(t['status'],'⬜')
    pri = {'high':'🔴','medium':'🟡','low':'🔵'}.get(t.get('priority',''),'⬜')
    print(f\"{icon} [{t['id']}] {pri} {t['task']} ({t.get('module','')}) — {t['status']}\")
pending = sum(1 for t in todos if t['status']=='pending')
done = sum(1 for t in todos if t['status']=='done')
print(f'\\nTotal: {len(todos)} | Pending: {pending} | Done: {done}')
"
}

cmd_update_todo() {
  local dir="" id="" status="" notes=""
  while (($#)); do
    case "$1" in
      --dir) dir="$2"; shift 2 ;;
      --id) id="$2"; shift 2 ;;
      --status) status="$2"; shift 2 ;;
      --notes) notes="$2"; shift 2 ;;
      *) die "unknown update-todo argument: $1" ;;
    esac
  done
  [[ -n "$dir" && -n "$id" && -n "$status" ]] || die "update-todo requires --dir, --id, --status"
  local file="$dir/todos.json"
  [[ -f "$file" ]] || die "no todos.json in $dir"

  # Pass values via env vars to avoid shell injection through inline Python
  OG_FILE="$file" OG_ID="$id" OG_STATUS="$status" OG_NOTES="$notes" \
  python3 -c "
import json, os
from datetime import datetime, timezone
f = json.load(open(os.environ['OG_FILE']))
found = False
for t in f:
    if t['id'] == os.environ['OG_ID']:
        t['status'] = os.environ['OG_STATUS']
        if os.environ['OG_NOTES']: t['notes'] = os.environ['OG_NOTES']
        if os.environ['OG_STATUS'] in ('done','skip'): t['completed_at'] = datetime.now(timezone.utc).isoformat()
        found = True
        break
if not found:
    print(json.dumps({'error': 'todo not found', 'id': os.environ['OG_ID']}))
else:
    json.dump(f, open(os.environ['OG_FILE'], 'w'), indent=2)
    print(json.dumps({'updated': os.environ['OG_ID'], 'status': os.environ['OG_STATUS']}))
"
}

# ─── Report Generation ───────────────────────────────────────────────────────
cmd_generate_report() {
  local dir=""
  while (($#)); do
    case "$1" in
      --dir) dir="$2"; shift 2 ;;
      *) shift ;;
    esac
  done
  [[ -n "$dir" ]] || die "generate-report requires --dir"

  local report="$dir/reports/report-$(date +%Y%m%d-%H%M%S).md"
  OG_DIR="$dir" OG_REPORT="$report" python3 -c "
import json, os
from datetime import datetime, timezone

d = os.environ['OG_DIR']
report_path = os.environ['OG_REPORT']

eng = json.load(open(d + '/engagement.json')) if os.path.exists(d + '/engagement.json') else {}
findings = json.load(open(d + '/findings.json')) if os.path.exists(d + '/findings.json') else []
todos = json.load(open(d + '/todos.json')) if os.path.exists(d + '/todos.json') else []

sev_order = {'critical':0,'high':1,'medium':2,'low':3,'info':4}
findings.sort(key=lambda f: sev_order.get(f.get('severity','info'),5))

badges = {'critical':'🔴','high':'🟠','medium':'🟡','low':'🔵','info':'⚪'}
lines = []
lines.append('# OpenGhost Penetration Test Report')
lines.append(f\"\"\"
**Target**: {eng.get('target_url','N/A')}
**Date**: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}
**Status**: {eng.get('status','N/A')}
\"\"\")

lines.append('## Executive Summary')
counts = {}
for f in findings:
    s = f.get('severity','info')
    counts[s] = counts.get(s,0) + 1
lines.append(f'Total findings: {len(findings)}')
for s in ['critical','high','medium','low','info']:
    if counts.get(s,0) > 0:
        lines.append(f'- {badges.get(s,\"⚪\")} {s.upper()}: {counts[s]}')
lines.append('')

lines.append('## Findings')
for f in findings:
    b = badges.get(f.get('severity','info'),'⚪')
    lines.append(f\"\"\"
### {b} {f['id']}: {f['title']}

| Field | Value |
|-------|-------|
| Severity | {f.get('severity','N/A').upper()} |
| Module | {f.get('module','N/A')} |
| URL | {f.get('url','N/A')} |
| Confidence | {f.get('confidence',0)}% |
| WSTG | {f.get('wstg_id','N/A')} |

**Impact**: {f.get('impact','N/A')}

**Remediation**: {f.get('remediation','N/A')}
\"\"\")

pending = [t for t in todos if t['status']=='pending']
if pending:
    lines.append('## Outstanding Testing Items')
    for t in pending:
        lines.append(f\"- ⬜ {t['task']} ({t.get('module','')}) — {t.get('priority','medium')}\")

with open(report_path, 'w') as f:
    f.write('\\n'.join(lines))
print(f'Report generated: {report_path}')
"
}

# ─── Main ────────────────────────────────────────────────────────────────────
main() {
  local command="${1:-}"
  [[ -n "$command" ]] || { usage; exit 1; }
  shift || true

  case "$command" in
    preflight)        cmd_preflight "$@" ;;
    start)            start_runtime "$@" ;;
    status)           cmd_status "$@" ;;
    stop)             cmd_stop "$@" ;;
    init)             cmd_init "$@" ;;
    exec-tool)        cmd_exec_tool "$@" ;;
    exec-bash)        cmd_exec_bash "$@" ;;
    exec-python)      cmd_exec_python "$@" ;;
    save-finding)     cmd_save_finding "$@" ;;
    get-findings)     cmd_get_findings "$@" ;;
    save-todo)        cmd_save_todo "$@" ;;
    get-todos)        cmd_get_todos "$@" ;;
    update-todo)      cmd_update_todo "$@" ;;
    generate-report)  cmd_generate_report "$@" ;;
    -h|--help|help)   usage ;;
    *)                usage; die "unknown command: $command" ;;
  esac
}

main "$@"
