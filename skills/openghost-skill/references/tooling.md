# Tooling Reference

The agent-facing interface is `openghost`. The launcher starts a Docker sandbox and executes every tool inside that container. Do not run offensive tooling directly on the host.

Before the first command, make sure the launcher directory is on `PATH`:

```bash
export PATH="$PWD/skills:$PWD/skills/openghost-skill:$PATH"
```

The `skills/openghost` file is the repository-level CLI shim. If the skill is installed without that shim, `skills/openghost-skill/openghost` exposes the same `openghost` command when `skills/openghost-skill` is on `PATH`.

## Sandbox Commands

```bash
openghost sandbox start
openghost sandbox status
openghost sandbox stop
openghost sandbox logs
openghost sandbox pull
openghost sandbox update
openghost sandbox shell
```

The launcher pulls `ghcr.io/vaibhavsing/openghost-sandbox:latest` by default when the image is missing. Set `OPENGHOST_IMAGE` to override the image. Normal skill users should not build a Dockerfile locally; maintainers build and publish the sandbox from the repo's Docker context.

## Execution Commands

```bash
openghost run <TOOL> [args...]
openghost bash '<COMMAND>'
openghost python code '<SCRIPT>'
openghost python file ./path/to/script.py -- arg1 arg2
openghost python repl
openghost script list
openghost script show api-inventory
openghost script copy api-inventory
openghost script run api-inventory -- --target-url https://<target>
openghost assess plan --target-url https://<target> --mode standard
openghost assess run --target-url https://<target> --confirm-scope-reviewed --mode standard
openghost zap start
openghost zap baseline --target <URL>
openghost browser devtools --url <URL> --zap
```

Compatibility aliases still work:

```bash
openghost exec-tool <TOOL> [args...]
openghost exec-bash '<COMMAND>'
openghost exec-python '<SCRIPT>'
```

## Engagement Commands

```bash
openghost engagement init --url <TARGET_URL> --name <name>
openghost evidence add --path <file> --kind <request|response|screenshot|tool-output|transcript> --title <title>
openghost evidence list
openghost artifact add --path <file> --kind <inventory|auth|tools|scripts|browser|packages> --title <title>
openghost artifact list
openghost finding add --title <title> --severity <severity> --module <module> --url <url> --confidence <90-100> --priority <P0-P4> --priority-rationale <text> --evidence E-001 --step <step>
openghost finding list
openghost todo add --task <task> --module <module> --priority <priority>
openghost todo list
openghost todo update --id <id> --status <status>
openghost report generate
openghost report list
```

OpenGhost stores v2 state under `.openghost/` by default. The latest initialized engagement is active, so `evidence`, `artifact`, `finding`, `todo`, and `report` commands can omit `--dir`. Use `--engagement <name>` to target another engagement or `--dir <path>` for custom paths. Legacy v1 engagement directories are not migrated; create a fresh v2 engagement with `openghost engagement init`.

## Autonomous First Pass

```bash
openghost assess plan --target-url https://<target> --mode standard
openghost assess run --target-url https://<target> --confirm-scope-reviewed --mode standard
```

`assess run` executes safe bundled templates, registers raw JSON outputs as evidence, creates `likely` findings for medium-or-higher signals, adds validation todos, and writes `runs/assess-<timestamp>/assessment.json`. It never creates confirmed findings. See `references/autonomous-assessment.md` before changing mode, tokens, endpoints, or request caps.

## Pentest Script Templates

Bundled Python templates live in `skills/openghost-skill/scripts/pentest/`. They are constrained for OpenGhost scope validation, Docker execution, and evidence output.

```bash
openghost script list
openghost script show xss-check
openghost script run web-baseline -- --target-url https://<target>
openghost script copy bola-check
openghost python file .openghost/engagements/<name>/scripts/bola_check.py -- --base-url https://<target> --token <TOKEN> --endpoints '/api/orders/{id}' --ids 1001,1002
```

Use `script run` for an unchanged stock template. Use `script copy` before changing logic for a target; copied files and `og_pentest.py` are placed in the active engagement `scripts/` directory. Template findings are signals requiring manual validation before `openghost finding add`.

Current templates:

```text
web-baseline, api-inventory, api-owasp-top10, bola-check, bfla-check,
mass-assignment-check, xss-check, cors-check, jwt-check, graphql-check,
websocket-check, hpp-check, forced-browsing-check, sqli-probe,
nosqli-probe, cache-check, vuln-triage
```

## Environment

```bash
export OPENGHOST_IMAGE=ghcr.io/vaibhavsing/openghost-sandbox:latest
export OPENGHOST_CONTAINER=openghost-sandbox
export OPENGHOST_WORKSPACE="$PWD"
export OPENGHOST_HOME="$PWD/.openghost"
export OPENGHOST_SCOPE=.openghost/engagements/<name>/scope.yaml
```

Developer-only local image builds are explicit opt-in:

```bash
OPENGHOST_BUILD=1 \
  OPENGHOST_IMAGE=openghost-sandbox:dev \
  OPENGHOST_DOCKERFILE=docker/Dockerfile \
  OPENGHOST_BUILD_CONTEXT=docker \
  openghost sandbox start
```

## Storage Layout

```text
.openghost/
  config.json
  current
  cache/
  tmp/
  engagements/<name>/
    engagement.json
    scope.yaml
    auth.yaml
    state/
      findings.json
      evidence.json
      artifacts.json
      todos.json
      reports.json
      activity.jsonl
    notes/
    evidence/
      F-001/
      unlinked/
    reports/
    artifacts/
      inventory/
      auth/
      tools/
      scripts/
      browser/
      packages/
    scripts/
    browser/
    zap/
    runs/
    traffic/
```

## Installed Tool Catalog

### Reconnaissance and Scanning

| Tool | Example | Purpose |
|---|---|---|
| `nmap` | `openghost run nmap -sV -sC <target>` | Ports, services, NSE scripts |
| `nikto` | `openghost run nikto -h https://<target>` | Web server checks |
| `nuclei` | `openghost run nuclei -u https://<target>` | Template-based vulnerability scan |
| `httpx` | `openghost bash 'subfinder -d <domain> -silent | httpx -silent -status-code -title -tech-detect'` | Probe live hosts |
| `subfinder` | `openghost run subfinder -d <domain> -silent` | Passive subdomain discovery |
| `dnsx` | `openghost bash 'dnsx -d <domain> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -silent'` | DNS probing |
| `katana` | `openghost run katana -u https://<target> -d 3 -jc -silent` | Crawling |
| `testssl.sh` | `openghost run testssl.sh --quiet https://<target>` | TLS assessment |
| `wafw00f` | `openghost run wafw00f https://<target>` | WAF fingerprinting |

### Discovery and Fuzzing

| Tool | Example | Purpose |
|---|---|---|
| `ffuf` | `openghost run ffuf -u https://<target>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,401,403` | Directory/API fuzzing |
| `dirsearch` | `openghost run dirsearch -u https://<target>` | Path discovery |
| `arjun` | `openghost run arjun -u https://<target>/api/search` | Hidden parameter discovery |
| `linkfinder` | `openghost run linkfinder -i https://<target>/static/app.js -o cli` | JavaScript endpoint extraction |

### Injection and Auth Validation

| Tool | Example | Purpose |
|---|---|---|
| `sqlmap` | `openghost run sqlmap -u "https://<target>/?id=1" --batch` | SQL injection validation |
| `jwt_tool` | `openghost run jwt_tool <JWT>` | JWT analysis and attacks |
| `hashcat` | `openghost run hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt --quiet` | JWT/HMAC secret cracking, CPU default |
| `curl` | `openghost bash 'curl -s -i https://<target>/api'` | Manual HTTP |
| `http` | `openghost run http GET https://<target>/api` | HTTPie CLI for readable HTTP requests |
| `jq` | `openghost bash 'curl -s https://<target>/api | jq .'` | JSON parsing |

### Browser and Protocol Testing

| Tool | Example | Purpose |
|---|---|---|
| `chromium` | `openghost python file .openghost/engagements/<name>/scripts/browser.py` | Browser validation through scripts |
| `playwright` | Python package available inside sandbox | DOM XSS, screenshots, OAuth flows, SPA exploration |
| `zap` | `openghost zap baseline --target https://<target>` | Headless ZAP DAST, passive baseline, API import, reports |
| `zap + playwright` | `openghost browser devtools --url https://<target> --zap` | Browser traffic through ZAP with HAR, trace, screenshot, and alerts |
| `websocat` | `openghost run websocat wss://<target>/ws` | WebSocket testing |
| `grpcurl` | `openghost run grpcurl -plaintext <target>:<port> list` | gRPC discovery/testing |

ZAP is included in the sandbox because it materially improves DAST output, but agents should use the managed `openghost zap` commands instead of raw `zap.sh`. Read `references/zap-playwright.md` before using ZAP or Playwright proxy workflows.

### ZAP and Browser Commands

```bash
openghost zap start
openghost zap status
openghost zap proxy-url
openghost browser devtools --url https://<target> --zap
openghost zap alerts --format json
openghost zap report --format html
openghost zap baseline --target https://<target> --minutes 5
openghost zap api-scan --target https://<target>/openapi.json --format openapi --target-url https://<target>
openghost zap api-scan --target https://<target>/graphql --format graphql --confirm-active
```

`baseline` and default `api-scan` are passive. `--confirm-active` is required for active API scanning and must only be used when active testing is in scope.

## Wordlists

Common paths:

```text
/usr/share/seclists/Discovery/Web-Content/common.txt
/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt
/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
/usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt
/usr/share/seclists/Fuzzing/XSS/XSS-Jhaddix.txt
/usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt
/usr/share/wordlists/rockyou.txt
```

`rockyou.txt` is a symlink to `10k-most-common.txt` in the default image. This keeps the image smaller while still supporting safe JWT weak-secret checks. Mount a larger wordlist under `/workspace` when explicitly authorized.

## Command Patterns

### Save Raw Evidence

```bash
openghost bash 'curl -s -i https://<target>/api/users/1' > /tmp/users-1.txt
openghost evidence add --path /tmp/users-1.txt --kind response --title "GET /api/users/1 response" --module access-control --url /api/users/1
```

### Authenticated Curl

```bash
openghost bash 'curl -s -i -H "Authorization: Bearer <TOKEN>" https://<target>/api/me'
```

### JSON Request

```bash
openghost bash 'curl -s -i -X POST -H "Content-Type: application/json" -H "Authorization: Bearer <TOKEN>" -d "{\"name\":\"test\"}" https://<target>/api/profile'
```

### Browser Script

```bash
openghost python file .openghost/engagements/<name>/scripts/browser-check.py
```

### Script Template Copy

```bash
openghost script copy api-inventory
openghost python file .openghost/engagements/<name>/scripts/api_inventory.py -- --target-url https://<target>
```

## When To Use Raw Bash

Use `openghost bash` for curl loops, custom parsing, and tool chains inside the sandbox. Avoid destructive filesystem commands, unbounded loops, broad credential attacks, and out-of-scope scans.
