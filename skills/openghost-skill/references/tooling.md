# Tooling Reference

This skill exposes one public interface to the agent: `scripts/openghost.sh`. The launcher is responsible for starting the sandbox, enforcing safety controls, and routing commands to the Docker runtime. The underlying implementation can use direct `docker exec` or an internal API server; the agent should not depend on implementation details.

## Launcher Commands

```bash
scripts/openghost.sh preflight
scripts/openghost.sh start
scripts/openghost.sh status
scripts/openghost.sh stop
```

Execution commands:

```bash
scripts/openghost.sh exec-tool <TOOL> [args...]
scripts/openghost.sh exec-bash '<COMMAND>'
scripts/openghost.sh exec-python '<SCRIPT>'
```

Engagement commands:

```bash
scripts/openghost.sh init --url <TARGET_URL> --out ./engagements/<name>
scripts/openghost.sh save-finding --dir ./engagements/<name> --title <title> --severity <severity>
scripts/openghost.sh get-findings --dir ./engagements/<name>
scripts/openghost.sh save-todo --dir ./engagements/<name> --task <task> --module <module> --priority <priority>
scripts/openghost.sh get-todos --dir ./engagements/<name>
scripts/openghost.sh update-todo --dir ./engagements/<name> --id <id> --status <status>
scripts/openghost.sh generate-report --dir ./engagements/<name>
```

Environment:

```bash
export OPENGHOST_SCOPE=./engagements/<name>/scope.yaml
export OPENGHOST_RATE_LIMIT=5
export OPENGHOST_IMAGE=openghost-runtime:latest
export OPENGHOST_CONTAINER=openghost-runtime
```

## Safety Pipeline

All tool execution must pass through the launcher. It provides:

- command allowlist for named tools
- command blocklist for dangerous host/system operations
- scope checking from `OPENGHOST_SCOPE`
- rate limiting per target
- circuit breaker behavior for repeated failures
- output truncation for very large stdout/stderr
- Docker sandbox isolation

## Tool Catalog

### Reconnaissance and Scanning

| Tool | Example | Purpose |
|---|---|---|
| `nmap` | `scripts/openghost.sh exec-tool nmap -sV -sC <target>` | ports, services, NSE |
| `nikto` | `scripts/openghost.sh exec-tool nikto -h https://<target>` | web server checks |
| `nuclei` | `scripts/openghost.sh exec-tool nuclei -u https://<target>` | template-based vuln scan |
| `httpx` | `scripts/openghost.sh exec-bash 'subfinder -d <domain> -silent | httpx -silent -status-code -title -tech-detect'` | probe live hosts |
| `subfinder` | `scripts/openghost.sh exec-tool subfinder -d <domain> -silent` | passive subdomains |
| `katana` | `scripts/openghost.sh exec-tool katana -u https://<target> -d 3 -jc -silent` | crawling |
| `testssl.sh` | `scripts/openghost.sh exec-tool testssl.sh --quiet https://<target>` | TLS assessment |
| `wafw00f` | `scripts/openghost.sh exec-tool wafw00f https://<target>` | WAF fingerprinting |

### Discovery and Fuzzing

| Tool | Example | Purpose |
|---|---|---|
| `ffuf` | `scripts/openghost.sh exec-tool ffuf -u https://<target>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,401,403` | directory/API fuzzing |
| `dirsearch` | `scripts/openghost.sh exec-tool dirsearch -u https://<target>` | path discovery |
| `arjun` | `scripts/openghost.sh exec-tool arjun -u https://<target>/api/search` | hidden parameter discovery |
| `linkfinder` | `scripts/openghost.sh exec-tool linkfinder -i https://<target>/static/app.js -o cli` | JS endpoint extraction |

### Injection and Exploitation Validation

| Tool | Example | Purpose |
|---|---|---|
| `sqlmap` | `scripts/openghost.sh exec-tool sqlmap -u "https://<target>/?id=1" --batch` | SQLi validation |
| `jwt_tool` | `scripts/openghost.sh exec-tool jwt_tool <JWT>` | JWT analysis/attacks |
| `hashcat` | `scripts/openghost.sh exec-bash 'hashcat -m 16500 jwt.txt wordlist.txt'` | hash/JWT secret cracking |
| `wscat` | `scripts/openghost.sh exec-bash 'wscat -c wss://<target>/ws'` | WebSocket testing |
| `curl` | `scripts/openghost.sh exec-bash 'curl -s -i https://<target>/api'` | manual HTTP |
| `jq` | `scripts/openghost.sh exec-bash 'curl -s https://<target>/api | jq .'` | JSON parsing |

### Browser and API Runtime

The sandbox may expose Playwright-managed Chromium and/or an internal API server. The agent-facing contract remains `scripts/openghost.sh`. If browser commands are available in the launcher, use them for:

- DOM XSS validation
- OAuth/OIDC/SAML redirect flows
- authenticated crawling
- screenshots for evidence
- clickjacking/CSRF PoCs
- SPA route exploration

If browser-specific commands are not available yet, use `exec-bash`/`exec-python` inside the sandbox to run approved browser scripts.

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

## Command Patterns

### Save Raw Evidence

```bash
scripts/openghost.sh exec-bash 'curl -s -i https://<target>/api/users/1' > ./engagements/<name>/evidence/http/users-1.txt
```

### Authenticated Curl

```bash
scripts/openghost.sh exec-bash 'curl -s -i -H "Authorization: Bearer <TOKEN>" https://<target>/api/me'
```

### JSON Request

```bash
scripts/openghost.sh exec-bash 'curl -s -i -X POST -H "Content-Type: application/json" -H "Authorization: Bearer <TOKEN>" -d "{\"name\":\"test\"}" https://<target>/api/profile'
```

### Parallel-Safe Loops

Use conservative loops with clear bounds and rate limits:

```bash
scripts/openghost.sh exec-bash 'for p in /swagger.json /openapi.json /graphql; do echo -n "$p "; curl -s -o /dev/null -w "%{http_code}\n" https://<target>$p; done'
```

## When to Use Raw `exec-bash`

Use `exec-bash` for:

- curl loops
- custom one-off parsing
- chained utilities inside the sandbox
- tool options not covered by named wrappers

Avoid `exec-bash` for:

- destructive filesystem commands
- host operations
- unbounded loops
- unauthenticated brute force
- broad out-of-scope network scans
