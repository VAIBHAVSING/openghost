# Surface Map Module

Covers: scope-safe reconnaissance, host discovery, port scanning, web crawling, endpoint inventory, subdomain enumeration, DNS checks, certificate transparency, JavaScript mining, API discovery, shadow API discovery, technology fingerprinting, WAF/CDN detection, and vulnerability triage.

## Contents

- Goals and output artifacts
- Port/service and web-server scanning
- Subdomain, DNS, and certificate transparency
- Crawling, JavaScript mining, and API inventory
- Technology fingerprinting, endpoint inventory, and triage

## Execution Gate

Passive inventory does not authorize active discovery. Port scanning and content discovery require allowed hosts and ports, current test windows, request/rate caps, and the applicable `active_testing` gate. Exclude third-party infrastructure unless it is separately authorized.

## Goals

- Build a complete list of in-scope hosts, services, applications, APIs, parameters, authentication boundaries, and technologies.
- Identify high-value test paths before exploitation.
- Avoid noisy or out-of-scope enumeration.
- Produce an endpoint inventory that drives the rest of the assessment.

## Output Artifacts

Save direct proof with `openghost evidence add` and supporting inventories with `openghost artifact add`:

- `notes/surface-map.md` - hosts, technologies, endpoints, auth boundaries
- `openghost evidence add --kind tool-output --path nmap-*.txt --title "Port scan output"`
- `openghost evidence add --kind tool-output --path crawl-*.txt --title "Crawler output"`
- `openghost artifact add --kind inventory --path api-docs-*.json --title "API documentation"`
- `openghost artifact add --kind inventory --path endpoints.txt --title "Normalized endpoint list"`
- `openghost artifact add --kind inventory --path js-files.txt --title "JavaScript URL inventory"`

## Port and Service Scanning

### Host Discovery

Use this only for explicitly scoped hosts or IP ranges.

```bash
openghost run nmap -sn <target>
openghost run nmap -sn -PS22,80,443 <target>
```

### Web-Focused Port Scans

```bash
# Top ports with service and default scripts
openghost run nmap -sV -sC -T4 <target>

# Common web and app ports
openghost run nmap -sV -sC -p 80,443,8080,8443,3000,5000,5173,8000,8008,8081,9000,9443 <target>

# Full TCP port scan when authorized
openghost run nmap -sV -p- --min-rate 1000 <target>
```

### Web NSE Scripts

```bash
openghost run nmap --script http-title,http-headers,http-methods,http-enum -p 80,443 <target>
openghost run nmap --script vuln -p 80,443 <target>
```

Record service names, versions, redirects, HTTP methods, TLS-only services, and unexpected management interfaces.

## Web Server Scanning

### Nikto

```bash
openghost run nikto -h https://<target>
openghost run nikto -h https://<target> -Tuning 1234
```

Tuning notes:

- `1` - interesting files
- `2` - misconfiguration
- `3` - information disclosure
- `4` - injection checks

Do not report Nikto findings until manually validated.

## Subdomain Enumeration

Only enumerate domains explicitly included in scope.

```bash
# Passive subdomain discovery
openghost run subfinder -d <domain> -silent

# Probe discovered hosts
openghost bash 'subfinder -d <domain> -silent | httpx -silent -status-code -title -tech-detect'

# DNS brute force when authorized
openghost bash 'dnsx -d <domain> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -silent'
```

High-value subdomain keywords:

```text
admin, api, auth, beta, dev, staging, test, uat, internal, vpn, sso, idp, grafana, kibana, prometheus, jenkins, git, registry, old, legacy, backup
```

## DNS Enumeration

```bash
# Common DNS records
openghost bash 'for t in A AAAA CNAME MX TXT NS SOA; do echo "== $t =="; dig +short <domain> $t; done'

# Zone transfer check
openghost bash 'for ns in $(dig +short NS <domain>); do echo "== $ns =="; dig axfr <domain> @$ns; done'

# SPF/DMARC discovery for email-related attack surface
openghost bash 'dig +short TXT <domain>; dig +short TXT _dmarc.<domain>'
```

Zone transfer success is a confirmed finding if it exposes non-public hosts.

## Certificate Transparency

Use CT logs to identify forgotten subdomains and certificate issuance mistakes.

```bash
openghost bash 'curl -s "https://crt.sh/?q=%25.<domain>&output=json" | jq -r ".[ ].name_value" | tr "\n" "\n" | sort -u'
```

Validate discovered names with `httpx` before adding them to the live surface list. Do not test CT-discovered hosts unless they match scope.

## Web Crawling and Endpoint Discovery

### Crawling

```bash
openghost run katana -u https://<target> -d 3 -jc -silent
openghost run katana -u https://<target> -d 4 -jc -fx -silent
```

Use authenticated cookies where allowed:

```bash
openghost run katana -u https://<target> -H 'Cookie: session=<value>' -d 3 -jc -silent
```

### Directory and File Discovery

```bash
openghost run ffuf -u https://<target>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,301,302,401,403
openghost run ffuf -u https://<target>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,301,302,401,403
openghost run ffuf -u https://<target>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -mc 200,401,403 -e .bak,.old,.conf,.config,.env,.sql,.zip,.tar.gz,.map
```

High-value paths:

```text
/.git/config
/.env
/backup.zip
/debug
/actuator
/actuator/env
/metrics
/server-status
/phpinfo.php
/admin
/console
/graphql
/api-docs
/swagger.json
/openapi.json
```

## JavaScript Mining

Collect JavaScript URLs from crawl output and HTML source, then extract endpoints and secrets.

```bash
# Extract JS files from a page
openghost bash 'curl -s https://<target> | grep -oE "https?://[^\"'"'"']+\.js|/[A-Za-z0-9_./-]+\.js" | sort -u'

# Extract API-like paths from JS
openghost bash 'curl -s https://<target>/static/app.js | grep -oE "(/[A-Za-z0-9_.-]+){2,}" | sort -u'

# Search for possible secrets
openghost bash 'curl -s https://<target>/static/app.js | grep -iE "(api[_-]?key|secret|token|client[_-]?id|aws_|private|bearer|authorization)"'
```

Treat client-side secrets as leads. Validate whether they grant access before reporting.

## API Inventory and Shadow APIs

### Documentation Discovery

```bash
openghost bash 'for p in /swagger.json /openapi.json /api-docs /docs /redoc /v2/api-docs /swagger/v1/swagger.json /.well-known/openapi.yaml /.well-known/openid-configuration /graphql /graphiql /service?wsdl; do echo -n "$p: "; curl -s -o /dev/null -w "%{http_code}\n" https://<target>$p; done'
```

### Version Discovery

```bash
openghost bash 'for v in v1 v2 v3 v4 beta old legacy internal; do echo -n "/api/$v/: "; curl -s -o /dev/null -w "%{http_code}\n" https://<target>/api/$v/; done'
```

### Shadow API Indicators

- JavaScript references endpoints not present in API docs.
- Old API versions still respond.
- Mobile API hosts differ from web API hosts.
- Debug or internal endpoints return 401/403 instead of 404.
- API gateway routes differ from origin routes.
- GraphQL endpoint exists with introspection disabled but errors reveal types.

## Technology Fingerprinting

```bash
# Headers and redirects
openghost bash 'curl -s -I https://<target>'

# WAF/CDN fingerprint
openghost run wafw00f https://<target>

# HTTP probing with technology detection
openghost bash 'printf "https://<target>\n" | httpx -silent -status-code -title -tech-detect -cdn'
```

Record frameworks, programming languages, CDN, WAF, reverse proxy, app server, auth provider, analytics tags, and front-end framework.

## Endpoint Inventory Template

```markdown
| Method | Path | Params | Auth | Role | Object IDs | Source | Test Priority |
|---|---|---|---|---|---|---|---|
| GET | /api/users/{id} | id | Bearer | user | user id | JS | high |
| POST | /api/webhooks | url | Bearer | admin | none | OpenAPI | high |
```

Prioritize endpoints with:

- Object IDs
- File upload/import/export
- URL fetchers or webhooks
- Auth/session actions
- Payment/order/credit operations
- Admin/debug/internal paths
- JSON/XML parsers
- Search/filter/sort parameters

## Vulnerability Triage During Recon

Do not over-report recon signals. Use this bar:

- **Confirmed**: directly exploitable behavior with evidence.
- **Likely**: strong signal requiring validation.
- **Possible**: weak signal; create todo, do not report yet.

Examples:

- Exposed `/swagger.json` is usually informational unless it reveals sensitive endpoints or allows unauthorized API access.
- `/actuator/env` returning secrets is high/critical depending on data.
- `/.git/config` exposed is high if repository data can be downloaded.
- Version disclosure is low/info unless the version maps to a confirmed exploitable vulnerability.
