# Server Integrity Module

Covers: TLS/SSL assessment, certificate validation, HTTP security headers, cookie attributes, server information disclosure, exposed management endpoints, backup/config leaks, DNS hygiene, default credentials, and application/platform configuration risks.

## Goals

- Identify server and deployment weaknesses that increase exploitability or expose sensitive data.
- Validate configuration issues with concrete impact.
- Separate best-practice hardening gaps from exploitable findings.

## TLS and Certificate Assessment

### testssl.sh

```bash
openghost run testssl.sh --quiet --color 0 https://<target>
openghost run testssl.sh --fast --color 0 https://<target>
```

Check for:

- SSLv2, SSLv3, TLS 1.0, TLS 1.1 enabled
- Weak ciphers: NULL, EXPORT, RC4, DES, 3DES, anonymous DH
- Weak key exchange: small DH params, weak ECDH curves
- Certificate chain errors, expired certificate, wrong hostname, self-signed cert
- Missing OCSP stapling when required by policy
- HSTS missing, low `max-age`, missing `includeSubDomains`, preload issues
- Known issues: Heartbleed, ROBOT, BEAST, POODLE, CRIME, BREACH indicators

### Manual Certificate Checks

```bash
openghost bash 'openssl s_client -connect <target>:443 -servername <target> </dev/null 2>/dev/null | openssl x509 -noout -text'
openghost bash 'openssl s_client -connect <target>:443 -servername <target> -tls1_2 </dev/null'
```

Report TLS findings based on exploitability and policy. Missing preload alone is usually low/info. Expired certificates or plaintext downgrade paths can be higher.

## Security Headers

```bash
openghost bash 'curl -s -I https://<target> | grep -iE "(strict-transport|content-security|x-frame|x-content-type|referrer-policy|permissions-policy|cross-origin|set-cookie|server|x-powered)"'
```

Expected baseline:

| Header | Expected | Risk |
|---|---|---|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` | SSL stripping, downgrade |
| `Content-Security-Policy` | restrictive `default-src`, `script-src`, `object-src 'none'`, `base-uri 'none'` | XSS blast radius |
| `X-Frame-Options` or `frame-ancestors` | `DENY`, `SAMEORIGIN`, or CSP frame policy | clickjacking |
| `X-Content-Type-Options` | `nosniff` | MIME sniffing |
| `Referrer-Policy` | `strict-origin-when-cross-origin` or stricter | URL/token leakage |
| `Permissions-Policy` | restrict camera, mic, geolocation, payment | browser feature abuse |
| `Cross-Origin-Opener-Policy` | `same-origin` for sensitive apps | cross-origin isolation issues |
| `Cross-Origin-Resource-Policy` | `same-origin` or `same-site` where applicable | resource leakage |
| `Server`, `X-Powered-By` | absent or generic | version disclosure |

Missing headers are usually low severity unless chained to a concrete exploit path.

## Cookie Integrity

```bash
openghost bash 'curl -s -I https://<target>/login | grep -i set-cookie'
```

Check every sensitive cookie:

- `Secure` present for HTTPS-only cookies
- `HttpOnly` present for session tokens
- `SameSite=Lax` or `Strict` for session cookies; `None` must include `Secure`
- Domain is not overly broad (`.example.com` can expose cookies to subdomain takeover)
- Path is restricted where possible
- Expiration is reasonable
- Session changes on login, privilege change, MFA, password reset

## Information Disclosure

### Headers and Errors

```bash
openghost bash 'curl -s -i https://<target>/does-not-exist-$(date +%s) | head -80'
openghost bash 'curl -s -i https://<target>/?debug=true | head -80'
```

Look for:

- Stack traces
- SQL errors
- Internal paths
- Framework versions
- Debug mode
- Cloud metadata in responses
- Source code snippets
- Internal hostnames or IPs

### Sensitive Files

```bash
openghost run ffuf -u https://<target>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -mc 200,401,403 -e .bak,.old,.conf,.config,.env,.sql,.zip,.tar,.tar.gz,.7z,.map,.log
```

High-risk files:

```text
.env
.git/config
.git/HEAD
config.php
settings.py
web.config
appsettings.json
application.yml
database.yml
composer.lock
package-lock.json
backup.sql
dump.sql
id_rsa
*.pem
*.key
*.map
```

Evidence threshold:

- File exists but access denied: create todo, not finding unless it reveals path policy issue.
- File readable and contains secrets: confirmed high/critical depending on secret power.
- Source maps readable: validate whether they reveal endpoints/secrets/source before reporting.

## Management and Debug Interfaces

```bash
openghost bash 'for p in /admin /console /debug /metrics /server-status /actuator /actuator/env /actuator/heapdump /phpinfo.php /_profiler /wp-admin /manager/html; do echo -n "$p "; curl -s -o /dev/null -w "%{http_code}\n" https://<target>$p; done'
```

Prioritize:

- Spring Boot Actuator exposed without auth
- Prometheus/Grafana/Kibana dashboards
- Jenkins/GitLab/registry panels
- Tomcat manager
- phpMyAdmin/Adminer
- cloud metadata/proxy dashboards
- debug profilers

Test default credentials only where authorized and rate-limited.

## Default Credentials

Only test known default credentials for identified software and only with safe rate limits.

Common examples:

```text
admin:admin
admin:password
admin:<blank>
tomcat:tomcat
jenkins:jenkins
grafana:admin
```

Do not run credential stuffing or large password attacks unless explicitly authorized.

## DNS and Email-Related Integrity

```bash
openghost bash 'for t in A AAAA CNAME MX TXT NS SOA CAA; do echo "== $t =="; dig +short <domain> $t; done'
openghost bash 'dig +short TXT _dmarc.<domain>; dig +short TXT <domain>'
```

Review:

- Zone transfer (`AXFR`) exposure
- Dangling CNAMEs that can lead to subdomain takeover
- Missing CAA where policy requires it
- SPF overly permissive (`+all`, broad includes)
- Missing DMARC or `p=none` for sensitive domains

Email posture is usually supporting context unless the engagement includes phishing resistance or account takeover chains.

## Container and Dependency Exposure

If source, container images, or package manifests are in scope:

```bash
openghost bash 'grep -R "FROM\|image:" -n . 2>/dev/null | head'
openghost bash 'find . -name package.json -o -name requirements.txt -o -name pom.xml -o -name go.mod 2>/dev/null | head'
```

Validate dependency issues only when the vulnerable component is reachable in the deployed application.

## Severity Guidance

| Issue | Typical Severity | Raise Severity When |
|---|---|---|
| Missing security header | Info/Low | Enables confirmed XSS/clickjacking/leakage |
| Version disclosure | Info/Low | Version has confirmed reachable exploit |
| Weak TLS protocol | Low/Medium | Sensitive app, compliance requirement, downgrade path |
| Expired/wrong certificate | Medium | Blocks users or enables MITM in practical context |
| Exposed `.env` or secrets | High/Critical | Secrets grant production/cloud/admin access |
| Exposed management panel | Medium | Default creds/auth bypass confirmed -> High/Critical |
| Exposed Actuator/env/heapdump | High/Critical | Secrets or memory data exposed |
| Zone transfer | Medium/High | Reveals internal hosts or sensitive records |

## Reporting Checklist

- Exact URL or host and port
- HTTP request/response or tool output
- Redacted sensitive data sample
- Impact path: what the disclosure or misconfig enables
- Safe reproduction steps
- Specific remediation: config key/header/certificate/tool version
