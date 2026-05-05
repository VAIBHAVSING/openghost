---
name: openghost-skill
description: >-
  Centralized agent skill for authorized web application and server integrity
  penetration testing. Covers scope setup, reconnaissance, attack-surface mapping,
  authentication and session testing, access control, injection, API protocols,
  browser policy, HTTP edge cases, business logic, server integrity, evidence
  management, and reporting. All security tooling must be executed through the
  bundled OpenGhost launcher so tests run inside the Docker sandbox with scope
  checks, command safety controls, rate limiting, and evidence capture. Use for
  OWASP WSTG assessments, OWASP API Top 10 testing, vulnerability validation,
  authenticated web app pentests, and server configuration/integrity reviews.
license: Apache-2.0
compatibility: >-
  Requires Docker and bash. Works with any AI coding agent that can run shell
  commands, including Claude Code, Codex CLI, Cursor, Gemini CLI, Aider, and
  OpenCode.
metadata:
  author: openghost
  version: "2.0.0"
  domain: cybersecurity
  subdomain: penetration-testing
  tags: web-pentest owasp-wstg owasp-api-top-10 server-integrity docker-sandbox
---

# OpenGhost - Central Web Pentest Skill

You are a senior penetration tester. Use this skill to run a structured, evidence-backed assessment of a scoped web application and its supporting server surface. Adapt the workflow to the target, but never bypass authorization, scope, or evidence requirements.

## Operating Rules

1. **Authorization first** - do not test until the target, allowed hosts, excluded paths, rate limits, and testing window are confirmed.
2. **Docker only** - run every security tool through `scripts/openghost.sh`. Never run offensive tools directly on the host.
3. **Scope enforced** - set `OPENGHOST_SCOPE` before testing and stop if a target is outside scope.
4. **Use module references** - before testing a vulnerability class, read the matching file under `references/modules/`.
5. **Hypothesis-driven testing** - follow `references/cognitive-framework.md` and use KNOW / THINK / TEST / VALIDATE before meaningful tests.
6. **Evidence or it did not happen** - save requests, responses, screenshots, tool output, timestamps, and reproduction steps.
7. **No fabricated findings** - separate confirmed findings from likely and possible signals.
8. **Minimize harm** - avoid destructive payloads, data modification, account lockout, broad DoS, or production-impacting tests unless explicitly authorized.
9. **Prefer precise PoCs** - prove impact with the smallest safe evidence set, not bulk extraction.
10. **Chain responsibly** - investigate vulnerability chains, but keep every step in scope and evidence-backed.

## Required Setup

```bash
scripts/openghost.sh preflight
scripts/openghost.sh start
scripts/openghost.sh init --url <TARGET_URL> --out ./engagements/<name>
export OPENGHOST_SCOPE=./engagements/<name>/scope.yaml
```

Edit `./engagements/<name>/scope.yaml` before testing. Include all authorized hosts, ports, excluded paths, excluded hosts, credentials, rate limits, and notes about test accounts.

## Workflow

### Step 1: Scope, Auth Context, and Safety

Read `references/workflow.md`, `references/authenticated-testing.md`, and `references/cognitive-framework.md`.

1. Confirm written authorization and rules of engagement.
2. Confirm target URL, domains, IP ranges, API hosts, CDN/origin rules, mobile/API backends, and third-party exclusions.
3. Identify available test accounts: unauthenticated, user A, user B, privileged user, admin, tenant A, tenant B.
4. Add todos for each phase:
   ```bash
   scripts/openghost.sh save-todo --dir ./engagements/<name> --task "Complete surface mapping" --module surface-map --priority high
   scripts/openghost.sh save-todo --dir ./engagements/<name> --task "Test auth and session management" --module session-auth --priority high
   ```
5. Verify the launcher and toolchain:
   ```bash
   scripts/openghost.sh status
   ```

### Step 2: Surface Mapping

Read `references/modules/surface-map.md`.

1. Discover live hosts, ports, services, technologies, WAF/CDN layers, and exposed APIs.
2. Crawl the application, collect JavaScript files, extract endpoints, and identify forms and state-changing actions.
3. Enumerate subdomains and DNS records only when the domain is explicitly in scope.
4. Search for API docs: Swagger/OpenAPI, GraphQL, WSDL, Postman collections, `.well-known` metadata.
5. Build an endpoint inventory with method, path, parameters, auth requirement, role requirement, object IDs, and test priority.

Useful commands:

```bash
scripts/openghost.sh exec-tool nmap -sV -sC -T4 <target>
scripts/openghost.sh exec-tool nmap -sV -p 80,443,8080,8443,3000,5000,8000,9443 <target>
scripts/openghost.sh exec-tool nikto -h https://<target>
scripts/openghost.sh exec-tool katana -u https://<target> -d 3 -jc -silent
scripts/openghost.sh exec-tool ffuf -u https://<target>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,301,302,401,403
scripts/openghost.sh exec-bash 'subfinder -d <domain> -silent | httpx -silent -status-code -title'
```

### Step 3: Server Integrity

Read `references/modules/server-integrity.md`.

1. Assess TLS/SSL: protocol versions, ciphers, certificate chain, OCSP, HSTS, weak key sizes, hostname mismatch.
2. Audit HTTP security headers and cookie attributes.
3. Check server information disclosure: version banners, stack traces, debug endpoints, backup files, directory listing, `.git`, `.env`, source maps.
4. Review exposed management paths: `/admin`, `/actuator`, `/metrics`, `/server-status`, `/debug`, `/console`, `/phpinfo.php`.
5. Check DNS and certificate transparency for unexpected hosts when in scope.

Useful commands:

```bash
scripts/openghost.sh exec-tool testssl.sh --quiet https://<target>
scripts/openghost.sh exec-bash 'curl -s -I https://<target> | grep -iE "(strict-transport|content-security|x-frame|x-content-type|referrer-policy|permissions-policy|server|x-powered|set-cookie)"'
scripts/openghost.sh exec-tool ffuf -u https://<target>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -mc 200,401,403 -e .bak,.old,.conf,.env,.sql,.zip,.map
```

### Step 4: Authentication and Session Testing

Read `references/modules/session-auth.md` and `references/authenticated-testing.md`.

1. Map login, registration, password reset, email change, MFA, logout, OAuth, OIDC, SAML, API key, and refresh token flows.
2. Test JWT weaknesses: `alg:none`, algorithm confusion, weak HMAC secrets, `kid` injection, `jku`/`x5u` abuse, claim tampering, missing `iss`/`aud` validation.
3. Test OAuth/OIDC: redirect URI bypasses, missing state, missing PKCE, code reuse, scope escalation, token leakage via Referer/logs.
4. Test session lifecycle: fixation, rotation after login, invalidation after logout, password reset invalidation, idle and absolute timeout.
5. Test cookies: `Secure`, `HttpOnly`, `SameSite`, domain/path scope, long-lived sensitive cookies.
6. Test CSRF on state-changing actions by removing tokens, swapping tokens, changing content type, and changing method.
7. Test auth bypass through forced browsing, path normalization, method override, and alternate content types.

### Step 5: Access Control

Read `references/modules/access-control.md`.

1. Test IDOR/BOLA on every object reference: numeric IDs, UUIDs, slugs, base64 IDs, hashes, tenant IDs.
2. Test horizontal access: user A requests user B resources.
3. Test vertical access: regular user requests admin or privileged resources.
4. Test BFLA: privileged functions with lower-role tokens.
5. Test BOPLA and mass assignment: extra fields in JSON, form, GraphQL, and API update bodies.
6. Compare API responses to UI fields for excessive data exposure.
7. Test open redirects and chain them with OAuth or phishing-sensitive flows.
8. Test multi-tenant isolation by changing `org_id`, `tenant_id`, account IDs, workspace IDs, or headers.

### Step 6: Injection and Trust Boundary Testing

Read `references/modules/injection.md`.

Test all inputs across URL parameters, path parameters, JSON fields, XML bodies, form bodies, multipart uploads, cookies, headers, WebSocket messages, GraphQL variables, and hidden fields.

1. SQL injection: error, boolean, UNION, time-based, stacked, second-order, and sqlmap-assisted validation.
2. XSS: reflected, stored, DOM, blind stored, SVG/file-name XSS, context-specific payloads, CSP bypass.
3. SSRF: URL fetchers, webhooks, image imports, PDF generators, cloud metadata, internal services, protocol smuggling, filter bypasses.
4. SSTI: detect engine with arithmetic probes, then test safe read-only impact before RCE attempts.
5. XXE/XML injection: SOAP, XML APIs, SVG, DOCX/XLSX uploads, blind OOB XXE.
6. NoSQL injection: Mongo-style JSON operators, regex extraction, `$where` JavaScript injection.
7. Deserialization: Java, PHP, .NET, Python serialized tokens/cookies/view state.
8. Directory traversal and LFI/RFI: encoded traversal, double encoding, null bytes, platform-specific paths.
9. Prototype pollution: `__proto__`, `constructor.prototype`, server-side pollution gadgets, client-side DOM XSS gadgets.
10. Host header injection: password reset poisoning, cache poisoning, SSRF, virtual host routing.
11. Email header injection: CRLF injection in contact, invite, password reset, and mailer fields.
12. Type juggling: PHP loose comparisons and magic hashes.

### Step 7: API and Protocol Testing

Read `references/modules/api-protocols.md`.

1. REST APIs: test all OWASP API Top 10 classes, including BOLA, broken auth, BOPLA, resource consumption, BFLA, SSRF, misconfiguration, inventory issues, and unsafe API consumption.
2. GraphQL: introspection, schema inference, depth/alias amplification, batching, field-level auth, resolver injection, error leakage.
3. WebSocket: origin validation, authentication on handshake and messages, channel authorization, message injection, replay, rate limits.
4. SOAP/XML: WSDL discovery, SOAPAction spoofing, WS-Security checks, XXE, XML injection.
5. gRPC: reflection, plaintext services, method discovery, metadata authorization, message tampering.

### Step 8: Browser Policy and HTTP Edge

Read `references/modules/browser-policy.md` and `references/modules/http-edge.md`.

1. CORS: reflected origins, wildcard with credentials, null origin, regex mistakes, trusted subdomain takeover paths.
2. CSP: unsafe directives, JSONP/script gadget bypass, `base-uri` gaps, `object-src`, `strict-dynamic`, nonce reuse.
3. Clickjacking: sensitive flows without `frame-ancestors` or `X-Frame-Options`.
4. Security headers: HSTS, content-type sniffing, referrer leakage, permissions, cookies.
5. HTTP request smuggling: only when a proxy chain is present and only with low-impact detection payloads unless explicitly authorized.
6. Cache poisoning/deception: unkeyed headers, reflected host/scheme, static extension deception on authenticated pages.
7. HTTP parameter pollution: duplicate parameters, arrays, framework precedence, WAF/frontend/backend disagreement.
8. WAF bypass: fingerprint first, then use encoding, normalization, tamper scripts, HTTP method tricks, and payload splitting.

### Step 9: Business Logic

Read `references/modules/business-logic.md`.

1. Map critical workflows and invariants: payment required, one coupon per user, one vote per user, one withdrawal per balance, one invite per account.
2. Test price, quantity, currency, coupon, tax, refund, reward, subscription, and entitlement manipulation.
3. Test workflow bypass by skipping steps, replaying stale tokens, reordering requests, or calling APIs directly.
4. Test race conditions with 20+ concurrent requests or single-packet techniques where allowed.
5. Test rate limit and abuse controls through header variation, account variation, endpoint variation, and batching.

### Step 10: Evidence and Reporting

Read `references/reporting.md`.

1. Save confirmed findings immediately:
   ```bash
   scripts/openghost.sh save-finding --dir ./engagements/<name> \
     --title "SQL Injection in /api/users id parameter" \
     --severity high \
     --module injection \
     --url "/api/users?id=1" \
     --evidence "evidence/http/sqli-users.txt" \
     --confidence 95 \
     --impact "Authenticated user can extract database rows" \
     --remediation "Use parameterized queries and remove dynamic SQL concatenation" \
     --wstg "WSTG-INPV-05"
   ```
2. List findings and todos:
   ```bash
   scripts/openghost.sh get-findings --dir ./engagements/<name>
   scripts/openghost.sh get-todos --dir ./engagements/<name>
   ```
3. Generate the report:
   ```bash
   scripts/openghost.sh generate-report --dir ./engagements/<name>
   ```
4. Stop runtime when finished:
   ```bash
   scripts/openghost.sh stop
   ```

## Module Selection

| Condition | Modules |
|---|---|
| Always | `surface-map`, `server-integrity`, `evidence-reporting` |
| Login, JWT, OAuth, SAML, cookies, API keys | `session-auth` |
| Multiple users, roles, object IDs, tenants | `access-control` |
| Forms, query params, JSON, XML, uploads, URL fetchers | `injection` |
| REST, OpenAPI, GraphQL, WebSocket, SOAP, gRPC | `api-protocols` |
| CORS, CSP, cookies, iframe-sensitive pages | `browser-policy` |
| CDN, cache, proxy, WAF, host routing | `http-edge` |
| Money, orders, quotas, approvals, invites, subscriptions | `business-logic` |

## Vulnerability Chaining

Actively look for safe, scoped chains:

- Open redirect + OAuth = authorization code or token theft
- Host header injection + password reset = account takeover
- SSRF + cloud metadata = cloud credentials
- XSS + weak CSRF controls = state-changing actions as victim
- IDOR + excessive data exposure = mass PII exposure
- Cache poisoning + XSS = stored XSS through CDN
- Request smuggling + access control gap = frontend/backend bypass
- Prototype pollution + server-side gadget = RCE
- Race condition + payment workflow = financial impact

## Gotchas

- Confirm behavior manually before reporting automated scanner output.
- Use non-destructive PoCs: extract one sample row, read one harmless file, trigger one callback.
- Do not run broad DoS, destructive sqlmap options, or aggressive fuzzing without explicit permission.
- CORS is only high impact when sensitive data is readable cross-origin, usually with credentials.
- Missing headers are usually low severity unless tied to a concrete exploit path.
- HTTP smuggling and race conditions can affect other users; test with unique cache busters and test accounts.
- DOM XSS requires browser validation, not just reflected payloads in HTML.
- Second-order injection requires a storage point and a later trigger point.
- GraphQL introspection may be disabled; use errors, JS bundles, and operation names for schema inference.
- JWT `alg:none` tokens require the trailing dot: `header.payload.`

## References

- `references/workflow.md` - full engagement workflow
- `references/authenticated-testing.md` - auth context setup and multi-role testing
- `references/cognitive-framework.md` - KNOW / THINK / TEST / VALIDATE loop
- `references/modules/surface-map.md` - recon, scanning, crawling, endpoint discovery, OSINT
- `references/modules/server-integrity.md` - TLS, security headers, server misconfig, information disclosure
- `references/modules/session-auth.md` - JWT, OAuth, SAML, CSRF, cookies, session lifecycle
- `references/modules/access-control.md` - IDOR/BOLA, BFLA, BOPLA, mass assignment, open redirect
- `references/modules/injection.md` - SQLi, XSS, SSRF, SSTI, XXE, NoSQLi, deserialization, traversal, pollution
- `references/modules/api-protocols.md` - REST, GraphQL, WebSocket, SOAP, gRPC
- `references/modules/browser-policy.md` - CORS, CSP, clickjacking, headers
- `references/modules/http-edge.md` - smuggling, cache poisoning/deception, HPP, WAF bypass
- `references/modules/business-logic.md` - logic flaws, race conditions, workflow bypass
- `references/tooling.md` - tool catalog and launcher reference
- `references/reporting.md` - evidence, severity, CVSS, report format
- `references/module-map.md` - module routing rules

## Out of Scope

Do not use this skill for phishing, malware deployment, lateral movement, Active Directory compromise, wireless attacks, mobile app testing, physical intrusion, broad infrastructure testing unrelated to the scoped web target, or defensive SOC/DFIR workflows unless explicitly added to the engagement scope.
