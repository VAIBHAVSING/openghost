# Engagement Workflow

Phase-by-phase workflow for a complete OpenGhost web application and server integrity assessment.

## Phase 0: Authorization and Scope

Mandatory before testing.

1. Confirm written authorization and rules of engagement.
2. Confirm allowed hosts, IPs, ports, APIs, credentials, exclusions, test window, rate limits, and production safety constraints.
3. Start runtime and create engagement:
   ```bash
   openghost sandbox status
   openghost sandbox start
   openghost engagement init --url <target> --name <name>
   export OPENGHOST_SCOPE=.openghost/engagements/<name>/scope.yaml
   ```
4. Edit `scope.yaml` before testing.
5. Create initial todos:
   ```bash
   openghost todo add --task "Validate scope and auth context" --module surface-map --priority high
   openghost todo add --task "Build endpoint inventory" --module surface-map --priority high
   ```

## Phase 1: Surface Mapping

Reference: `references/modules/surface-map.md`

1. Port scan web/app ports.
2. Run web server scanning.
3. Crawl application.
4. Directory and file brute-force.
5. Extract endpoints from JavaScript.
6. Discover API docs and shadow APIs.
7. Enumerate subdomains/DNS/CT only if in scope.
8. Fingerprint technology, CDN, WAF, and auth provider.

Output: host/service map, endpoint inventory, technology stack, discovered auth boundaries.

## Phase 2: Server Integrity

Reference: `references/modules/server-integrity.md`

1. TLS/SSL assessment.
2. Security headers and cookie audit.
3. Information disclosure and backup/config file checks.
4. Exposed management/debug endpoints.
5. DNS and certificate hygiene.

Output: configuration findings and hardening observations.

## Phase 3: Authentication and Session Analysis

References: `references/modules/session-auth.md`, `references/authenticated-testing.md`

1. Map login, registration, password reset, MFA, OAuth/OIDC, SAML, API key, logout, refresh flows.
2. Test JWT and token handling.
3. Test OAuth/OIDC and SAML implementation flaws.
4. Test cookie flags and session lifecycle.
5. Test CSRF and auth bypass patterns.

Output: auth mechanism assessment, token/session findings.

## Phase 4: Access Control

Reference: `references/modules/access-control.md`

1. Test IDOR/BOLA across all object references.
2. Test BFLA on admin/privileged functions.
3. Test BOPLA and mass assignment.
4. Test excessive data exposure.
5. Test multi-tenant isolation.
6. Test open redirects and forced browsing.

Output: authorization matrix and access control findings.

## Phase 5: Injection and Parser Abuse

Reference: `references/modules/injection.md`

1. SQLi, including second-order SQLi.
2. XSS: reflected, stored, DOM, blind stored.
3. SSRF, cloud metadata, internal services, protocol smuggling.
4. SSTI, XXE/XML, NoSQLi.
5. Deserialization, traversal, host/email header injection, prototype pollution, type juggling.

Save findings immediately when confidence reaches 90% or above.

## Phase 6: API and Protocol Testing

References: `references/modules/api-protocols.md`, `references/zap-playwright.md`

1. REST API testing against OWASP API Top 10.
2. GraphQL testing.
3. WebSocket testing.
4. SOAP/XML testing.
5. gRPC testing if discovered.
6. Import OpenAPI or GraphQL into ZAP for DAST coverage when specs or endpoints are in scope.

Output: protocol-specific findings and API inventory gaps.

## Phase 7: Browser Policy and HTTP Edge

References: `references/modules/browser-policy.md`, `references/modules/http-edge.md`, `references/zap-playwright.md`

1. CORS, CSP, clickjacking, headers, cookies.
2. Use Playwright through ZAP for browser-only behavior, SPA routes, authenticated flows, HAR/trace capture, and passive ZAP alerts.
3. Request smuggling/desync only if architecture and authorization support it.
4. Cache poisoning/deception when CDN/cache exists.
5. HPP, method override, host routing, WAF/CDN bypass.

Output: browser/edge findings with safe PoCs.

## Phase 8: Business Logic

Reference: `references/modules/business-logic.md`

1. Map workflows and invariants.
2. Test price, quantity, coupon, refund, plan, entitlement manipulation.
3. Test workflow step bypass and replay.
4. Test race conditions and rate-limit bypass safely.

Output: business-impact findings.

## Phase 9: Reporting and Cleanup

Reference: `references/reporting.md`

1. Review evidence quality.
2. Deduplicate findings.
3. Score severity and CVSS.
4. Record skipped areas and limitations.
5. Generate report:
   ```bash
   openghost report generate
   ```
6. Stop runtime:
   ```bash
   openghost sandbox stop
   ```
