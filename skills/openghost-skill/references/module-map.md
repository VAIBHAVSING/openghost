# Module Map

This file defines how the OpenGhost central skill routes a web or server assessment into focused modules. The skill is self-contained; external repositories are context only and are not part of this skill's runtime or reference dependency chain.

## Modules

| Module | Purpose | Reference |
|---|---|---|
| `surface-map` | recon, scanning, crawling, endpoint/API discovery, OSINT within scope | `references/modules/surface-map.md` |
| `server-integrity` | TLS, headers, cookies, exposed files, management endpoints, DNS hygiene | `references/modules/server-integrity.md` |
| `session-auth` | login, JWT, OAuth/OIDC, SAML, sessions, CSRF, auth bypass | `references/modules/session-auth.md` |
| `access-control` | IDOR/BOLA, BFLA, BOPLA, mass assignment, open redirect, tenants | `references/modules/access-control.md` |
| `injection` | SQLi, XSS, SSRF, SSTI, XXE, NoSQLi, deserialization, traversal, pollution | `references/modules/injection.md` |
| `api-protocols` | REST, OpenAPI, GraphQL, WebSocket, SOAP/XML, gRPC | `references/modules/api-protocols.md` |
| `browser-policy` | CORS, CSP, clickjacking, browser headers, cookie policy | `references/modules/browser-policy.md` |
| `http-edge` | request smuggling, cache poisoning/deception, HPP, WAF/CDN bypass | `references/modules/http-edge.md` |
| `business-logic` | workflow bypass, payment/quantity abuse, race conditions, rate-limit abuse | `references/modules/business-logic.md` |
| `evidence-reporting` | evidence quality, severity, CVSS, report generation | `references/reporting.md` |

## Routing Rules

- Always run `surface-map`, `server-integrity`, and `evidence-reporting`.
- Add `session-auth` when login, JWT, OAuth/OIDC, SAML, API keys, cookies, or refresh tokens exist.
- Add `access-control` when multiple users, roles, tenants, object IDs, exports, downloads, or admin functions exist.
- Add `injection` when inputs reach parameters, bodies, headers, cookies, XML, templates, file parsers, URL fetchers, or upload flows.
- Add `api-protocols` when OpenAPI, REST, GraphQL, WebSocket, SOAP, XML, gRPC, mobile APIs, or shadow APIs appear.
- Add `browser-policy` when CORS, CSP, cookies, iframes, browser-only flows, DOM sinks, SPA behavior, Playwright validation, or ZAP proxy coverage matter.
- Add `http-edge` when CDN, cache, WAF, reverse proxy, host routing, HTTP/2 downgrade, or header normalization signals appear.
- Add `business-logic` when money, orders, quotas, credits, coupons, approvals, invites, subscriptions, entitlements, or one-time tokens exist.

## Priority Rules

| Signal | Priority |
|---|---|
| unauthenticated admin/API access | critical path |
| auth bypass, session forgery, token weakness | critical path |
| object IDs tied to sensitive data | high |
| URL fetcher/webhook/PDF generator | high |
| GraphQL or old API version | high |
| money or state-transition workflow | high |
| WAF/CDN/proxy mismatch | medium/high depending target |
| missing headers only | low unless chained |

## Completion Criteria

An assessment is complete when:

- scope is documented
- endpoint inventory exists
- modules selected by routing rules have been tested or explicitly skipped with reason
- all confirmed findings have registered evidence IDs, reproduction steps, impact, and remediation
- outstanding leads are documented as todos or report limitations
- final report is generated and manually reviewed
