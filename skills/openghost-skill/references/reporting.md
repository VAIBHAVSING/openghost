# Reporting Reference

Use this reference to convert confirmed evidence into actionable, defensible findings.

## Contents

- Finding Quality Bar
- Do Not Report As Confirmed
- Evidence Standards
- Severity Guidelines
- CVSS Guidance
- OWASP, ASVS, WSTG, and CWE Mapping
- Finding Template
- Evidence Handling
- Save Findings
- Report Structure
- Report Generation

## Finding Quality Bar

Every finding must include:

1. **Title** - specific and concise, including location and issue type.
2. **Severity** - Critical, High, Medium, Low, or Info with rationale.
3. **Confidence** - 90-100 for confirmed findings.
4. **Affected asset** - host, path, method, parameter, role, tenant, or object.
5. **Evidence** - registered `E-###` records for exact HTTP request/response, tool output, browser screenshot, or transcript.
6. **Reproduction steps** - `--step` entries that are numbered, repeatable, and safe for test accounts.
7. **Impact** - what an attacker can do, in business terms.
8. **Exploitability conditions** - required role, auth, network position, user interaction, timing.
9. **Remediation** - specific fixes, not generic advice.
10. **CVSS when used** - version, score, vector, and v4.0 nomenclature where applicable.
11. **Priority** - P0-P4 remediation priority.
12. **Priority rationale** - CVSS plus business context, exploitability, asset criticality, and urgency signals when applicable.
13. **References** - versioned OWASP WSTG, ASVS 5.0.0, API Top 10, CWE, and CVSS mappings where applicable.

## Do Not Report As Confirmed

- scanner output without manual validation
- missing best-practice header without impact
- exposed docs without sensitive data or auth gap
- 403/401 endpoints with no bypass
- speculative chains without a working PoC
- version disclosure without reachable vulnerable behavior

## Evidence Standards

| Finding Type | Required Evidence |
|---|---|
| SQLi | true/false or time proof, isolated parameter, optional redacted sample data |
| XSS | browser execution screenshot or DOM evidence, exact payload and context |
| SSRF | callback proof or safe internal/cloud metadata proof |
| IDOR/BOLA | user A token accessing user B object |
| BFLA | low-privilege token executing privileged function |
| Mass assignment | request with injected field and resulting changed state |
| CORS | malicious origin reading sensitive authenticated response |
| CSRF | cross-site PoC causes state change |
| Race condition | concurrent requests produce more successes than allowed |
| Cache poisoning | poisoned response served from cache to clean request |
| TLS/header issue | exact header/config output and impact rationale |

## Severity Guidelines

| Severity | CVSS Range | Examples |
|---|---:|---|
| Critical | 9.0-10.0 | RCE, full auth bypass to admin, full DB extraction, cloud credential theft, tenant-wide compromise |
| High | 7.0-8.9 | SQLi with data access, stored XSS affecting admin, SSRF to internal/cloud metadata, IDOR exposing sensitive data, privilege escalation |
| Medium | 4.0-6.9 | reflected XSS, CSRF on sensitive action, limited data exposure, open redirect with meaningful chain, weak TLS on sensitive app |
| Low | 0.1-3.9 | missing cookie flag with limited impact, version disclosure, clickjacking on low-risk page, directory listing without sensitive files |
| Info | 0.0 | hardening recommendation, documentation exposure without sensitive impact |

## CVSS Guidance

Use CVSS v4.0 for new reports unless the engagement rules, client template, or
upstream intake process requires CVSS v3.1. Keep CVSS support docs-only: record
the value in the existing free-text `--cvss "<score and vector>"` field, and do
not assume OpenGhost calculates or validates vectors.

Whenever CVSS is used, include both the numeric score and the vector string. For
CVSS v4.0, also label the score with the metric-group nomenclature so readers
know whether the score is Base-only or includes Threat and Environmental data.

CVSS is a standardized severity input, not the whole remediation decision. Use
`references/risk-triage.md` when CVSS alone under- or over-states priority.
Common adjustments include crown-jewel exposure, tenant escape, payment
integrity, public exploit availability, active exploitation, KEV/EPSS context,
and strong compensating controls.

CVSS v4.0 nomenclature examples:

```text
Base only: CVSS:4.0/<base metrics> (score X.X, CVSS-B)
Base + Threat: CVSS:4.0/<base metrics>/<threat metrics> (score X.X, CVSS-BT)
Base + Environmental: CVSS:4.0/<base metrics>/<environmental metrics> (score X.X, CVSS-BE)
Base + Threat + Environmental: CVSS:4.0/<base metrics>/<threat metrics>/<environmental metrics> (score X.X, CVSS-BTE)
```

Common CVSS v4.0 base-vector starters:

```text
Unauthenticated network flaw with high vulnerable-system confidentiality and integrity impact:
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N (score X.X, CVSS-B)

Authenticated sensitive data exposure with no subsequent-system impact:
CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N (score X.X, CVSS-B)
```

Common CVSS v3.1 vectors for clients that still require v3.1:

```text
Unauthenticated SQLi with high confidentiality/integrity: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
Stored XSS requiring victim interaction: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N
IDOR with sensitive data read: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
SSRF to cloud metadata: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N
```

Adjust metrics based on actual preconditions and impact.

Primary references:

- FIRST CVSS v4.0 Specification Document: https://www.first.org/cvss/specification-document
- FIRST CVSS v4.0 User Guide: https://www.first.org/cvss/v4.0/user-guide

## OWASP, ASVS, WSTG, and CWE Mapping

Common mappings:

| Issue | OWASP | CWE |
|---|---|---|
| SQL injection | A05:2025 Injection, WSTG-v42-INPV-05 | CWE-89 |
| XSS | A05:2025 Injection, WSTG-v42-INPV-01 | CWE-79 |
| SSRF | WSTG-v42-INPV-19 | CWE-918 |
| IDOR/BOLA | A01:2025 Broken Access Control, API1:2023 | CWE-639, CWE-862 |
| BFLA | API5:2023 | CWE-862 |
| Mass assignment | API3:2023/BOPLA | CWE-915 |
| CSRF | WSTG-v42-SESS-05 | CWE-352 |
| XXE | A05:2025 Injection | CWE-611 |
| Open redirect | WSTG-v42-CLNT-04 | CWE-601 |
| Request smuggling | HTTP edge | CWE-444 |
| Race condition | business logic | CWE-362 |

## Finding Template

```markdown
## [SEVERITY] Title

**Asset:** https://target.example/path
**Module:** injection/access-control/session-auth/etc.
**Confidence:** 95%
**CVSS:** CVSS:4.0/... (score X.X, CVSS-B)
**Priority:** P1 - <short rationale>
**OWASP/CWE:** OWASP A01, CWE-862

### Summary
One-paragraph explanation of the vulnerability.

### Affected Endpoint
- Method: GET
- Path: /api/users/{id}
- Parameter/Object: id
- Required role: authenticated user

### Evidence
```http
<redacted request>
```

```http
<redacted response>
```

### Reproduction Steps
1. Authenticate as user A.
2. Send the request below for user B's object.
3. Observe user B data in the response.

### Impact
Explain what an attacker can read, change, delete, or trigger.

### Priority Rationale
Explain exploitability, affected business function, asset criticality, and urgency.

### Remediation
Specific implementation guidance.

### References
- OWASP link or mapping
- CWE mapping
```

## Evidence Handling

- Add evidence through `openghost evidence add`; the helper copies the file into the v2 evidence store and records SHA-256, size, media type, capture time, and redaction state in `state/evidence.json`.
- Use `--kind request`, `--kind response`, `--kind screenshot`, `--kind tool-output`, `--kind transcript`, or another precise kind.
- Link evidence to a finding with `--finding F-001` when the finding already exists, or add it unlinked first and reference the returned `E-###` from `finding add`.
- Use `openghost artifact add` for inventories, cookie jars, tool work files, scripts, browser captures, and packages that support the engagement but are not direct proof.
- Redact secrets, tokens, cookies, PII, and customer data.
- Mark each record `--redaction raw`, `redacted`, or `sanitized`, then run `openghost evidence verify` before delivery.
- Keep enough original context to reproduce.
- Name source files descriptively before adding them: `idor-invoice-userb-response.txt`.

## Save Findings

```bash
openghost evidence add \
  --path /tmp/F-001-idor-invoice-response.txt \
  --kind response \
  --title "User A token reads user B invoice" \
  --module access-control \
  --redaction redacted \
  --url "/api/invoices/1005"

openghost finding add \
  --title "IDOR allows access to other users' invoices" \
  --severity high \
  --priority P1 \
  --module access-control \
  --url "/api/invoices/1005" \
  --evidence E-001 \
  --confidence 95 \
  --step "Authenticate as user A with a standard test account." \
  --step "Request /api/invoices/1005, which belongs to user B." \
  --step "Observe that the response returns user B's invoice data." \
  --impact "Any authenticated user can download another user's invoice by changing the invoice ID" \
  --cvss "CVSS:4.0/... (score X.X, CVSS-B)" \
  --priority-rationale "P1 because exploitation is a single authenticated request against sensitive billing data" \
  --remediation "Enforce object-level authorization on every invoice read and download query" \
  --wstg "WSTG-v42-ATHZ-04" \
  --asvs "ASVS-5.0.0-V8"
```

Use `--status draft` or `--status likely` for incomplete leads. Confirmed findings require severity, module, affected asset, confidence of 90 or higher, registered evidence, reproduction steps, impact, remediation, priority, and priority rationale.
Add priority rationale from `references/risk-triage.md` when findings will drive remediation sequencing.

## Report Structure

```markdown
# Penetration Test Report

## Executive Summary
- Target, generated date, confirmed finding count, evidence count, artifact count, open testing items
- Finding count by severity
- Top remediation priorities and rationale
- Highest-impact chains

## Scope and Limitations
- Embedded `scope.yaml` excerpt
- Objectives, crown jewels, test window, emergency stop, and data-handling constraints
- Outstanding todos and draft/likely findings

## Methodology
- Modules tested
- Tools used
- Auth contexts used

## Report Quality Gate
- Confirmed findings have evidence, reproduction steps, impact, remediation, priority, and priority rationale
- CVSS values, when present, include version, score, vector, and v4.0 nomenclature where applicable
- Any incomplete confirmed finding is listed before delivery

## Findings
Sorted by severity, then exploitability.

## Positive Security Observations
Controls that worked well.

## Appendix
- Endpoint inventory
- Tool versions
- Evidence index
```

## Report Generation

```bash
openghost evidence verify
openghost coverage list
openghost report validate
openghost report generate
```

The final quality gate checks explicit scope review, closed module coverage, evidence integrity, complete confirmed findings, and unresolved high-priority testing work. The generator writes both `reports/report-<timestamp>.md` and `reports/report-<timestamp>.json`, then records them in `state/reports.json`.

If work is intentionally incomplete, use `openghost report generate --allow-incomplete`. The output is visibly marked `DRAFT - INCOMPLETE`; do not deliver it as a final report. Review every generated report manually.
