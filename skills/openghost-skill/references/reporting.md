# Reporting Reference

Use this reference to convert confirmed evidence into actionable, defensible findings.

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
10. **References** - OWASP WSTG/API Top 10/CWE/CVSS where applicable.

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

## CVSS Notes

Use CVSS 3.1 or 4.0 if required by the engagement. Be consistent.

Common CVSS 3.1 vectors:

```text
Unauthenticated SQLi with high confidentiality/integrity: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N
Stored XSS requiring victim interaction: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N
IDOR with sensitive data read: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
SSRF to cloud metadata: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N
```

Adjust metrics based on actual preconditions and impact.

## OWASP and CWE Mapping

Common mappings:

| Issue | OWASP | CWE |
|---|---|---|
| SQL injection | A03 Injection, WSTG-INPV-05 | CWE-89 |
| XSS | A03 Injection, WSTG-INPV-01 | CWE-79 |
| SSRF | A10 SSRF, WSTG-INPV-19 | CWE-918 |
| IDOR/BOLA | A01 Broken Access Control, API1 | CWE-639, CWE-862 |
| BFLA | API5 | CWE-862 |
| Mass assignment | API3/BOPLA | CWE-915 |
| CSRF | WSTG-SESS-05 | CWE-352 |
| XXE | A05 Security Misconfiguration | CWE-611 |
| Open redirect | WSTG-CLNT-04 | CWE-601 |
| Request smuggling | HTTP edge | CWE-444 |
| Race condition | business logic | CWE-362 |

## Finding Template

```markdown
## [SEVERITY] Title

**Asset:** https://target.example/path
**Module:** injection/access-control/session-auth/etc.
**Confidence:** 95%
**CVSS:** CVSS:3.1/...
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

### Remediation
Specific implementation guidance.

### References
- OWASP link or mapping
- CWE mapping
```

## Evidence Handling

- Add evidence through `openghost evidence add`; the helper copies the file into the v2 evidence store and records metadata in `state/evidence.json`.
- Use `--kind request`, `--kind response`, `--kind screenshot`, `--kind tool-output`, `--kind transcript`, or another precise kind.
- Link evidence to a finding with `--finding F-001` when the finding already exists, or add it unlinked first and reference the returned `E-###` from `finding add`.
- Use `openghost artifact add` for inventories, cookie jars, tool work files, scripts, browser captures, and packages that support the engagement but are not direct proof.
- Redact secrets, tokens, cookies, PII, and customer data.
- Keep enough original context to reproduce.
- Name source files descriptively before adding them: `idor-invoice-userb-response.txt`.

## Save Findings

```bash
openghost evidence add \
  --path /tmp/F-001-idor-invoice-response.txt \
  --kind response \
  --title "User A token reads user B invoice" \
  --module access-control \
  --url "/api/invoices/1005"

openghost finding add \
  --title "IDOR allows access to other users' invoices" \
  --severity high \
  --module access-control \
  --url "/api/invoices/1005" \
  --evidence E-001 \
  --confidence 95 \
  --step "Authenticate as user A with a standard test account." \
  --step "Request /api/invoices/1005, which belongs to user B." \
  --step "Observe that the response returns user B's invoice data." \
  --impact "Any authenticated user can download another user's invoice by changing the invoice ID" \
  --remediation "Enforce object-level authorization on every invoice read and download query" \
  --wstg "WSTG-ATHZ-04"
```

Use `--status draft` or `--status likely` for incomplete leads. Confirmed findings require severity, module, affected asset, confidence of 90 or higher, registered evidence, reproduction steps, impact, and remediation.

## Report Structure

```markdown
# Penetration Test Report

## Executive Summary
- Target, generated date, confirmed finding count, evidence count, artifact count, open testing items
- Finding count by severity
- Highest-impact chains

## Scope and Limitations
- Embedded `scope.yaml` excerpt
- Outstanding todos and draft/likely findings

## Methodology
- Modules tested
- Tools used
- Auth contexts used

## Report Quality Gate
- Confirmed findings have evidence, reproduction steps, impact, and remediation
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
openghost report generate
```

The generator writes both `reports/report-<timestamp>.md` and `reports/report-<timestamp>.json`, then records them in `state/reports.json`. Review generated reports manually before delivery.
