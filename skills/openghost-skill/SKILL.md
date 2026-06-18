---
name: openghost-skill
description: >-
  Agent skill for authorized web application and supporting server integrity
  penetration testing. Use for scoped OWASP WSTG and OWASP API Top 10
  assessments, authenticated web app pentests, API and browser validation,
  attack-surface mapping, ZAP-backed DAST, evidence-backed vulnerability
  validation, CVSS/risk triage, and report generation. Security tooling must run
  through the bundled `openghost` Docker sandbox launcher, with explicit
  authorization, scope, and evidence controls.
---

# OpenGhost

Use OpenGhost for structured, evidence-backed assessments of scoped web applications and supporting server surface. The agent reasons, automates, validates in a browser, and assembles reports; OpenGhost provides Docker-backed tool execution and engagement state.

## Runtime

- Require Docker, bash, and host `python3`.
- Run security tools only through `openghost`; never run offensive tooling directly on the host.
- If an installed skill already exposes `openghost`, use it directly.
- For a repo checkout, add both launchers:
  ```bash
  export PATH="$PWD/skills:$PWD/skills/openghost-skill:$PATH"
  ```
- For a copied standalone skill package, add only the skill directory containing `openghost` if needed.
- Keep generated operational data under `.openghost/`, normally uncommitted.

## Defender-First Full Capability

Act as a defender-first senior assessment operator. Use all available reasoning, automation, browser validation, sandboxed tooling, parsing/reporting scripts, and review capacity to maximize authorized defensive coverage. Use subagents or parallel review where harness policy allows.

Full capability does not relax safety boundaries. Every target, request, tool, payload, browser action, and report claim must remain inside written authorization, `OPENGHOST_SCOPE`, ROE, rate limits, test windows, account/data constraints, and destructive-testing allowances.

## Guardrails

1. Confirm written authorization and rules of engagement before active testing.
2. Define allowed hosts, ports, paths, accounts, exclusions, rate limits, test windows, emergency stop, and data handling before testing.
3. Set `OPENGHOST_SCOPE` and verify scope before each target, module, and tool run.
4. Read the relevant reference before testing a vulnerability class or workflow.
5. Use `references/cognitive-framework.md`: KNOW / THINK / TEST / VALIDATE.
6. Treat scanners, scripts, and autonomous assessment output as leads until manually validated.
7. Save exact evidence: requests, responses, tool output, screenshots, browser traces, timestamps, roles, and reproduction steps.
8. Do not fabricate findings; separate confirmed findings from likely or draft leads.
9. Prefer the smallest safe proof of impact; do not bulk extract data.
10. Avoid destructive, disruptive, high-volume, lockout, broad DoS, or production-impacting checks without explicit ROE approval.
11. Investigate safe vulnerability chains only when every step is in scope and evidence-backed.
12. Stop and ask when authorization, scope, credentials, or risk tolerance are ambiguous.

## Product Boundary

Do not use this skill for phishing, malware deployment, lateral movement, Active Directory compromise, wireless attacks, mobile app testing, physical intrusion, broad infrastructure testing unrelated to the scoped web target, or defensive SOC/DFIR workflows. Keep OpenGhost focused on authorized web application and supporting server integrity testing.

## Minimal Setup

```bash
openghost sandbox start
openghost engagement init --url <TARGET_URL> --name <name>
export OPENGHOST_SCOPE=.openghost/engagements/<name>/scope.yaml
```

Edit `.openghost/engagements/<name>/scope.yaml` before testing. Include authorized hosts, ports, accounts, roles, tenants, exclusions, rate limits, test windows, destructive allowances, emergency contacts, and notes.

OpenGhost records the active engagement in `.openghost/current`. Evidence, artifacts, findings, todos, reports, scripts, browser captures, ZAP output, and assessment runs live under `.openghost/engagements/<name>/`.

## Operating Loop

1. Scope: confirm authorization, target list, exclusions, credentials, ROE, and data handling.
2. Plan: identify objectives, crown jewels, critical workflows, threat scenarios, roles, tenants, and cleanup.
3. Map: enumerate hosts, server posture, technologies, APIs, endpoints, forms, JS routes, state changes, and trust boundaries.
4. Select: choose modules from the routing table and create todos.
5. Test: run sandboxed tools and browser automation against one hypothesis at a time.
6. Validate: reproduce manually, compare roles/tenants, minimize proof, and save evidence.
7. Score/report: assign severity, CVSS, remediation priority, and priority rationale; generate and review reports.
8. Cleanup: record test data, modified state, residual limitations, and stopped runtime.

## Module Routing

Read the module reference before running tests in that area.

| Condition | Reference |
|---|---|
| Always: scope, workflow, endpoint inventory | `references/workflow.md`, `references/modules/surface-map.md` |
| Server posture: TLS, headers, exposed files, DNS | `references/modules/server-integrity.md` |
| Login, cookies, JWT, OAuth/OIDC, SAML, API keys | `references/modules/session-auth.md`, `references/authenticated-testing.md` |
| Users, roles, tenants, object IDs, admin functions | `references/modules/access-control.md` |
| Params, forms, JSON/XML, uploads, parsers, URL fetchers | `references/modules/injection.md` |
| REST, OpenAPI, GraphQL, WebSocket, SOAP/XML, gRPC | `references/modules/api-protocols.md` |
| CORS, CSP, clickjacking, browser-only behavior | `references/modules/browser-policy.md`, `references/zap-playwright.md` |
| CDN, cache, proxy, WAF, host routing, HPP | `references/modules/http-edge.md` |
| Money, quotas, approvals, invites, entitlements, races | `references/modules/business-logic.md` |
| Evidence, findings, CVSS, priority, reports | `references/reporting.md`, `references/risk-triage.md` |

Use `references/module-map.md` for routing rules and completion criteria when module choice is unclear.

## Autonomous First Pass

After scope is reviewed, gather safe leads with:

```bash
openghost assess plan --target-url <TARGET_URL> --mode standard
openghost assess run --target-url <TARGET_URL> --confirm-scope-reviewed --mode standard
```

Use `safe` for minimal passive collection and `deep` only for authorized labs or explicit approval. Read `references/autonomous-assessment.md` before tuning modes, tokens, endpoint caps, request caps, or interpreting `assessment.json`. Autonomous assessment creates raw evidence, todos, and likely findings; it never creates confirmed findings.

## Evidence, CVSS, and Reporting

Register proof before saving confirmed findings:

```bash
openghost evidence add --path <file> --kind <kind> --title <title> --module <module>
openghost finding add --title <title> --severity <severity> --priority <P0-P4> \
  --module <module> --url <url> --evidence E-001 --confidence 95 \
  --cvss "CVSS:4.0/... (score X.X, CVSS-B)" \
  --priority-rationale "<severity plus business priority rationale>"
openghost report generate
```

Use CVSS v4.0 by default for new reports unless the engagement requires v3.1. When CVSS is used, include version, score, vector, and v4.0 nomenclature where applicable. CVSS is a severity input; remediation priority also depends on business criticality, exploitability, active exploitation, KEV/EPSS context, compensating controls, and urgency.

## Reference Routing

| Reference | Load When |
|---|---|
| `references/workflow.md` | Complete engagement workflow |
| `references/threat-modeling.md` | Objectives, crown jewels, attack paths, ROE, deconfliction, cleanup |
| `references/authenticated-testing.md` | Credentials, cookies, tokens, and multi-role testing |
| `references/cognitive-framework.md` | Hypotheses, tests, validation, and confidence |
| `references/autonomous-assessment.md` | `openghost assess` modes and generated leads |
| `references/tooling.md` | Launcher commands, sandbox tools, storage, templates |
| `references/zap-playwright.md` | ZAP, browser proxying, HAR/trace/screenshot capture, alerts |
| `references/reporting.md` | Evidence, findings, CVSS, final reports |
| `references/risk-triage.md` | Remediation priority beyond raw severity |
| `references/module-map.md` | Module selection and completion criteria |

## Finish Criteria

- Scope and ROE are documented.
- Selected modules were tested or explicitly skipped with reason.
- Confirmed findings have evidence IDs, reproduction steps, impact, remediation, severity, CVSS when applicable, priority, and priority rationale.
- Draft leads, limitations, cleanup state, and untested areas are recorded.
- Reports are generated and manually reviewed before delivery.
- Stop the sandbox when finished: `openghost sandbox stop`
