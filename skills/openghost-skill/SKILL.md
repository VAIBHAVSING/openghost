---
name: openghost-skill
description: >-
  Local open-source Agent Skill for authorized web application, API, browser,
  business-logic, and supporting server-integrity penetration testing. Use for
  scoped OWASP WSTG, ASVS, and API Security assessments; authenticated and
  multi-role validation; attack-surface mapping; bounded DAST; evidence-backed
  findings; coverage tracking; CVSS/risk triage; and delivery-ready reports.
  Do not use for phishing, malware, lateral movement, wireless, physical, or
  unrelated broad infrastructure testing. Run security tools only through the
  bundled Docker launcher with explicit authorization and scope controls.
---

# OpenGhost

Use OpenGhost for structured, evidence-backed assessments of scoped web applications and supporting server surface. The agent reasons, automates, validates in a browser, and assembles reports; OpenGhost provides Docker-backed tool execution and engagement state.

OpenGhost is fully local and open source. It has no hosted control plane, account, API key, telemetry requirement, or managed authentication service. Any optional credential is for the authorized target application only.

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

## Bounded Defensive Capability

Act as a senior defensive assessment operator. Escalate from passive inventory to bounded active validation only when the scope file explicitly enables the relevant test class.

Every target, request, tool, payload, browser action, and report claim must remain inside written authorization, `OPENGHOST_SCOPE`, ROE, rate limits, test windows, account/data constraints, and destructive-testing allowances.

## Guardrails

1. Confirm written authorization and rules of engagement before active testing.
2. Define allowed hosts, ports, paths, accounts, exclusions, rate limits, test windows, emergency stop, and data handling before testing.
3. Set `OPENGHOST_SCOPE`; require `authorization.reviewed: true`; verify scope before each target, module, and tool run.
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

```bash
openghost scope validate
```

OpenGhost records the active engagement in `.openghost/current`. Evidence, artifacts, findings, todos, reports, scripts, browser captures, ZAP output, and assessment runs live under `.openghost/engagements/<name>/`.

## Context and Cost Discipline

At the start of an engagement or after resuming, run:

```bash
openghost context show
```

Use this compact, content-addressed local snapshot before reading raw state. Load only the reference for the active test module and only the evidence needed for the current hypothesis. Do not repeatedly load complete reports, raw tool output, or every module reference. OpenGhost also reuses unchanged bundled script code and deterministic assessment output; use `--refresh` when freshness is more important than reuse. Authenticated assessment caching is disabled by default.

Read `references/caching.md` when changing cache TTLs, refreshing results, using target-authenticated caching, or reasoning about LLM context cost.

## Operating Loop

1. Authorize: confirm target list, exclusions, identities, ROE, test gates, emergency stop, and data handling.
2. Model: identify crown jewels, critical workflows, trust boundaries, attacker goals, roles, tenants, and likely abuse paths.
3. Inventory: map the anonymous and authenticated surface, APIs, browser behavior, state changes, dependencies, and edge infrastructure.
4. Select: choose only relevant modules and record each as `planned` coverage.
5. Validate: test one falsifiable hypothesis at a time with the smallest bounded proof and compare roles or tenants where relevant.
6. Preserve: register redacted evidence and verify its digest; keep automated signals as leads.
7. Close coverage: mark every selected module `tested`, `skipped`, or `not-applicable` with a reason.
8. Deliver: run `openghost report validate`, generate the final report, review it, clean up test state, and stop the sandbox.

Read `references/modern-workflow.md` for the complete phase gates and stopping rules.

## Module Routing

Read the module reference before running tests in that area.

| Condition | Reference |
|---|---|
| Always: scope, workflow, endpoint inventory | `references/modern-workflow.md`, `references/modules/module-surface-map.md` |
| Server posture: TLS, headers, exposed files, DNS | `references/modules/module-server-integrity.md` |
| Login, cookies, JWT, OAuth/OIDC, SAML, API keys | `references/modules/module-session-auth.md`, `references/authenticated-testing.md` |
| Users, roles, tenants, object IDs, admin functions | `references/modules/module-access-control.md` |
| Params, forms, JSON/XML, uploads, parsers, URL fetchers | `references/modules/module-injection.md` |
| REST, OpenAPI, GraphQL, WebSocket, SOAP/XML, gRPC | `references/modules/module-api-protocols.md` |
| CORS, CSP, clickjacking, browser-only behavior | `references/modules/module-browser-policy.md`, `references/zap-playwright.md` |
| CDN, cache, proxy, WAF, host routing, HPP | `references/modules/module-http-edge.md` |
| Money, quotas, approvals, invites, entitlements, races | `references/modules/module-business-logic.md` |
| Evidence, findings, CVSS, priority, reports | `references/reporting.md`, `references/risk-triage.md` |

Use `references/modules/module-map.md` for routing rules and completion criteria when module choice is unclear.

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
openghost evidence verify
openghost finding add --title <title> --severity <severity> --priority <P0-P4> \
  --module <module> --url <url> --evidence E-001 --confidence 95 \
  --cvss "CVSS:4.0/... (score X.X, CVSS-B)" \
  --priority-rationale "<severity plus business priority rationale>"
openghost coverage set --module <module> --status tested
openghost report validate
openghost report generate
```

Use CVSS v4.0 by default for new reports unless the engagement requires v3.1. When CVSS is used, include version, score, vector, and v4.0 nomenclature where applicable. CVSS is a severity input; remediation priority also depends on business criticality, exploitability, active exploitation, KEV/EPSS context, compensating controls, and urgency.

## Reference Routing

| Reference | Load When |
|---|---|
| `references/threat-modeling.md` | Objectives, crown jewels, attack paths, ROE, deconfliction, cleanup |
| `references/authenticated-testing.md` | Credentials, cookies, tokens, and multi-role testing |
| `references/cognitive-framework.md` | Hypotheses, tests, validation, and confidence |
| `references/autonomous-assessment.md` | `openghost assess` modes and generated leads |
| `references/caching.md` | Local script/result caches and compact agent context |
| `references/tooling.md` | Launcher commands, sandbox tools, storage, templates |
| `references/zap-playwright.md` | ZAP, browser proxying, HAR/trace/screenshot capture, alerts |
| `references/risk-triage.md` | Remediation priority beyond raw severity |

## Finish Criteria

- Scope and ROE are documented and `authorization.reviewed` is true.
- Selected modules were tested or explicitly skipped with reason.
- Confirmed findings have evidence IDs, reproduction steps, impact, remediation, severity, CVSS when applicable, priority, and priority rationale.
- Draft leads, limitations, cleanup state, and untested areas are recorded.
- Evidence integrity and the report quality gate pass; incomplete reports are visibly marked draft.
- Reports are generated and manually reviewed before delivery.
- Stop the sandbox when finished: `openghost sandbox stop`
