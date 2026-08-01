# Modern Web Penetration Testing Workflow

Use this workflow for web applications, APIs, browser trust boundaries, business logic, and the supporting server edge. It is risk-based and coverage-driven: scanners produce bounded signals, while evidence-backed human or agent validation determines findings.

## Contents

- Authorization gate
- Threat and abuse model
- Authenticated surface inventory
- Coverage selection
- Hypothesis-led validation
- Evidence and confidence
- Reporting and remediation
- Retest and closure
- Standards baseline

## Authorization gate

Do not send active test traffic until `scope.yaml` is complete and `authorization.reviewed: true`.

Record:

- authorization sponsor and document;
- test window, check-in channel, emergency contact, and stop phrase;
- allowed hosts, ports, paths, identities, roles, tenants, and source addresses;
- request and concurrency limits;
- excluded endpoints and prohibited actions;
- data access, proof, retention, redaction, cleanup, and out-of-band rules;
- individual active-test gates such as content discovery, reflected markers, active DAST, stateful fuzzing, races, lockout checks, and destructive tests.

Explicit command confirmation never substitutes for missing scope data.

## Threat and abuse model

Begin with the application rather than a generic vulnerability checklist.

1. Identify crown jewels and security-sensitive outcomes.
2. Map users, service identities, roles, tenants, trust zones, and external integrations.
3. Trace critical workflows such as authentication, recovery, invitations, approvals, purchases, payouts, exports, and administration.
4. Write abuse hypotheses in the form: actor + precondition + action + violated invariant + observable evidence.
5. Rank hypotheses by plausible impact, exposure, control uncertainty, and proof cost.

Use checklists and standards to check completeness after modeling, not as a substitute for modeling.

## Authenticated surface inventory

Map anonymous and authenticated surfaces separately. Use at least one low-privilege identity and the minimum additional role or tenant identities needed by the rules of engagement.

Record:

- routes, methods, parameters, content types, state changes, object identifiers, and error behavior;
- browser-only flows, client-side routes, storage, messaging, CSP/CORS, and third-party origins;
- REST, GraphQL, WebSocket, SOAP/XML, and gRPC operations where present;
- server, TLS, CDN, reverse-proxy, cache, WAF, DNS, and administrative exposure;
- authentication, token/session lifecycles, authorization decisions, and workflow invariants;
- externally visible dependency or build metadata that supports supply-chain hypotheses.

Do not treat a crawler or API specification as a complete inventory. Compare traffic across identities and workflows.

## Coverage selection

Choose modules based on observed surface and threat hypotheses. Record each selected module before testing:

```bash
openghost coverage set --module access-control --status planned
```

Use `references/modules/module-map.md` for routing. A module closes only as:

- `tested`: planned hypotheses were exercised with adequate evidence;
- `skipped`: relevant but not tested, with a reason and limitation;
- `not-applicable`: surface is absent, with the observation supporting that decision.

Use `partial` only during active work. It blocks a final report.

## Hypothesis-led validation

For each hypothesis:

1. State the expected security invariant.
2. Establish a control request or browser flow.
3. Change one meaningful variable: identity, role, tenant, object, state, method, encoding, origin, sequence, or timing.
4. Use the smallest request count and proof necessary.
5. Compare response and durable state, not status code alone.
6. Save exact evidence and note negative results.
7. Stop when the hypothesis is supported, falsified, unsafe to continue, or blocked by scope.

Escalate test intensity only through an enabled scope gate. Never infer permission for write actions, lockout, race amplification, active scanning, large dictionaries, bulk extraction, or destructive proof.

## Evidence and confidence

Register evidence immediately and classify its redaction state:

```bash
openghost evidence add --path <file> --kind http --title <title> \
  --module <module> --redaction redacted
openghost evidence verify
```

Automated output is a lead. A confirmed finding requires a registered evidence ID, affected asset, reproducible steps, impact, remediation, confidence of at least 90, priority, and priority rationale.

Use `openghost context show` when resuming. Read raw evidence only for the active hypothesis; this reduces repeated context use and accidental exposure of unrelated data.

## Reporting and remediation

Separate four concepts:

- technical severity;
- exploitability and preconditions;
- business remediation priority;
- assessment coverage and limitations.

Run the quality gate before generating a delivery report:

```bash
openghost report validate
openghost report generate
```

The final gate checks scope review, coverage closure, evidence integrity, finding completeness, and high-priority open work. Use `--allow-incomplete` only to create a visibly marked draft.

Group remediation by root cause and control owner. Give concrete fixes, compensating controls, validation advice, and the affected finding IDs. Do not imply that an untested area is secure.

## Retest and closure

For each remediated finding, repeat the original proof and a nearby regression case. Preserve retest evidence, update the finding status, and record residual risk.

Before closure:

- remove test data and sessions as authorized;
- document anything that could not be cleaned up;
- close or disposition all todos;
- close every selected coverage module;
- verify evidence integrity;
- review the generated report manually;
- stop the sandbox.

## Standards baseline

Use current stable standards as coverage aids:

- OWASP Web Security Testing Guide v4.2 with versioned `WSTG-v42-*` identifiers;
- OWASP Application Security Verification Standard 5.0.0 for verifiable control requirements;
- OWASP API Security Top 10 2023 for API-specific risk themes;
- OWASP Top 10:2025 for broad awareness, including supply-chain and exceptional-condition risks;
- CVSS v4.0 for technical severity when the engagement requires scoring.

Standards mappings support traceability. They do not replace evidence, application-specific abuse cases, or explicit coverage records.
