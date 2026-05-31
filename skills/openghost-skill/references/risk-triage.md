# Risk Triage

Use this reference after findings are confirmed. The goal is to rank remediation work by verified impact, exploitability, asset value, and urgency instead of scanner severity alone.

## Inputs

For each confirmed finding, collect:

- affected asset and business function
- required attacker access: anonymous, authenticated, role, tenant, network position
- exploit reliability and user interaction
- data type and volume exposed or modified
- integrity, availability, financial, privacy, and compliance impact
- existing compensating controls: WAF, monitoring, approvals, rate limits, MFA, segmentation
- exploit maturity: no known exploit, private PoC, public PoC, or active exploitation
- remediation complexity and safe workaround options

## Triage Flow

1. Confirm the finding meets the evidence quality bar in `references/reporting.md`.
2. Assign CVSS consistently when the engagement requires it.
3. Adjust priority with business context: crown-jewel asset, tenant escape, admin reachability, payment impact, or sensitive data exposure.
4. Add urgency context: public exploit, active exploitation, CISA KEV listing, high EPSS, exposed internet surface, or easy automation.
5. Record the rationale with `openghost finding add --priority <P0-P4> --priority-rationale "<reason>"`.

## Priority Matrix

| Priority | Typical Conditions | Suggested SLA |
|---|---|---|
| P0 emergency | critical exploit on internet-facing app, active exploitation, full tenant/cloud/admin compromise | 24-48 hours |
| P1 urgent | high-impact confirmed flaw on sensitive asset, easy repeatability, no strong compensating control | 7 days |
| P2 high | confirmed high/medium severity flaw requiring auth or specific preconditions | 14-30 days |
| P3 normal | limited exposure, low exploitability, strong monitoring or compensating control | 30-90 days |
| P4 backlog | hardening issue, best-practice gap, or informational exposure without direct exploit path | planned cycle |

Do not downgrade a confirmed tenant escape, account takeover, privilege escalation, RCE, SQLi with data access, SSRF to cloud credentials, or payment integrity failure solely because it requires authentication.

## OWASP Risk Factors

Use these as narrative inputs when CVSS is too generic:

| Likelihood Factor | Questions |
|---|---|
| skill level | can a low-skill attacker repeat it with a browser or curl? |
| opportunity | is the endpoint internet-facing and reachable by many users? |
| ease of discovery | did normal crawling or docs reveal it? |
| ease of exploit | is the PoC reliable and scriptable? |
| detection | would logs, WAF, or alerts notice it? |

| Impact Factor | Questions |
|---|---|
| confidentiality | what data type and volume can be read? |
| integrity | what records, roles, balances, or workflows can be changed? |
| availability | can the issue degrade service without noisy DoS behavior? |
| accountability | can abuse be attributed and audited? |
| business | does it affect revenue, privacy, compliance, or trust? |

## SSVC-Style Decision Points

Use this compact decision model for remediation urgency:

- **Exploitation**: none, PoC, or active.
- **Technical impact**: partial or total control/data access.
- **Automatable**: one-off/manual or easily scripted.
- **Mission prevalence**: isolated feature, supporting workflow, or essential business workflow.
- **Public impact**: minimal, material, or safety/regulated-data concern.

Outcome guidance:

- `act` - immediate owner and deadline.
- `attend` - schedule in the current remediation cycle.
- `track*` - monitor with compensating control or planned fix.
- `track` - accept as informational or backlog after rationale.

## Reporting Language

Good:

```text
Priority P1 because any authenticated tenant user can export another tenant's invoices, the endpoint is internet-facing, exploitation is a single request, and the app stores regulated billing data.
```

Weak:

```text
High because the scanner says high.
```

Keep risk rationale short, evidence-backed, and tied to the affected business workflow.
