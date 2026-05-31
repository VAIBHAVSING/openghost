# Threat Modeling and Engagement Planning

Use this reference before testing when objectives, business impact, or engagement safety need more structure than a URL and credential set.

## Planning Inputs

Record these in `scope.yaml`, `notes/threat-model.md`, or the final report:

- sponsor and authorization source
- emergency stop contact and stop phrase
- primary communication channel and expected check-in cadence
- allowed hosts, excluded hosts, excluded paths, and blackout windows
- allowed write actions, destructive actions, lockout tests, race tests, and active scans
- sensitive data handling: what may be viewed, copied, redacted, retained, and destroyed
- test accounts, roles, tenants, seeded data, and cleanup owner
- monitoring/deconfliction: SOC notification, source IPs, user agents, and test markers

Stop and clarify before testing if the target, authority, or permitted impact is ambiguous.

## Objectives and Crown Jewels

Define what the assessment must prove or disprove:

```markdown
| Objective | Crown Jewel | Likely Entry Points | Evidence Needed |
|---|---|---|---|
| Validate tenant isolation | tenant documents | /api/files, exports | user A reads user B denied |
| Validate checkout integrity | orders and payments | cart, coupon, webhook | price/quantity tamper rejected |
```

High-value web crown jewels commonly include PII, invoices, health data, payment flows, API keys, admin consoles, audit logs, exports, webhooks, and tenant-scoped files.

## Threat Scenarios

Select a small set of realistic scenarios instead of testing every class equally.

| Scenario | Useful Modules |
|---|---|
| anonymous attacker targets exposed app | `surface-map`, `server-integrity`, `injection`, `browser-policy` |
| authenticated user targets another user | `session-auth`, `access-control`, `api-protocols` |
| tenant user targets another tenant | `access-control`, `api-protocols`, `business-logic` |
| attacker abuses URL fetcher or webhook | `injection`, `api-protocols`, `http-edge` |
| attacker chains auth flaw to admin action | `session-auth`, `access-control`, `business-logic` |
| attacker poisons browser/cache behavior | `browser-policy`, `http-edge` |

Map each scenario to concrete tests, expected evidence, and a safety limit.

## Attack Path Notes

Track chains as hypotheses, not findings, until every step works:

```markdown
| Step | Hypothesis | Evidence | Status |
|---|---|---|---|
| 1 | open redirect accepts external URL | request/response | confirmed |
| 2 | OAuth redirect URI allows open redirect chain | auth transcript | likely |
| 3 | code reaches attacker callback | none | untested |
```

Do not continue a chain if the next step leaves scope, changes real customer data, or requires a permission not recorded in `scope.yaml`.

## Deconfliction and Cleanup

Before active scans, race tests, lockout tests, or state-changing PoCs:

1. Confirm the testing window and rate limit.
2. Use a clear marker such as `openghost-<date>-<finding>`.
3. Notify the approved contact if the rules of engagement require it.
4. Record affected test data and cleanup steps.
5. Add cleanup todos before running the test.

After testing, verify all created accounts, files, webhooks, coupons, roles, tokens, and test records are removed or handed off according to the data-handling plan.
