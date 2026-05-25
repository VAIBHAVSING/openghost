# Finding: <title>

**Severity:** <critical|high|medium|low|info>
**Status:** <confirmed|likely|draft|fixed|accepted-risk|false-positive>
**Confidence:** <90-100 for confirmed findings>
**CVSS:** <vector and score>
**Affected Asset:** <url, host, endpoint, parameter, object, or role>
**Module:** <surface-map|server-integrity|session-auth|access-control|injection|api-protocols|browser-policy|http-edge|business-logic>
**Role/Context:** <unauthenticated|user_a|user_b|admin|tenant_a|tenant_b>
**OWASP/CWE:** <mapping>

## Summary

<One-paragraph explanation of the vulnerable behavior and why it matters.>

## Affected Component

- Method: <GET|POST|PUT|PATCH|DELETE|N/A>
- Path: <path>
- Parameter/Object: <parameter or object ID>
- Required privileges: <required role>

## Evidence

| ID | Kind | Title | Path |
|---|---|---|---|
| E-001 | response | <title> | `evidence/F-001/response/E-001-...txt` |

## Reproduction

1. <step>
2. <step>
3. <step>

## Impact

<Business and security impact, including what an attacker can read, change, delete, bypass, or trigger.>

## Remediation

<Specific fix guidance. Include server-side controls, validation, authorization checks, safe parser configuration, or header configuration as applicable.>

## Retest Notes

<Original proof path, adjacent endpoints/variants to retest, and expected fixed behavior.>
