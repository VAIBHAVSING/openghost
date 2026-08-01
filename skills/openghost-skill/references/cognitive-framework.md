# Cognitive Framework

Use this reasoning loop before meaningful pentest actions. The goal is to keep testing deliberate, scoped, evidence-backed, and adaptive.

## Contents

- KNOW / THINK / TEST / VALIDATE
- Strong hypotheses and confidence
- Direct-first and batch gates
- Constraint typing and evidence thresholds
- Truthfulness and safe-impact rules

## KNOW / THINK / TEST / VALIDATE

Before each tool call or manual test:

1. **KNOW** - confirmed observations, scope constraints, auth context, current evidence.
2. **THINK** - specific hypothesis with confidence from 0-100%.
3. **TEST** - minimal safe action that confirms or refutes the hypothesis.
4. **VALIDATE** - expected outcome and interpretation rules.

Pattern:

```text
Observation: <fact>.
Hypothesis: <specific vulnerability/behavior>. Confidence: <N>%.
Test: <minimal action>.
Expected: <confirming evidence> / <refuting evidence>.
```

## Strong Hypotheses

Weak:

```text
SQLi might work.
```

Strong:

```text
The `id` parameter on GET /api/orders/{id} is likely SQL-backed because invalid numeric input returns a PostgreSQL cast error. Confidence 70%. Test boolean probes with safe true/false conditions and compare status/length.
```

Weak:

```text
There might be IDOR.
```

Strong:

```text
GET /api/invoices/{id} returns invoice 1004 for user A. User B has invoice 1005. Hypothesis: object-level authorization is missing. Confidence 65%. Test user A token against user B invoice ID and compare response.
```

## Confidence Scale

| Confidence | Classification | Action |
|---:|---|---|
| 0-29% | Signal | Gather more data or deprioritize |
| 30-49% | Weak lead | One focused test, then pivot if weak |
| 50-69% | Likely | Validate manually |
| 70-89% | High confidence | Produce safe PoC |
| 90-100% | Confirmed | Register evidence and save finding with reproduction steps |

## Confidence Updates

- Confirming evidence: +20%
- Strong refutation: -30%
- Ambiguous result: -10%
- Three failed attempts with same technique: switch technique
- Five failed attempts in same class: switch module or return later

Always explain updates:

```text
Confidence was 70%. User B token correctly received 403 for User A invoice. 70 - 30 = 40%. Pivot from IDOR on invoices to BFLA on export endpoints.
```

## Direct-First Principle

Take the shortest safe path to proving impact.

| Discovery | Direct Test | Avoid First |
|---|---|---|
| SQL error | Boolean/time probe on same parameter | Full database enumeration |
| Possible IDOR | Replay with second test account | Brute-force IDs broadly |
| SSRF callback | Cloud metadata root or localhost harmless port | Internal network sweep |
| XSS reflection | Browser execution with harmless alert/marker | Cookie theft payload |
| File read | Read harmless known file | Recursive sensitive file dumping |
| Admin endpoint | Test regular token vs endpoint | Credential guessing |

## Batch Gate

Before a tool call, ask whether tests are independent.

- Independent tests: batch them safely.
- Dependent tests: run sequentially.
- High-risk tests: isolate and run one at a time.

Good batching:

```text
Check common API doc paths with curl loop.
```

Bad batching:

```text
Run sqlmap, ffuf, nuclei, and race tests simultaneously against production.
```

## Constraint Typing

When a technique fails, classify the constraint and pivot deliberately.

| Constraint | Meaning | Pivot |
|---|---|---|
| syntax | payload rejected by parser | encode or change format |
| processing | input accepted but not interpreted | find different sink |
| filter | pattern blocked | map allowed characters, bypass filter |
| auth | not enough privilege | try lower-risk access control tests |
| rate-limit | request blocked by limits | slow down, use approved lower rate |
| cache | stale or shared response | use cache buster, validate cache key |
| browser | curl cannot reproduce | use browser automation |
| second-order | payload stored but not triggered | find render/export/admin trigger |

## Evidence Thresholds

| Finding Type | Minimum Confirmation |
|---|---|
| SQLi | true/false or time delta plus parameter isolation; data extraction only if authorized |
| XSS | payload executes in browser in correct context; screenshot or browser evidence |
| SSRF | controlled callback or internal/cloud metadata proof |
| IDOR | second account accesses another account's object |
| BFLA | low-privilege account performs privileged function |
| CORS | malicious origin reads sensitive authenticated data |
| CSRF | cross-site PoC performs state-changing action |
| Race condition | more successful actions than allowed by business rule |
| Cache poisoning | poisoned response served without malicious header/input |

## Truthfulness Rules

- Never fabricate findings.
- Never report scanner output without validation.
- Say "possible" when evidence is weak.
- Say "likely" when evidence is strong but impact is not proven.
- Say "confirmed" only when the PoC works.
- False positives are worse than missed low-severity findings.

## Safe Impact Rules

- Use test accounts.
- Redact tokens, secrets, PII, and keys.
- Prove access with one sample, not a dump.
- Avoid destructive payloads.
- Do not persist XSS payloads where real users may trigger them.
- Do not run DoS, broad fuzzing, or aggressive race tests without explicit authorization.
