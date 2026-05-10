# Business Logic Module

Covers: business logic flaws, workflow bypass, price/quantity/currency manipulation, coupon/reward abuse, race conditions, rate-limit bypass, authorization gaps between workflow states, replay, stale token use, and feature abuse.

## Goals

- Understand intended business invariants before testing.
- Prove that the application allows a user to violate those invariants.
- Use test accounts and reversible transactions only.

## Workflow Mapping

Map each critical workflow as states, transitions, and invariants.

Examples:

```text
E-commerce: product -> cart -> checkout -> payment -> confirmation -> fulfillment
Financial: balance check -> transfer request -> fraud check -> confirmation -> settlement
Registration: signup -> email verify -> MFA setup -> active account
Approval: request -> review -> approve -> execute
Subscription: trial -> paid plan -> renewal -> cancellation
```

Document:

```markdown
| Step | Endpoint | Required State | Required Role | Invariant |
|---|---|---|---|---|
| checkout | POST /api/checkout | cart priced by server | user | total cannot be client-controlled |
```

## Price, Quantity, and Currency Manipulation

Test whether server trusts client-side values:

```bash
# Negative quantity
openghost bash 'curl -s -X POST -H "Content-Type: application/json" -H "Authorization: Bearer <TOKEN>" -d "{\"product_id\":1,\"quantity\":-1,\"price\":99.99}" https://<target>/api/cart/add'

# Zero price
openghost bash 'curl -s -X POST -H "Content-Type: application/json" -H "Authorization: Bearer <TOKEN>" -d "{\"product_id\":1,\"quantity\":1,\"price\":0}" https://<target>/api/cart/add'

# Modify checkout total
openghost bash 'curl -s -X POST -H "Content-Type: application/json" -H "Authorization: Bearer <TOKEN>" -d "{\"cart_id\":123,\"total\":0.01}" https://<target>/api/checkout'
```

Payload classes:

```text
quantity: -1, 0, 0.001, 999999999, 2147483647
price: 0, 0.01, -1, null, "0", "0.00", []
currency: USD -> JPY, USD -> XXX
coupon: duplicate coupon, expired coupon, coupon from another user
tax/shipping: 0, negative, omitted field
```

## Workflow Step Bypass

Test direct API calls and stale tokens:

- access dashboard after password but before MFA
- submit checkout confirmation without payment
- activate account without email verification
- approve request as requester
- skip terms acceptance
- reuse password reset token
- reuse invite token
- call final API endpoint directly
- replay signed step token after state changed

Example:

```bash
openghost bash 'curl -s -H "Authorization: Bearer <TOKEN_AFTER_PASSWORD_BEFORE_MFA>" https://<target>/api/dashboard'
```

## Coupon, Reward, Referral, and Credit Abuse

Test:

- apply same coupon multiple times
- stack incompatible coupons
- use expired coupons
- use another user's coupon
- self-referral loops
- referral with disposable accounts
- negative reward redemption
- duplicate refund
- trial reset by changing email/payment method
- plan downgrade while retaining paid features

Record expected invariant and actual violation.

## Race Conditions

### Attack Surface

- coupon redemption limit
- balance transfer/withdrawal
- checkout limited inventory
- vote/like once per user
- password reset token use
- invite token use
- email change + password reset
- MFA disable + sensitive action
- API key generation/deletion

### Python Threading Test

```python
import threading
import requests

url = "https://target.example/api/redeem-coupon"
headers = {"Authorization": "Bearer TOKEN", "Content-Type": "application/json"}
data = {"code": "DISCOUNT50"}
results = []

def send():
    r = requests.post(url, json=data, headers=headers, timeout=10)
    results.append((r.status_code, r.text[:200]))

threads = [threading.Thread(target=send) for _ in range(20)]
for t in threads:
    t.start()
for t in threads:
    t.join()

print(results)
print("successes", sum(1 for status, _ in results if status == 200))
```

Run through the sandbox:

```bash
openghost python code '<python script here>'
```

### Single-Packet Concept

Use single-packet race techniques only when authorized. The goal is to send all requests in the same TCP/TLS packet or HTTP/2 gate so they arrive before state updates commit.

### Confirmation

Confirmed if more successful operations occur than business rules allow, such as:

- coupon redeemed twice
- balance withdrawn twice
- item purchased beyond stock
- token used multiple times
- rate limit counter bypassed

## Rate Limit and Abuse Bypass

Test safe variations:

```text
X-Forwarded-For
X-Real-IP
X-Originating-IP
Forwarded
Client-IP
X-Client-IP
User-Agent variation
case variation: /login vs /Login
method variation: POST vs PUT
path variation: /login/ vs /login
batching: GraphQL aliases, JSON arrays, bulk endpoints
```

Do not run high-volume attacks unless authorized.

## Role and State Transition Logic

Test:

- role changed while active session remains privileged
- downgrade account but old token retains paid privileges
- admin impersonation leaks admin capability to user session
- tenant switch does not clear cached authorization
- support role can escalate through hidden fields
- approval can be performed by requester

## Business Logic Reporting

Every finding needs:

- Intended rule or invariant
- Steps showing violation
- Exact API calls or UI actions
- Test account IDs and roles
- Before/after state
- Business impact in plain language
- Reversible cleanup steps
- Remediation: server-side pricing/state enforcement, transaction locks, idempotency keys, atomic updates, state machine validation, replay protection

## Severity Guidance

| Impact | Typical Severity |
|---|---|
| free purchase, unauthorized refund, balance theft | Critical/High |
| duplicate coupon/reward with financial value | High/Medium |
| workflow bypass to privileged feature | High |
| email verification bypass with account takeover chain | High/Critical |
| rate-limit bypass without sensitive action | Low/Medium |
| minor UI-only workflow bypass | Low |
