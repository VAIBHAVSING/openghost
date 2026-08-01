# Access Control Module

Covers: IDOR, BOLA, BFLA, BOPLA, mass assignment, excessive data exposure, sensitive data exposure, open redirect, forced browsing, multi-tenant isolation, role transitions, and method/path authorization bypasses.

## Contents

- Goals and required auth context
- Object reference mapping and IDOR/BOLA
- BFLA, BOPLA, and mass assignment
- Excessive data exposure and open redirect
- Forced browsing and multi-tenant isolation
- Authorization matrix and reporting checklist

## Execution Gate

Use only authorized test identities and seeded objects. Read operations still require role/tenant limits; writes, mass assignment, forced browsing, and workflow transitions require their applicable scope gates and cleanup plan. Never use another customer's real object as proof.

## Goals

- Verify authorization on every object, function, and property.
- Test horizontal, vertical, and cross-tenant access boundaries.
- Prove impact with two or more test accounts and minimal safe data access.

## Required Auth Context

Use at least these contexts when available:

- unauthenticated
- user A
- user B
- low-privilege user
- admin or elevated test account
- tenant A user
- tenant B user

Record token/cookie file names and roles in `notes/auth-context.md`.

## Object Reference Mapping

Collect every object reference from URLs, JSON, GraphQL variables, hidden fields, cookies, WebSocket messages, and JavaScript.

Common object types:

```text
user_id, account_id, profile_id, order_id, invoice_id, payment_id, document_id, file_id, message_id, conversation_id, project_id, workspace_id, org_id, tenant_id, team_id, role_id
```

ID formats to test:

- Sequential integers: `1`, `2`, `3`
- UUIDs copied from user B or leaked list endpoints
- Base64 encoded IDs: `MTAx` -> `101`
- Hash-like IDs with predictable source values
- Slugs and usernames
- Composite IDs: `tenant:user`, `org/project/id`

## IDOR / BOLA

BOLA is authorization failure at the object level. Every object access must enforce ownership or permission.

Template helper:

```bash
OPENGHOST_TARGET_BEARER_TOKEN='<user-a-target-token>' \
  openghost script run bola-check -- --base-url https://<target> --endpoints '/api/orders/{id}' --ids <USER_B_OBJECT_ID>
```

### Test Pattern

1. Login as user A and capture a request to user A's resource.
2. Login as user B and capture user B's equivalent resource ID.
3. Replay user A's request with user B's token and user A's object ID.
4. Replay user A's token against user B's object ID.
5. Repeat for GET, POST, PUT, PATCH, DELETE, export, download, and search/list endpoints.

Example:

```bash
# User A token reading user B profile
openghost bash 'curl -s -H "Authorization: Bearer <USER_A_TOKEN>" https://<target>/api/users/<USER_B_ID>/profile | jq .'

# Write-based IDOR
openghost bash 'curl -s -X PATCH -H "Authorization: Bearer <USER_A_TOKEN>" -H "Content-Type: application/json" -d "{\"display_name\":\"changed-by-test\"}" https://<target>/api/users/<USER_B_ID>/profile'
```

### Common IDOR Locations

```text
GET /api/users/{id}
GET /api/orders/{id}
GET /api/invoices/{id}/download
GET /api/documents/{id}
PUT /api/users/{id}/profile
DELETE /api/comments/{id}
POST /api/files/{id}/share
GET /api/messages?conversation_id={id}
POST /api/export
```

### Confirmation Criteria

Confirmed when user A can read, modify, delete, share, export, or infer user B's data without authorization.

## BFLA - Broken Function-Level Authorization

BFLA is authorization failure at the action/function level.

### Test Pattern

1. Map privileged functions from UI, JS, docs, route names, and errors.
2. Call privileged endpoint with lower-privilege token.
3. Try alternate methods and method override headers.
4. Try direct API calls even if the UI hides the function.

```bash
# Admin list with regular token
openghost bash 'curl -s -H "Authorization: Bearer <USER_TOKEN>" https://<target>/api/admin/users'

# Privileged delete with regular token
openghost bash 'curl -s -X DELETE -H "Authorization: Bearer <USER_TOKEN>" https://<target>/api/users/<id>'

# Method override
openghost bash 'curl -s -X POST -H "X-HTTP-Method-Override: DELETE" -H "Authorization: Bearer <USER_TOKEN>" https://<target>/api/users/<id>'
```

High-value privileged actions:

- create/delete users
- assign roles
- export data
- refund/charge
- approve workflows
- change tenant settings
- invite users
- generate API keys
- impersonate users

## BOPLA and Mass Assignment

BOPLA is property-level authorization failure. Mass assignment is accepting unexpected writable fields.

Template helper:

```bash
openghost script copy mass-assignment-check
OPENGHOST_TARGET_BEARER_TOKEN='<target-app-token>' \
  openghost python file .openghost/engagements/<name>/scripts/mass_assignment_check.py -- \
  --base-url https://<target> --endpoint /api/users/me --confirm-write
```

### Test Pattern

1. Capture a normal create/update request.
2. Add sensitive fields.
3. Check response and subsequent state.
4. Test both root object and nested objects.

Payload fields:

```json
{
  "role": "admin",
  "roles": ["admin"],
  "isAdmin": true,
  "is_admin": true,
  "verified": true,
  "email_verified": true,
  "account_status": "active",
  "plan": "enterprise",
  "balance": 999999,
  "credits": 999999,
  "price": 0,
  "discount": 100,
  "tenant_id": "other-tenant",
  "org_id": "other-org",
  "owner_id": "victim-user",
  "password_hash": "test",
  "api_key": "test"
}
```

Example:

```bash
openghost bash 'curl -s -X PATCH -H "Authorization: Bearer <TOKEN>" -H "Content-Type: application/json" -d "{\"name\":\"test\",\"role\":\"admin\",\"isAdmin\":true}" https://<target>/api/users/me | jq .'
```

### Framework Notes

- Rails: missing `params.permit()` can allow arbitrary fields.
- Django/DRF: serializer may expose writable fields unintentionally.
- Express/Mongoose: direct `Model.update(req.body)` is high risk.
- Laravel: missing `$fillable` or unsafe `$guarded` config.
- Spring/Jackson: object binding can overwrite nested fields.

## Excessive Data Exposure

APIs often return more fields than the UI displays.

Test:

```bash
openghost bash 'curl -s -H "Authorization: Bearer <TOKEN>" https://<target>/api/users/me | jq .'
openghost bash 'curl -s -H "Authorization: Bearer <TOKEN>" https://<target>/api/users | jq .[0]'
```

Sensitive fields:

```text
password_hash, reset_token, mfa_secret, totp_secret, api_key, secret, access_token, refresh_token, ssn, dob, credit_card, internal_id, tenant_id, role, permissions, audit_notes, deleted_at, created_by, internal_flags
```

Confirmed when sensitive fields are exposed to unauthorized users or roles. If the field is non-sensitive and only unnecessary, severity is lower.

## Open Redirect

Parameters to test:

```text
url, redirect, redirect_uri, next, return, return_url, goto, continue, dest, destination, callback, callback_url, relay, relayState
```

Payloads:

```text
//evil.example
https://evil.example
https://target.example@evil.example
https://target.example.evil.example
/\evil.example
/%5cevil.example
//evil.example/%2f..
https://evil.example#target.example
https://evil%E3%80%82example
java%0d%0ascript:alert(1)
```

Chains:

- Open redirect + OAuth/OIDC redirect URI = code/token theft
- Open redirect + SSRF allowlist = internal fetch bypass
- Open redirect + phishing = credential theft risk

Report only when redirect reaches attacker-controlled destination or enables a meaningful chain.

## Forced Browsing and Path Authorization

```bash
openghost run ffuf -u https://<target>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,301,302,401,403
openghost run ffuf -u https://<target>/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 200,401,403
```

Test discovered paths with:

- no auth
- invalid auth
- user token
- admin token
- alternate methods
- path casing and normalization

Path bypass examples:

```text
/admin
/Admin
/admin/
/admin/.
/./admin
/%61dmin
/admin..;/
/admin%2f
/admin%252f
```

## Multi-Tenant Isolation

For tenant-aware apps, test every tenant boundary:

- URL: `/tenant/<id>/resource`
- Header: `X-Tenant-ID`, `X-Org-ID`, `X-Workspace-ID`
- JSON body: `tenant_id`, `org_id`, `workspace_id`
- JWT claim: `tenant_id`, `org_id`
- Cookie/local storage: tenant switcher values

Confirmed when tenant A can read or modify tenant B resources.

## Authorization Matrix

Build a matrix for key actions:

```markdown
| Endpoint | Unauth | User A | User B | Admin | Expected | Actual |
|---|---:|---:|---:|---:|---|---|
| GET /api/users/A | 401 | 200 | 403 | 200 | owner/admin only | ok |
| GET /api/users/B | 401 | 403 | 200 | 200 | owner/admin only | A gets 200 |
```

## Reporting Checklist

- Two test accounts used
- Exact request from attacker context
- Exact victim object/function/property
- Response proving unauthorized access
- Impact: read, write, delete, export, privilege escalation, tenant escape
- Remediation: server-side authorization checks on object, function, and property; deny-by-default; tenant scoping in queries; field allowlists
