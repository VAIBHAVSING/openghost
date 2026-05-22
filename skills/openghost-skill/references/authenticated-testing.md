# Authenticated Testing Reference

Use this reference to set up authentication contexts for multi-role and multi-tenant testing.

## Required Contexts

Use as many of these as the engagement provides:

1. unauthenticated
2. regular user A
3. regular user B
4. elevated user or manager
5. admin
6. tenant A user
7. tenant B user
8. API/service account

Record each account, role, tenant, and token/cookie file in `notes/auth-context.md`. Add cookie jars or auth work files with `openghost artifact add --kind auth`. Do not store real secrets in final reports.

## Bearer Token

```bash
export AUTH_HEADER="Authorization: Bearer <TOKEN>"
openghost bash 'curl -s -i -H "Authorization: Bearer <TOKEN>" https://<target>/api/me'
```

## Cookie-Based Session

```bash
# Login and capture cookies
openghost bash 'curl -s -i -c /workspace/.openghost/engagements/<name>/artifacts/auth/user-a.cookies -d "username=userA&password=<password>" https://<target>/login'

# Use cookies
openghost bash 'curl -s -i -b /workspace/.openghost/engagements/<name>/artifacts/auth/user-a.cookies https://<target>/dashboard'
```

## Multi-Role Request Replay

For every sensitive endpoint, replay with each context:

```bash
# user A reads own object
openghost bash 'curl -s -i -H "Authorization: Bearer <USER_A_TOKEN>" https://<target>/api/users/<USER_A_ID>'

# user A reads user B object
openghost bash 'curl -s -i -H "Authorization: Bearer <USER_A_TOKEN>" https://<target>/api/users/<USER_B_ID>'

# unauthenticated
openghost bash 'curl -s -i https://<target>/api/users/<USER_A_ID>'
```

## OAuth/OIDC Token Acquisition

For authorization code flow, use browser automation or manual capture when needed. Token exchange example:

```bash
openghost bash 'curl -s -X POST https://<auth-host>/oauth/token \
  -d "grant_type=authorization_code&code=<CODE>&redirect_uri=<CALLBACK>&client_id=<CLIENT_ID>&client_secret=<CLIENT_SECRET>" | jq .'
```

For client credentials:

```bash
openghost bash 'curl -s -X POST https://<auth-host>/oauth/token \
  -d "grant_type=client_credentials&client_id=<CLIENT_ID>&client_secret=<CLIENT_SECRET>" | jq .'
```

## JWT Handling

```bash
openghost bash 'TOKEN="<JWT>"; echo "$TOKEN" | cut -d. -f1 | base64 -d 2>/dev/null | jq .; echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq .'
openghost run jwt_tool <JWT>
```

Track:

- which endpoint issued token
- token lifetime
- refresh token behavior
- claims linked to user/role/tenant
- logout invalidation behavior

## Testing Patterns

### Horizontal Access

1. Login as user A.
2. Capture user A resource request.
3. Login as user B.
4. Replay user A request using user B credentials and vice versa.

### Vertical Access

1. Capture admin request.
2. Replay with regular user credentials.
3. Test alternate methods and method override headers.

### Cross-Tenant Access

1. Identify tenant ID in URL, body, header, cookie, or JWT.
2. Switch tenant value while keeping same token.
3. Test list, read, write, export, invite, and admin endpoints.

### Session Lifecycle

1. Capture token before login if present.
2. Login and compare session token.
3. Logout and replay old token.
4. Reset password and replay old token.
5. Complete MFA and compare token/session state.

## Evidence Storage

Suggested files:

```text
artifacts/auth/user-a.cookies
artifacts/auth/user-b.cookies
artifacts/auth/admin.cookies
notes/auth-context.md
evidence/F-001/response/E-001-auth-replay-user-a-to-user-b.txt
```

Register auth files with `openghost artifact add --kind auth` and replay proof with `openghost evidence add --kind response`. Redact credentials before committing or sharing reports.
