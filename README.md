# OpenGhost

[![skills.sh](https://skills.sh/b/VAIBHAVSING/openghost)](https://skills.sh/VAIBHAVSING/openghost)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Agent Skill](https://img.shields.io/badge/Agent%20Skill-SKILL.md-111827.svg)](skills/openghost-skill/SKILL.md)

Agent Skill for authorized web application and supporting server integrity
penetration testing.

OpenGhost helps an AI coding agent run a scoped security assessment. The agent
plans the work, tests carefully, validates evidence, and writes findings.
OpenGhost provides the Docker sandbox, scope files, evidence folders, reusable
checks, and report templates.

OpenGhost is fully local and open source. It has no hosted service, account,
API key, telemetry requirement, or managed control plane.

> [!IMPORTANT]
> Use OpenGhost only on systems you are explicitly authorized to test.
>
> Write the allowed targets, exclusions, accounts, rate limits, test windows,
> emergency contacts, and rules of engagement into the generated scope file
> before active testing.

## How to Use

Install the skill with the [skills](https://skills.sh/) CLI:

```bash
npx skills@latest add https://github.com/VAIBHAVSING/openghost --skill openghost-skill
```

Then ask your agent to use OpenGhost for an authorized assessment:

```text
Use $openghost-skill to assess https://target.example.
Authorization and scope details are in the engagement notes.
```

Make sure Docker is running and Bash 4.3+ plus Python 3 are available. Security tools are executed through the OpenGhost
sandbox, not directly on your host machine.

<details>
<summary>Use from a local checkout</summary>

```bash
git clone https://github.com/VAIBHAVSING/openghost.git
cd openghost
export PATH="$PWD/skills:$PWD/skills/openghost-skill:$PATH"
openghost help
```

</details>

<details>
<summary>Use with Codex or another Agent Skills client</summary>

Prefer the `skills` CLI install command above. If you install manually, copy the
skill folder into your client skill directory:

```bash
git clone https://github.com/VAIBHAVSING/openghost.git /tmp/openghost
mkdir -p ~/.agents/skills
cp -R /tmp/openghost/skills/openghost-skill ~/.agents/skills/
```

Codex and other Agent Skills clients can then discover the `openghost-skill`
package from the skill directory.

</details>

## Start an Engagement

Create a scoped workspace before testing:

```bash
openghost sandbox start
openghost engagement init --url https://target.example --name target-example
export OPENGHOST_SCOPE=.openghost/engagements/target-example/scope.yaml
# Edit scope.yaml, set authorization.reviewed: true, then validate it.
openghost scope validate
```

Edit the generated scope file:

```text
.openghost/engagements/target-example/scope.yaml
```

Add the allowed hosts, ports, paths, accounts, roles, tenants, exclusions, rate
limits, test windows, destructive-test rules, emergency contacts, and notes.

OpenGhost keeps generated engagement data under `.openghost/`. That data is
operational evidence and should normally stay out of commits.

## What OpenGhost Includes

```text
OpenGhost
|-- Agent Skill instructions
|-- Docker sandbox launcher
|-- Engagement state and scope helpers
|-- Evidence, finding, and report helpers
|-- Reusable assessment scripts
`-- Reference modules for common web and API test areas
```

| Area | What it does |
| --- | --- |
| `SKILL.md` | Tells the agent how to run an authorized assessment. |
| `openghost` launcher | Starts the sandbox and runs allowlisted tools inside Docker. |
| Scope files | Define what is allowed and what is out of bounds. |
| Evidence helpers | Save proof such as requests, responses, screenshots, and tool output. |
| Finding helpers | Record confirmed issues with impact, confidence, priority, and remediation. |
| Report templates | Build a final report from confirmed evidence. |

## Assessment Modules

OpenGhost is one skill package with several focused modules. The agent loads the
deeper reference only when that topic is needed.

| Module | Use it for |
| --- | --- |
| `surface-map` | Hosts, technologies, routes, endpoints, forms, and exposed files. |
| `server-integrity` | TLS, headers, DNS, services, and server posture. |
| `session-auth` | Login, cookies, JWT, OAuth/OIDC, SAML, API keys, and sessions. |
| `access-control` | Roles, tenants, object IDs, admin actions, BOLA, and BFLA. |
| `injection` | SQL, NoSQL, XSS, XML, command, template, and parser issues. |
| `api-protocols` | REST, OpenAPI, GraphQL, WebSocket, SOAP/XML, and gRPC. |
| `browser-policy` | CORS, CSP, clickjacking, browser behavior, and ZAP with Playwright. |
| `http-edge` | CDN, cache, proxy, WAF, host routing, and HTTP parameter pollution. |
| `business-logic` | Payments, approvals, invites, quotas, entitlements, races, and abuse cases. |

## Basic Workflow

Run safe checks through the sandbox:

```bash
openghost sandbox status
openghost script list
openghost script run web-baseline -- --target-url https://target.example
openghost script run api-inventory -- --target-url https://target.example
```

Record evidence:

```bash
openghost evidence add --path response.txt --kind response --title "Baseline response" --redaction redacted
```

Save a confirmed finding:

```bash
openghost finding add \
  --title "Example finding title" \
  --severity medium \
  --priority P3 \
  --module server-integrity \
  --url "https://target.example/" \
  --confidence 95 \
  --evidence E-001 \
  --step "Captured the baseline response." \
  --impact "Documented confirmed behavior." \
  --priority-rationale "P3 because impact is limited." \
  --remediation "Apply the recommended hardening."
```

Generate the report:

```bash
openghost context show
openghost coverage set --module server-integrity --status tested
openghost evidence verify
openghost report validate
openghost report generate
```

## Common Commands

### Sandbox

```bash
openghost sandbox start
openghost sandbox status
openghost sandbox stop
openghost sandbox update
openghost sandbox shell
```

### Tool Execution

```bash
openghost run <tool> [args...]
openghost bash '<command>'
openghost python code '<script>'
openghost python file <path> -- [args...]
```

### ZAP and Browser Workflows

```bash
openghost zap start
openghost zap baseline --target https://target.example --minutes 5
openghost zap api-scan --target https://target.example/openapi.json --format openapi --target-url https://target.example
openghost zap alerts --format md
openghost browser devtools --url https://target.example --zap
```

### Engagement Helpers

```bash
openghost todo add --task "Complete surface mapping" --module surface-map --priority high
openghost evidence add --path <file> --kind <kind> --title <title> --redaction <raw|redacted|sanitized>
openghost artifact add --path <file> --kind <kind> --title <title>
openghost finding add --title <title> --severity <severity> --module <module> --url <url> --confidence <90-100> --evidence E-001
openghost coverage set --module <module> --status <status>
openghost evidence verify
openghost report validate
openghost report generate
```

### Script Templates

```bash
openghost script list
openghost script show api-inventory
openghost script copy xss-check
openghost script run cors-check -- --base-url https://target.example --endpoints /api/me /
```

## Safety Model

- Confirm authorization, targets, exclusions, rate limits, and test windows
  before testing.
- Set `OPENGHOST_SCOPE` and verify scope before each target, module, and tool run.
- Run security tooling through `openghost`, not directly on the host.
- Treat scanner output as leads until validated with evidence.
- Keep generated engagement data under `.openghost/` and normally out of commits.
- Use destructive, high-volume, or state-changing checks only when the rules of
  engagement explicitly allow them.
- Separate confirmed findings from notes, draft leads, and speculation.

## Repository Map

```text
.
|-- README.md
|-- ARCHITECTURE.md
|-- DEVELOPMENT.md
|-- AGENTS.md
|-- CONTRIBUTING.md
|-- SECURITY.md
|-- Dockerfile
|-- docker/
|-- openghost
`-- skills/
    |-- openghost
    `-- openghost-skill/
        |-- SKILL.md
        |-- agents/
        |-- assets/
        |-- openghost
        |-- references/
        |   `-- modules/
        `-- scripts/
            `-- pentest/
```

## Developer Docs

- [Architecture](ARCHITECTURE.md) - components, command flow, trust boundaries,
  and engagement state.
- [Development](DEVELOPMENT.md) - local setup, validation commands, and release
  checklist.
- [AGENTS.md](AGENTS.md) - coding-agent maintenance context.
- [Contributing](CONTRIBUTING.md) - contribution rules and pull request
  expectations.
- [Security](SECURITY.md) - vulnerability reporting policy.
- [Attribution](ATTRIBUTION.md) - attribution and provenance notes.

## Contribute

Keep OpenGhost direct and practical:

- Keep `README.md` simple: purpose, install, basic use, safety, and repo map.
- Keep detailed methodology in `skills/openghost-skill/SKILL.md` and
  `skills/openghost-skill/references/`.
- Keep security tools inside the Docker sandbox.
- Keep examples scoped and non-destructive.
- Keep confirmed findings evidence-backed.

## License

OpenGhost is licensed under the Apache License 2.0. See [LICENSE](LICENSE).
