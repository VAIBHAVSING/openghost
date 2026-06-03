# OpenGhost

[![skills.sh](https://skills.sh/b/VAIBHAVSING/openghost)](https://skills.sh/VAIBHAVSING/openghost)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Agent Skill](https://img.shields.io/badge/Agent%20Skill-SKILL.md-111827.svg)](skills/openghost-skill/SKILL.md)

Agent Skill for authorized web application and server integrity penetration testing.

OpenGhost gives AI coding agents a real assessment workflow: scoped targets,
Docker-backed tool execution, evidence records, reusable checks, and report
output. The agent reasons and coordinates; OpenGhost keeps security tools inside
a sandbox and keeps engagement data organized under `.openghost/`.

Use OpenGhost only on systems you are explicitly authorized to test.

## Quickstart

1. Install the skill:

   ```bash
   npx skills@latest add VAIBHAVSING/openghost --skill openghost-skill
   ```

2. Make sure Docker is running.

3. Ask your agent to use OpenGhost for an authorized assessment, or clone the repo
   for direct CLI use:

   ```bash
   git clone https://github.com/VAIBHAVSING/openghost.git
   cd openghost
   export PATH="$PWD/skills:$PWD/skills/openghost-skill:$PATH"
   openghost help
   ```

4. Start a scoped engagement:

   ```bash
   openghost sandbox start
   openghost engagement init --url https://target.example --name target-example
   export OPENGHOST_SCOPE=.openghost/engagements/target-example/scope.yaml
   ```

5. Edit the generated scope file before testing. Add allowed hosts, exclusions,
   credentials, rate limits, test windows, emergency contacts, and rules of
   engagement.

## Why OpenGhost Exists

### Security tools should not leak onto the host

Agents are good at reasoning, but ad hoc host commands make security work messy.
OpenGhost routes assessment tooling through `openghost`, which runs allowlisted
commands inside a Docker sandbox.

### Pentests need scope discipline

A useful assessment starts with explicit authorization, hosts, accounts, testing
windows, rate limits, and exclusions. OpenGhost keeps those constraints in
`OPENGHOST_SCOPE` and makes scope part of the operator workflow.

### Scanner output is not a finding

OpenGhost treats scanners and scripts as leads. Findings should include evidence,
reproduction steps, impact, confidence, priority, and remediation before they are
reported as confirmed.

### Agents need reusable structure

The skill package gives agents a short `SKILL.md` entrypoint plus deeper module
references only when needed. That keeps the main prompt readable while still
covering OWASP WSTG, OWASP API Top 10, authenticated testing, access control,
injection, browser policy, HTTP edge cases, business logic, server integrity,
ZAP-backed DAST, and Playwright/browser validation.

## Basic Workflow

Run checks through the sandbox:

```bash
openghost sandbox status
openghost script list
openghost script run web-baseline -- --target-url https://target.example
openghost script run api-inventory -- --target-url https://target.example
```

Record evidence and generate a report:

```bash
openghost evidence add --path response.txt --kind response --title "Baseline response"
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
openghost report generate
```

## Reference

### Skill Package

- `skills/openghost-skill/SKILL.md` - agent-facing entrypoint and workflow.
- `skills/openghost-skill/references/` - deeper workflow, tooling, auth,
  reporting, risk triage, threat modeling, and module guidance.
- `skills/openghost-skill/references/modules/` - assessment modules for surface
  mapping, session auth, access control, injection, APIs, browser policy, HTTP
  edge cases, business logic, and server integrity.
- `skills/openghost-skill/scripts/` - launcher, state helper, verification, and
  reusable automation.
- `skills/openghost-skill/assets/` - scope, auth, finding, and report templates.

### Sandbox Commands

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

### ZAP And Browser Workflows

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
openghost evidence add --path <file> --kind <kind> --title <title>
openghost artifact add --path <file> --kind <kind> --title <title>
openghost finding add --title <title> --severity <severity> --module <module> --url <url> --confidence <90-100> --evidence E-001
openghost report generate
```

### Script Templates

```bash
openghost script list
openghost script show api-inventory
openghost script copy xss-check
openghost script run cors-check -- --base-url https://target.example --endpoints /api/me /
```

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
|-- skills.sh.json
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

## Safety Model

- Confirm authorization, targets, exclusions, rate limits, and test windows
  before testing.
- Set `OPENGHOST_SCOPE` and verify scope before running tests.
- Run security tooling through `openghost`, not directly on the host.
- Treat scanner output as leads until validated with evidence.
- Keep generated engagement data under `.openghost/` and normally out of commits.
- Use destructive, high-volume, or state-changing checks only when the rules of
  engagement explicitly allow them.

## License

OpenGhost is licensed under the Apache License 2.0. See [LICENSE](LICENSE).
