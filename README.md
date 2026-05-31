# OpenGhost

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Agent Skill](https://img.shields.io/badge/Agent%20Skill-SKILL.md-111827.svg)](https://agentskills.io/)

OpenGhost is a standalone Agent Skill for authorized web application and server integrity penetration testing. It packages the operator workflow, module references, evidence helpers, report templates, and a Docker-backed launcher so AI agents can run structured assessments without installing security tools on the host.

The model is intentionally split:

- The agent provides reasoning, planning, and workflow control.
- OpenGhost provides the sandboxed execution layer, scope state, evidence records, and report output.

Use OpenGhost only on systems you are explicitly authorized to test.

## Features

- Agent Skill package with a `SKILL.md` entrypoint, reference docs, scripts, and assets.
- Docker sandbox for security tooling, with an allowlist and host isolation.
- Engagement state under `.openghost/`, including scope, evidence, artifacts, todos, findings, and reports.
- Coverage for OWASP WSTG, OWASP API Top 10, authenticated testing, access control, injection, browser policy, HTTP edge cases, business logic, and server integrity.
- Bundled low-impact Python templates for repeatable checks such as API inventory, web baseline, CORS, JWT, GraphQL, WebSocket, HPP, cache behavior, BOLA/BFLA, SQLi/NoSQLi probes, XSS reflection, and vulnerability triage.
- ZAP, Playwright/browser validation, and common web assessment tools exposed through the `openghost` launcher.

## Install

### Install as an Agent Skill

If your agent supports the `skills` CLI, install the skill from GitHub:

```bash
npx skills add VAIBHAVSING/openghost --skill openghost-skill
```

The skill will become available to compatible agents through its `SKILL.md` metadata. The launcher still requires Docker at runtime.

### Clone for local development or direct CLI use

```bash
git clone https://github.com/VAIBHAVSING/openghost.git
cd openghost
export PATH="$PWD/skills:$PWD/skills/openghost-skill:$PATH"
```

Requirements:

- Bash
- Docker with a reachable daemon
- Network access to pull `ghcr.io/vaibhavsing/openghost-sandbox:latest`

## Quick Start

```bash
openghost sandbox start
openghost engagement init --url https://target.example --name target-example
export OPENGHOST_SCOPE=.openghost/engagements/target-example/scope.yaml
```

Edit the generated scope file before testing. Add allowed hosts, excluded hosts and paths, credentials, rate limits, testing windows, and any rules of engagement.

Run non-destructive checks through the sandbox:

```bash
openghost sandbox status
openghost script list
openghost script run web-baseline -- --target-url https://target.example
openghost script run api-inventory -- --target-url https://target.example
```

Record evidence and produce a report:

```bash
openghost evidence add --path response.txt --kind response --title "Baseline response"
openghost finding add \
  --title "Example finding title" \
  --severity medium \
  --module server-integrity \
  --evidence E-001 \
  --step "Captured the baseline response." \
  --impact "Documented confirmed behavior." \
  --remediation "Apply the recommended hardening."
openghost report generate
```

## Using With AI Agents

Point the agent at `skills/openghost-skill/SKILL.md` or install the skill with a compatible skill manager. The skill tells the agent when to load deeper reference files and how to keep all tool execution inside Docker.

Examples:

```bash
codex --instructions "Read skills/openghost-skill/SKILL.md and prepare an authorized assessment plan for https://target.example"
```

```bash
gemini "Read skills/openghost-skill/SKILL.md and help initialize an OpenGhost engagement for https://target.example"
```

For agents that auto-discover Agent Skills, install the package and ask for an authorized web app assessment. The `description` field in `SKILL.md` is the trigger surface.

## CLI Overview

Sandbox lifecycle:

```bash
openghost sandbox start
openghost sandbox status
openghost sandbox stop
openghost sandbox update
openghost sandbox shell
```

Run tools inside Docker:

```bash
openghost run <tool> [args...]
openghost bash '<command>'
openghost python code '<script>'
openghost python file <path> -- [args...]
```

ZAP and browser workflows:

```bash
openghost zap start
openghost zap baseline --target https://target.example --minutes 5
openghost zap api-scan --target https://target.example/openapi.json --format openapi --target-url https://target.example
openghost zap alerts --format md
openghost browser devtools --url https://target.example --zap
```

Engagement helpers:

```bash
openghost engagement init --url <url> --name <name>
openghost todo add --task "Complete surface mapping" --module surface-map --priority high
openghost evidence add --path <file> --kind <kind> --title <title>
openghost artifact add --path <file> --kind <kind> --title <title>
openghost finding add --title <title> --severity <severity> --evidence E-001
openghost report generate
```

Script templates:

```bash
openghost script list
openghost script show api-inventory
openghost script copy xss-check
openghost script run cors-check -- --base-url https://target.example --endpoints /api/me /
```

Run `openghost help` for the complete command list.

## Repository Layout

```text
.
|-- AGENTS.md
|-- Dockerfile
|-- README.md
|-- developer/
|   `-- docker/
|-- openghost
|-- runtime/
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

Important paths:

- `skills/openghost-skill/SKILL.md` - skill manifest and operator workflow.
- `skills/openghost-skill/references/` - deeper workflow, tooling, auth, reporting, and module guidance.
- `skills/openghost-skill/references/modules/` - focused assessment modules.
- `skills/openghost-skill/scripts/openghost.sh` - canonical launcher and Docker sandbox implementation.
- `skills/openghost-skill/scripts/pentest/` - bundled reusable script templates.
- `skills/openghost-skill/assets/` - scope, auth, finding, and report templates.
- `developer/docker/Dockerfile` - maintainer image source for the sandbox.
- `Dockerfile` - published-image delegate for normal users.

## Agent Skill Structure

OpenGhost follows the Agent Skills format used by modern agent clients:

```text
openghost-skill/
|-- SKILL.md        # Required metadata and instructions
|-- scripts/        # Executable helpers for deterministic work
|-- references/     # Documentation loaded by agents only when needed
`-- assets/         # Templates and reusable output resources
```

`SKILL.md` contains YAML frontmatter with `name`, `description`, `license`, and metadata. Keep this file focused on discovery, safety rules, setup, and the high-level workflow. Put detailed methodology in `references/`, deterministic helpers in `scripts/`, and reusable templates in `assets/`.

## Security Model

OpenGhost is designed for authorized assessments:

- Confirm authorization, allowed targets, exclusions, rate limits, and test windows before testing.
- Set `OPENGHOST_SCOPE` and verify scope before running tests.
- Run security tooling through `openghost`, not directly on the host.
- Keep destructive, high-volume, or state-changing tests disabled unless explicitly authorized.
- Treat scanner output as leads until validated with evidence.
- Keep generated engagement data under `.openghost/` and normally out of commits.

The sandbox mounts the current workspace at `/workspace`, drops unnecessary capabilities, and exposes tools through the launcher allowlist.

## Developer Guide

### Validate local changes

For documentation-only changes:

```bash
rg -n "old command|wrong path" README.md AGENTS.md skills/openghost-skill
```

For shell changes:

```bash
bash -n openghost
bash -n skills/openghost
bash -n skills/openghost-skill/openghost
bash -n skills/openghost-skill/scripts/openghost.sh
bash -n skills/openghost-skill/scripts/verify-toolchain.sh
```

For Python changes:

```bash
python3 -m py_compile skills/openghost-skill/scripts/select-modules.py
python3 -m py_compile skills/openghost-skill/scripts/openghost-state.py
```

For sandbox/runtime changes:

```bash
./openghost sandbox status
./skills/openghost-skill/scripts/verify-toolchain.sh
```

### Add or update a sandbox tool

1. Install the tool in `developer/docker/Dockerfile`.
2. Add it to `ALLOWED_TOOLS` in `skills/openghost-skill/scripts/openghost.sh` if agents should run it directly.
3. Add it to `skills/openghost-skill/scripts/verify-toolchain.sh` if it is required.
4. Document operator usage in `SKILL.md`, `references/tooling.md`, or the relevant module file.
5. Keep the root `Dockerfile` as a delegate to the published image.

Build a local developer image when needed:

```bash
OPENGHOST_BUILD=1 OPENGHOST_IMAGE=openghost-sandbox:dev ./openghost sandbox update
```

### Add or update a module

1. Add module guidance under `skills/openghost-skill/references/modules/`.
2. Keep the module focused on one assessment area.
3. Link it from `SKILL.md` only where agents need to discover it.
4. Update `skills/openghost-skill/references/module-map.md` if module selection changes.
5. Update `skills/openghost-skill/scripts/select-modules.py` if automatic selection should include the module.

### Add or update a script template

1. Add the script under `skills/openghost-skill/scripts/pentest/`.
2. Give it safe defaults and clear `--help` output.
3. Add its metadata to `skills/openghost-skill/scripts/pentest/manifest.json`.
4. Run it only through `openghost script run` or `openghost python file`.
5. Treat output as evidence to validate, not as an automatically confirmed finding.

### Publish and registry notes

The project is installable by skill managers that can read GitHub repositories with a `skills/` directory. For `skills.sh` compatibility:

- Keep `skills/openghost-skill/SKILL.md` frontmatter valid.
- Make the `description` field explicit about what the skill does and when agents should use it.
- Keep references relative to the skill root.
- Avoid duplicating long methodology in both `SKILL.md` and `references/`.
- Keep scripts, references, and assets organized by purpose.

The sandbox image is built from `developer/docker/Dockerfile` by the GitHub Actions workflow in `.github/workflows/publish-sandbox-image.yml`.

## License

OpenGhost is licensed under the Apache License 2.0. See [LICENSE](LICENSE).

## References

- [Agent Skills overview](https://agentskills.io/)
- [Open Agent Skills specification](https://openagentskills.dev/docs/specification)
- [skills.sh documentation](https://www.skills.sh/docs)
