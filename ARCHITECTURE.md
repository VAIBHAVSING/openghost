# Architecture

OpenGhost separates agent reasoning from security tool execution.

The agent owns planning, scope decisions, module selection, and reporting
judgment. OpenGhost owns the sandboxed execution layer, deterministic helpers,
engagement state, and evidence/report files.

## Design Goals

- Keep offensive tooling out of the host environment.
- Make authorization, scope, and evidence explicit.
- Give agents a short skill entrypoint with deeper references loaded only when
  relevant.
- Keep engagement output separate from source code.
- Preserve one canonical launcher implementation.

## System Overview

```text
Agent client
  |
  | reads
  v
skills/openghost-skill/SKILL.md
  |
  | calls
  v
openghost launcher
  |
  | starts / execs
  v
Docker sandbox
  |
  | writes structured state
  v
.openghost/engagements/<name>/
```

## Main Components

### Skill Package

`skills/openghost-skill/` is the published Agent Skill package.

- `SKILL.md` is the entrypoint, metadata, safety rules, setup, and high-level
  workflow.
- `references/` contains deeper methodology for scope, workflow, tooling,
  authentication, ZAP/Playwright, reporting, risk triage, threat modeling, and
  modules.
- `references/modules/` contains focused assessment modules such as surface
  mapping, session auth, access control, injection, APIs, browser policy, HTTP
  edge cases, business logic, and server integrity.
- `scripts/` contains the launcher, state helper, verification helper, and
  reusable pentest templates.
- `assets/` contains reusable templates for scope, auth, findings, and reports.
- `agents/` contains compatibility notes for specific agent clients.

### Launchers

OpenGhost has three entrypoints:

- `./openghost` - repository root convenience wrapper.
- `skills/openghost` - skill-local CLI shim.
- `skills/openghost-skill/openghost` - standalone fallback for installs that
  copy only the skill package.

All entrypoints forward to:

```text
skills/openghost-skill/scripts/openghost.sh
```

Keep command behavior consistent across all entrypoints by changing
`openghost.sh`, not by duplicating logic in wrappers.

### Docker Sandbox

The default runtime image is:

```text
ghcr.io/vaibhavsing/openghost-sandbox:latest
```

The root `Dockerfile` intentionally delegates to that published image so normal
root builds behave like normal skill installs.

Maintainers build the sandbox image from:

```text
docker/Dockerfile
```

The sandbox mounts the current workspace at `/workspace`, starts from
`WORKDIR /workspace`, and exposes tools only through the launcher allowlist.
The launcher also contains a bash blocklist for obvious destructive host or
system-damage patterns.

### State Helper

`skills/openghost-skill/scripts/openghost-state.py` owns structured engagement
state. The shell launcher delegates evidence, artifact, finding, todo, and
report operations to this helper.

Generated state normally lives under:

```text
.openghost/
|-- config.json
|-- current
`-- engagements/
    `-- <name>/
        |-- scope.yaml
        |-- engagement.json
        |-- state/
        |-- evidence/
        |-- artifacts/
        |-- scripts/
        |-- notes/
        |-- reports/
        `-- runs/
```

`.openghost/` is operational data. It should normally stay uncommitted.

## Command Flow

### Sandbox Lifecycle

```text
openghost sandbox start
  -> require Docker
  -> pull or build image
  -> start container
  -> mount workspace
```

`OPENGHOST_BUILD=1` switches maintainer mode on and builds the local
`docker/Dockerfile` instead of pulling the published image.

### Tool Execution

```text
openghost run nmap ...
  -> verify nmap is allowlisted
  -> ensure sandbox exists
  -> docker exec nmap ...
```

`openghost bash` and `openghost python` also run inside Docker. They are for
assessment automation and parsing, not for bypassing scope or safety controls.

### Script Templates

```text
openghost script run api-inventory -- --target-url https://target.example
  -> read manifest
  -> locate bundled script
  -> execute inside Docker
```

Use `openghost script copy <name>` when a template needs target-specific
changes. Modified copies belong under the active engagement's `scripts/`
directory.

### Evidence and Reporting

```text
openghost evidence add ...
openghost finding add ...
openghost report generate
```

Findings should reference evidence IDs and distinguish confirmed behavior from
likely or possible signals.

## Trust Boundaries

- Host system: should not run offensive tools directly.
- Docker sandbox: runs assessment tooling with workspace mount and constrained
  capabilities.
- Target system: must be explicitly authorized and represented in
  `OPENGHOST_SCOPE`.
- Engagement state: may contain sensitive operational data and evidence.
- Source tree: should contain reusable skill/package code, not real target data.

## Change Guide

When changing the CLI:

- Update `skills/openghost-skill/scripts/openghost.sh`.
- Preserve compatibility aliases unless the breaking change is intentional.
- Update `README.md`, `DEVELOPMENT.md`, and relevant skill references.
- Run shell validation.

When adding a sandbox tool:

- Install it in `docker/Dockerfile`.
- Add it to `ALLOWED_TOOLS` in `openghost.sh` when direct agent access is
  intended.
- Add it to `verify-toolchain.sh` if it is required.
- Document operator usage only where operators need it.

When adding assessment methodology:

- Keep `SKILL.md` short.
- Put detailed guidance in `references/` or `references/modules/`.
- Avoid duplicating large methodology across files.
