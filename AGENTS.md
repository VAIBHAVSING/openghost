# AGENTS.md

Project context for coding agents working on OpenGhost.

## What This Repo Is

OpenGhost is an original standalone Agent Skill for authorized web application and server integrity penetration testing. The repo packages skill instructions, reference methodology, evidence/reporting helpers, and a Docker-backed launcher that keeps security tooling out of the host environment.

The central design constraint is simple: agents provide reasoning and workflow control, while OpenGhost provides the sandboxed execution layer and structured engagement state.

## Product Boundary

- This repository owns the OpenGhost skill package and sandbox launcher.
- Security tools must be executed through `openghost`, not directly on the host.
- External research/reference directories are not runtime dependencies and should not be cited as OpenGhost source material.
- Generated engagement data belongs under `.openghost/` and should normally stay uncommitted.

## Agent Skill Structure

OpenGhost follows the standard Agent Skill layout:

- `skills/openghost-skill/SKILL.md` is the published skill entrypoint and operator workflow.
- Keep `SKILL.md` focused and use progressive disclosure: short entrypoint instructions first, deeper details in references.
- `skills/openghost-skill/references/` contains deeper guidance that agents should load only when relevant.
- `skills/openghost-skill/scripts/` contains deterministic helpers and launcher implementation.
- `skills/openghost-skill/assets/` contains templates and reusable output files.
- Do not duplicate large methodology content across files; link to the canonical reference instead.

## Main Source Paths

- `skills/openghost-skill/SKILL.md` - published skill entrypoint and operator workflow.
- `skills/openghost-skill/references/` - deeper guidance for modules, reporting, tooling, auth, and workflow.
- `skills/openghost-skill/references/modules/` - assessment modules such as surface mapping, session auth, access control, injection, APIs, browser policy, HTTP edge, business logic, and server integrity.
- `skills/openghost-skill/scripts/openghost.sh` - canonical CLI and Docker sandbox implementation.
- `skills/openghost-skill/scripts/verify-toolchain.sh` - runtime toolchain verification.
- `skills/openghost-skill/scripts/select-modules.py` - module selection helper.
- `skills/openghost-skill/assets/` - templates for scope, auth, findings, and reports.
- `skills/openghost-skill/agents/` - compatibility notes for other coding agents.

## Launchers

There are three launcher entrypoints:

- `./openghost` forwards to `skills/openghost`.
- `skills/openghost` forwards to `skills/openghost-skill/scripts/openghost.sh`.
- `skills/openghost-skill/openghost` is the standalone fallback for installs that copy only the skill package.

Keep launcher behavior consistent when changing CLI commands.

## Sandbox Model

The root `Dockerfile` intentionally delegates to `ghcr.io/vaibhavsing/openghost-sandbox:latest`. The actual maintainer image source is `docker/Dockerfile`.

Normal users should pull the published image. Maintainers can set `OPENGHOST_BUILD=1` to build from `docker/`.

The sandbox mounts the current workspace at `/workspace`, runs with dropped capabilities plus the minimum network capabilities needed for testing, and exposes tools through an allowlist in `openghost.sh`.

## CLI Surface

Primary commands:

```bash
./openghost sandbox start
./openghost sandbox status
./openghost sandbox stop
./openghost sandbox update
./openghost run <tool> [args...]
./openghost bash '<command>'
./openghost python code '<script>'
./openghost python file <path> -- [args...]
./openghost engagement init --url <target> --name <name>
./openghost finding add ...
./openghost finding list
./openghost todo add ...
./openghost todo list
./openghost todo update ...
./openghost report generate
```

Compatibility aliases exist in `openghost.sh`; preserve them unless intentionally making a breaking change.

## Engagement State

`openghost engagement init` creates:

- `.openghost/config.json`
- `.openghost/current`
- `.openghost/engagements/<name>/scope.yaml`
- `.openghost/engagements/<name>/engagement.json`
- `.openghost/engagements/<name>/findings.json`
- `.openghost/engagements/<name>/todos.json`
- evidence, notes, reports, artifacts, scripts, browser, and run directories.

`OPENGHOST_SCOPE` should point to the active `scope.yaml` before testing. Scope files are operational data, not source docs.

## Safety Rules

- Keep the authorization-first language in `SKILL.md`.
- Do not weaken the Docker-only rule for security tools.
- Do not remove the tool allowlist or bash blocklist casually.
- Avoid adding commands that can modify or damage host state.
- Keep examples scoped and non-destructive.
- Finding/report helpers must distinguish confirmed evidence from speculation.

## When Editing Tooling

If adding a sandbox tool, check all relevant surfaces:

- Install it in `docker/Dockerfile`.
- Add it to `ALLOWED_TOOLS` in `skills/openghost-skill/scripts/openghost.sh` if agents should run it directly.
- Add it to `skills/openghost-skill/scripts/verify-toolchain.sh` if it is required.
- Add docs only where operators need to see it: usually `SKILL.md`, `references/tooling.md`, or a module file.
- Keep root `Dockerfile` as a published-image delegate.

If changing CLI behavior, update examples in `README.md`, `SKILL.md`, and any affected reference docs.

## Documentation Style

- `README.md` should stay minimal: purpose, repo contents, quick start, and requirements.
- Detailed pentest methodology belongs in `SKILL.md` and `references/`.
- Agent-facing maintenance context belongs here.
- Keep docs direct and concise; avoid marketing copy.
- Use ASCII unless the edited file already requires otherwise.

## Verification

For docs-only edits:

```bash
rg -n "old command|wrong path" README.md AGENTS.md skills/openghost-skill
```

For shell edits:

```bash
bash -n openghost
bash -n skills/openghost
bash -n skills/openghost-skill/openghost
bash -n skills/openghost-skill/scripts/openghost.sh
bash -n skills/openghost-skill/scripts/verify-toolchain.sh
```

For Python edits:

```bash
python3 -m py_compile skills/openghost-skill/scripts/select-modules.py
```

For sandbox/runtime changes:

```bash
./openghost sandbox status
./skills/openghost-skill/scripts/verify-toolchain.sh
```

Only run Docker-heavy checks when Docker is available and the task requires runtime validation.

## Common Pitfalls

- Do not edit generated `.openghost/` engagement output as if it were source.
- Do not put long operator instructions in `README.md`.
- Do not duplicate the canonical CLI in another script; route through `openghost.sh`.
- Do not make the root `Dockerfile` the maintainer image source.
- Do not assume a reference directory in the workspace is part of the OpenGhost package.
