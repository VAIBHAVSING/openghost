# Contributing

OpenGhost is an Agent Skill and Docker sandbox launcher for authorized security
testing. Contributions should preserve the authorization-first workflow,
Docker-only tool execution, and evidence quality gates.

Start with:

- [Architecture](ARCHITECTURE.md) for components and trust boundaries.
- [Development](DEVELOPMENT.md) for setup, validation, and maintainer workflows.
- [Security](SECURITY.md) for vulnerability reporting.

## Contribution Rules

- Keep generated engagement data under `.openghost/` and out of commits.
- Do not commit credentials, target data, screenshots with sensitive data,
  traffic captures, or real assessment evidence.
- Run security tools through `openghost`, not directly on the host.
- Keep `skills/openghost-skill/SKILL.md` focused and put detailed methodology in
  `references/`.
- Preserve launcher compatibility aliases unless a breaking change is intentional
  and documented.
- Keep the root `Dockerfile` as a delegate to the published sandbox image.

## Pull Requests

Pull requests should include:

- What changed and why.
- Validation commands run.
- Any security, compatibility, or operator workflow impact.
- Documentation updates for changed commands, paths, or behavior.

Before opening a PR, check that no real target names, credentials, traffic
captures, or vulnerability evidence from live systems are included.
