# Hacker News Draft

## Title

Show HN: OpenGhost - an Agent Skill for AI-assisted web pentesting

## URL

https://github.com/VAIBHAVSING/openghost

## Text

Hi HN,

I built OpenGhost because I wanted coding agents to be useful for authorized web
app security testing without just giving them a raw shell.

Agents like Codex, Claude Code, and Cursor are already useful for writing code,
debugging, and optimization because developer tooling has adapted around them.
Pentesting still lags behind: it needs scope, authorization, safe tool
execution, evidence, findings, todos, and a report trail.

OpenGhost is an Agent Skill plus a Docker-backed CLI for that workflow.

The agent does the reasoning and coordination. OpenGhost provides the operating
layer:

- Docker sandbox for security tools
- allowlisted openghost launcher instead of direct host commands
- explicit scope through OPENGHOST_SCOPE
- engagement state under .openghost/
- helpers for evidence, artifacts, findings, todos, and reports
- reusable checks for web, API, auth, access control, injection, browser policy,
  HTTP edge cases, and server posture

Install:

```bash
npx skills@latest add https://github.com/VAIBHAVSING/openghost --skill openghost-skill
```

Example prompt:

```text
Use $openghost-skill to assess https://target.example.
Confirm scope first, run tools only through openghost, keep testing non-destructive, validate findings with evidence, and generate a report.
```

This is not meant to be a magic "autonomous hacker" tool. Scanner output is
treated as a lead, not a confirmed finding. A finding still needs evidence,
reproduction steps, impact, confidence, priority, and remediation.

The main thing I am exploring is whether Agent Skills are the right abstraction
for this kind of work. Instead of building another AI pentester CLI, OpenGhost
lets people use the coding agent they already have, while keeping the security
tooling local and scoped.

I would especially like feedback from appsec and pentest people:

- Is a local Docker sandbox the right boundary for agent-assisted pentesting?
- Is this better as an Agent Skill, a standalone CLI, or both?
- What would make you trust or not trust this workflow on a real assessment?
