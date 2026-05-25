# OpenGhost Skill

This repo contains one standalone Agent Skill: `skills/openghost-skill`. The skill is a centralized web application and server integrity pentesting skill for authorized assessments. It routes all tool execution through the bundled launcher so agents use the Docker sandbox instead of ad hoc host commands.

## Repo Shape

- `skills/openghost-skill`
  The skill package: `SKILL.md`, module references, workflow guidance, reporting guidance, and operational scripts.
- `skills/openghost`
  The skill-local launcher. It starts the sandbox and runs all tools inside Docker. The root `./openghost` file forwards here for convenience.
- `skills/openghost-skill/openghost`
  Standalone launcher kept inside the skill package for Agent Skills installs that copy only `openghost-skill`.
- `developer/docker`
  Developer-only sandbox image source used to publish `ghcr.io/vaibhavsing/openghost-sandbox:latest`. Normal skill users do not build this; the launcher pulls the GHCR image.

## Main Entry

```bash
./skills/openghost sandbox start
./skills/openghost engagement init --url https://example.com --name example
export OPENGHOST_SCOPE=.openghost/engagements/example/scope.yaml
./skills/openghost run nmap scanme.nmap.org
./skills/openghost evidence add --path response.txt --kind response --title "Confirmed response"
./skills/openghost finding add --title "IDOR allows invoice access" --severity high --module access-control --url /api/invoices/1005 --confidence 95 --evidence E-001 --step "Authenticate as user A." --step "Request user B invoice." --impact "User A can read user B invoices." --remediation "Enforce object-level authorization."
./skills/openghost report generate
```
