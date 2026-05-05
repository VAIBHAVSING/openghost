# OpenGhost Skill

This repo contains one standalone Agent Skill: `skills/openghost-skill`. The skill is a centralized web application and server integrity pentesting skill for authorized assessments. It routes all tool execution through the bundled launcher so agents use the Docker sandbox instead of ad hoc host commands.

## Repo Shape

- `skills/openghost-skill`
  The skill package: `SKILL.md`, module references, workflow guidance, reporting guidance, and operational scripts.
- `Dockerfile`
  The isolated runtime image with tools such as OWASP ZAP, `nmap`, `nuclei`, `ffuf`, and `sqlmap`.
- `runtime/`
  Internal runtime entrypoint and healthcheck scripts used by the launcher.

## Main Entry

```bash
./skills/openghost-skill/scripts/openghost-skill.sh preflight
./skills/openghost-skill/scripts/openghost-skill.sh start
./skills/openghost-skill/scripts/openghost-skill.sh exec-tool nmap scanme.nmap.org
```
