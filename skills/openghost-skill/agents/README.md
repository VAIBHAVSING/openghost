# Agent Compatibility

OpenGhost works with any AI coding agent that can read markdown and run bash commands.

## Claude Code
Place this skill directory in your project. Claude Code auto-discovers `SKILL.md`.

## OpenAI Codex CLI
```bash
codex --instructions "Read skills/openghost-skill/SKILL.md and follow it to pentest https://target.com"
```

## Cursor
Add to `.cursorrules`:
```
For security testing, read and follow skills/openghost-skill/SKILL.md
```

## Gemini CLI
```bash
gemini "Read skills/openghost-skill/SKILL.md and run a web pentest on https://target.com"
```

## Any Other Agent
Point the agent to `SKILL.md` — it contains everything needed to self-guide:
- Operating rules and safety constraints
- Tool execution via the `openghost` launcher on `PATH`
- Module order and selection criteria
- Finding/todo management commands
- Links to deep reference docs per module

## Key Principle
The agent provides the **brain** (reasoning, methodology, adaptation).
OpenGhost provides the **hands** (Docker sandbox, safety pipeline, structured tools).
