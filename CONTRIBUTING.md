# Contributing

OpenGhost is an Agent Skill and sandbox launcher for authorized security testing. Contributions should keep the authorization-first workflow, Docker-only tool execution, and evidence quality gates intact.

## Local Setup

```bash
git clone https://github.com/VAIBHAVSING/openghost.git
cd openghost
export PATH="$PWD/skills:$PWD/skills/openghost-skill:$PATH"
```

Docker is required for runtime testing. Documentation and helper validation can run without Docker.

## Development Rules

- Keep `skills/openghost-skill/SKILL.md` focused and move detailed methodology into `references/`.
- Run security tools through `openghost`, not directly on the host.
- Keep generated engagement data under `.openghost/` and out of commits.
- Do not commit credentials, target data, screenshots with sensitive data, or real assessment evidence.
- Preserve compatibility aliases in `skills/openghost-skill/scripts/openghost.sh` unless a breaking change is intentional and documented.
- Keep the root `Dockerfile` as a delegate to the published image; maintain the sandbox image source in `docker/Dockerfile`.

## Validation

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
PYTHONPYCACHEPREFIX=/tmp/openghost-pycache python3 -m py_compile \
  skills/openghost-skill/scripts/select-modules.py \
  skills/openghost-skill/scripts/openghost-state.py
rm -rf /tmp/openghost-pycache
```

For skill package changes:

```bash
python3 /home/vsing/.codex/skills/.system/skill-creator/scripts/quick_validate.py skills/openghost-skill
```

For sandbox changes:

```bash
OPENGHOST_BUILD=1 OPENGHOST_IMAGE=openghost-sandbox:dev ./openghost sandbox update
./skills/openghost-skill/scripts/verify-toolchain.sh
```

Only run Docker-heavy checks when Docker is available and the task needs runtime validation.

## Pull Requests

Pull requests should include:

- What changed and why.
- Validation commands run.
- Any security, compatibility, or operator workflow impact.
- Documentation updates for changed commands, paths, or behavior.

Do not include real target names, credentials, traffic captures, or vulnerability evidence from live systems.
