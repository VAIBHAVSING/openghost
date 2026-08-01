# Development

This guide is for maintainers changing the OpenGhost skill package, launcher,
sandbox image, or documentation.

## Local Setup

```bash
git clone https://github.com/VAIBHAVSING/openghost.git
cd openghost
export PATH="$PWD/skills:$PWD/skills/openghost-skill:$PATH"
openghost help
```

Docker is required for runtime testing. Documentation, shell syntax checks, and
Python compilation checks can run without Docker.

## Validation Commands

Documentation-only changes:

```bash
rg -n "old command|wrong path" README.md ARCHITECTURE.md DEVELOPMENT.md CONTRIBUTING.md AGENTS.md skills/openghost-skill
```

Shell changes:

```bash
bash -n openghost
bash -n skills/openghost
bash -n skills/openghost-skill/openghost
bash -n skills/openghost-skill/scripts/openghost.sh
bash -n skills/openghost-skill/scripts/verify-toolchain.sh
```

Python changes:

```bash
PYTHONPYCACHEPREFIX=/tmp/openghost-pycache python3 -m py_compile \
  skills/openghost-skill/scripts/select-modules.py \
  skills/openghost-skill/scripts/scope_utils.py \
  skills/openghost-skill/scripts/openghost-assess.py \
  skills/openghost-skill/scripts/openghost-state.py \
  skills/openghost-skill/scripts/check-references.py
PYTHONPYCACHEPREFIX=/tmp/openghost-pycache python3 -m unittest discover -s tests -v
python3 skills/openghost-skill/scripts/check-references.py
rm -rf /tmp/openghost-pycache
```

Skill package validation:

```bash
python3 /home/vsing/.codex/skills/.system/skill-creator/scripts/quick_validate.py skills/openghost-skill
```

Sandbox/runtime changes:

```bash
./openghost sandbox status
./skills/openghost-skill/scripts/verify-toolchain.sh
```

Only run Docker-heavy checks when Docker is available and the change requires
runtime validation.

## Common Workflows

### Update Skill Instructions

1. Keep `skills/openghost-skill/SKILL.md` focused on routing, operating rules,
   setup, and workflow.
2. Put detailed methodology in `skills/openghost-skill/references/`.
3. Put module-specific methodology in `skills/openghost-skill/references/modules/`.
4. Keep examples scoped, authorized, and non-destructive by default.
5. Run skill validation when the package structure or frontmatter changes.

### Change CLI Behavior

1. Change `skills/openghost-skill/scripts/openghost.sh`.
2. Keep `./openghost`, `skills/openghost`, and
   `skills/openghost-skill/openghost` as wrappers.
3. Preserve compatibility aliases unless intentionally breaking them.
4. Update README examples and relevant references.
5. Run shell validation.

### Add A Sandbox Tool

1. Install the tool in `docker/Dockerfile`.
2. Add it to `ALLOWED_TOOLS` in `skills/openghost-skill/scripts/openghost.sh`
   if agents should run it directly.
3. Add it to `skills/openghost-skill/scripts/verify-toolchain.sh` if it is
   required.
4. Document usage in `SKILL.md`, `references/tooling.md`, or the relevant module.
5. Keep the root `Dockerfile` as a delegate to the published image.

Build a local developer image when needed:

```bash
OPENGHOST_BUILD=1 OPENGHOST_IMAGE=openghost-sandbox:dev ./openghost sandbox update
```

### Add A Script Template

1. Add the script under `skills/openghost-skill/scripts/pentest/`.
2. Give it safe defaults and a useful `--help`.
3. Add metadata to `skills/openghost-skill/scripts/pentest/manifest.json`.
4. Run it through `openghost script run` or `openghost python file`.
5. Treat output as evidence to validate, not as an automatically confirmed
   finding.

### Add Or Update A Module

1. Add module guidance under `skills/openghost-skill/references/modules/`.
2. Keep the module focused on one assessment area.
3. Link it from `SKILL.md` only where agents need to discover it.
4. Update `skills/openghost-skill/references/modules/module-map.md` when module
   selection changes.
5. Update `skills/openghost-skill/scripts/select-modules.py` when automatic
   selection should include the module.

## Skills.sh Listing

This repository includes `skills.sh.json` at the root to improve how the repo is
grouped on skills.sh.

For compatibility:

- Keep `skills/openghost-skill/SKILL.md` frontmatter valid.
- Keep the `description` explicit about when agents should use the skill.
- Keep references relative to the skill root.
- Avoid duplicating long methodology in `README.md`.
- Use the install form:

```bash
npx skills@latest add VAIBHAVSING/openghost --skill openghost-skill
```

## Release Checklist

Before shipping:

- [ ] README examples still match `openghost help`.
- [ ] `ARCHITECTURE.md` still matches launcher, state, and Docker behavior.
- [ ] `CONTRIBUTING.md` and `.github/PULL_REQUEST_TEMPLATE.md` validation lists
      are still accurate.
- [ ] No generated `.openghost/` data, credentials, target names, screenshots, or
      traffic captures are staged.
- [ ] Docker-heavy checks were run when runtime behavior changed.
