## Summary

-

## Validation

- [ ] `bash -n openghost skills/openghost skills/openghost-skill/openghost skills/openghost-skill/scripts/openghost.sh skills/openghost-skill/scripts/verify-toolchain.sh`
- [ ] `python3 -m py_compile skills/openghost-skill/scripts/select-modules.py skills/openghost-skill/scripts/openghost-state.py`
- [ ] Skill validation, if `skills/openghost-skill` changed
- [ ] Docker/toolchain validation, if `docker/` changed

## Security and Safety

- [ ] No credentials, target data, traffic captures, or real assessment evidence are included.
- [ ] Security tooling still runs through `openghost`.
- [ ] Documentation was updated for changed commands, paths, or behavior.
