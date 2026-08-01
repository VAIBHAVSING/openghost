# Autonomous Assessment Reference

Use this reference when you need a fast, scoped first pass that produces concrete leads for manual validation.

## Purpose

`openghost assess` is a deterministic orchestrator for the skill. It runs safe bundled templates through Docker, registers raw outputs as evidence, creates `likely` findings for medium-or-higher signals, adds validation todos, and writes an `assessment.json` summary.

OpenGhost is local-only. It has no service token. An optional bearer token is a credential for the authorized target application and is forwarded only to the selected sandbox script process.

It does not create confirmed findings. Promotion to confirmed still requires direct proof, reproduction steps, impact, remediation, priority, and priority rationale.

## Commands

Preview the plan:

```bash
openghost assess plan --target-url https://<target> --mode standard
```

Run the first pass after authorization and scope have been reviewed:

```bash
openghost assess run --target-url https://<target> --confirm-scope-reviewed --mode standard
```

If an active engagement already has `target_url`, `--target-url` can be omitted:

```bash
openghost assess run --confirm-scope-reviewed
```

## Modes

| Mode | Checks | Use When |
|---|---|---|
| `safe` | `web-baseline`, `api-inventory` | minimal passive/read-only signal collection |
| `standard` | safe checks plus `forced-browsing-check`, dynamic `cors-check` | default first pass for most authorized web/API targets |
| `deep` | standard plus low-impact XSS marker probes | disposable lab or explicit approval for broader read-only probing |

Options:

```bash
--endpoint /api/me              Seed an endpoint for dynamic CORS checks. Repeatable.
--token-env <NAME>              Read a target-app bearer token from this host environment variable.
--token-file <path>             Read a target-app bearer token from a local uncommitted file.
--max-requests 40               Cap generated requests per template.
--rate-ms 250                   Delay between template requests.
--max-leads 20                  Cap likely findings created from signals.
--cache-ttl 3600                Reuse matching deterministic outputs for this many seconds.
--refresh                       Ignore matching cached results and refresh them.
--no-cache                      Disable deterministic output caching.
--cache-authenticated           Opt in to target-authenticated output reuse; off by default.
--json                          Emit machine-readable assessment summary.
```

Cache keys include the exact scope, arguments, limits, template code, and shared helper code. Credentials are never stored; only a one-way authentication-context fingerprint participates in the key. A cache hit reuses an existing evidence record rather than creating duplicate evidence.

## Output

The run creates:

- `runs/assess-<timestamp>/assessment.json`
- one raw JSON output per template in the run directory
- `E-###` evidence records for raw tool outputs
- `likely` findings for critical/high/medium signals
- validation todos linked to created likely findings
- an artifact record for `assessment.json`

## Agent Workflow

1. Confirm authorization and review `scope.yaml`.
2. Run `openghost assess plan` to preview the low-impact first pass.
3. Run `openghost assess run --confirm-scope-reviewed`.
4. Run `openghost context show`; open raw `assessment.json` only if the compact summary is insufficient.
5. For each useful lead, load the relevant module reference and validate manually.
6. Promote only validated issues with direct evidence to confirmed findings.
7. Generate the final report after confirmed findings are ready.

## Interpretation Rules

- Treat missing-header and inventory signals as context unless they enable a concrete exploit path.
- Treat CORS as high impact only when sensitive authenticated data is readable cross-origin.
- Treat exposed admin/internal paths as leads until access control, sensitivity, and exploitability are proven.
- Treat XSS marker reflection as a lead; browser execution evidence is required before confirmed reporting.
- Keep automated outputs as evidence records, but do not cite them as sole proof for confirmed findings.
