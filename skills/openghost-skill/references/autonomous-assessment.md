# Autonomous Assessment Reference

Use this reference when you need a fast, scoped first pass that produces concrete leads for manual validation.

## Purpose

`openghost assess` is a deterministic orchestrator for the skill. It runs safe bundled templates through Docker, registers raw outputs as evidence, creates `likely` findings for medium-or-higher signals, adds validation todos, and writes an `assessment.json` summary.

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
--token <token>                 Use a bearer token for read-only authenticated checks.
--max-requests 40               Cap generated requests per template.
--rate-ms 250                   Delay between template requests.
--max-leads 20                  Cap likely findings created from signals.
--json                          Emit machine-readable assessment summary.
```

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
4. Read `assessment.json`, `openghost finding list --status likely`, and `openghost todo list`.
5. For each useful lead, load the relevant module reference and validate manually.
6. Promote only validated issues with direct evidence to confirmed findings.
7. Generate the final report after confirmed findings are ready.

## Interpretation Rules

- Treat missing-header and inventory signals as context unless they enable a concrete exploit path.
- Treat CORS as high impact only when sensitive authenticated data is readable cross-origin.
- Treat exposed admin/internal paths as leads until access control, sensitivity, and exploitability are proven.
- Treat XSS marker reflection as a lead; browser execution evidence is required before confirmed reporting.
- Keep automated outputs as evidence records, but do not cite them as sole proof for confirmed findings.
