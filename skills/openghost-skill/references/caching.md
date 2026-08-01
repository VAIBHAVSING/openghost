# Local Caching and Context Cost

OpenGhost is a local open-source skill. It has no remote cache service and cannot control a model provider's prompt-cache billing. It reduces repeated work and agent context by keeping deterministic local caches under the active engagement.

## Cache layers

### Script bundle cache

`openghost script run` content-addresses the selected bundled template, `og_pentest.py`, and the bundled notice. The unchanged bundle is copied to `.openghost/cache/scripts/<name>/<sha256>/` once and reused on later runs.

Changing any bundled code creates a new cache entry. The cached code remains inside generated `.openghost/` state and should not be committed.

### Assessment result cache

`openghost assess run` caches deterministic template output under the engagement's `cache/assessment/` directory.

The key covers:

- selected tool, module, and exact arguments;
- request, delay, and timeout limits;
- SHA-256 of `scope.yaml`;
- SHA-256 of the selected template and shared helper;
- an anonymous/authenticated context marker.

Default TTL is 3600 seconds. Use:

```bash
openghost assess run --confirm-scope-reviewed --cache-ttl 3600
openghost assess run --confirm-scope-reviewed --refresh
openghost assess run --confirm-scope-reviewed --no-cache
```

Target-authenticated results are not reused by default because permissions and user state can change. `--cache-authenticated` is an explicit opt-in. OpenGhost stores only a one-way credential fingerprint in the key, never the credential.

Cache hits reuse the registered evidence record. They are recorded in `assessment.json` so the operator can distinguish fresh execution from reuse.

### Compact context cache

Run:

```bash
openghost context show
```

This content-addresses the current engagement, scope, findings, evidence, artifacts, todos, coverage, and latest assessment. It produces a short snapshot containing counts, top confirmed findings, leads, open work, coverage, recent cache statistics, and recommended next actions.

Use the snapshot as the agent's resume point. Load raw state, reports, or evidence only for the current hypothesis. This is the primary mechanism for reducing LLM input: less irrelevant text is placed into context.

Use `openghost context show --refresh` to rebuild the snapshot. Normal state changes automatically produce a new key, and authorization-window readiness is refreshed at least every five minutes, so manual refresh is rarely necessary.

Inspect local cache usage with `openghost cache status`.

## Data handling

- All cache files remain under `.openghost/`.
- Cache metadata must not contain target credentials, cookies, raw authorization headers, or secret environment-variable values.
- Treat cached assessment output as potentially sensitive engagement data.
- A cache hit does not increase finding confidence and never converts a lead into a confirmed finding.
- Refresh time-sensitive checks when authorization, identity, role, tenant, deployment, or target state may have changed.
