# ZAP and Playwright Reference

Use this reference when browser-driven coverage, DAST alerts, API scanning, or proxy evidence is needed. ZAP is installed inside the OpenGhost sandbox and is exposed only through `openghost zap`; Playwright is exposed through `openghost browser devtools`.

Official docs:

- Playwright Python BrowserType options, including proxy and persistent contexts: https://playwright.dev/python/docs/api/class-browsertype
- Playwright tracing: https://playwright.dev/python/docs/trace-viewer
- Playwright network/HAR recording: https://playwright.dev/python/docs/network
- ZAP Docker and packaged scans: https://www.zaproxy.org/docs/docker/
- ZAP Automation Framework: https://www.zaproxy.org/docs/automate/automation-framework/
- ZAP command line: https://www.zaproxy.org/docs/desktop/cmdline/
- ZAP API: https://www.zaproxy.org/docs/desktop/start/features/api/

## Operating Model

- Keep all ZAP and Playwright traffic inside the sandbox.
- Use Playwright to exercise authenticated UI and SPA behavior, then let ZAP passively analyze real traffic.
- Use ZAP automation plans for repeatable passive baseline, API import, and explicitly authorized active scans.
- Treat ZAP alerts as leads until a request/response, browser artifact, or manual replay confirms impact.

## Core Commands

```bash
# Start ZAP proxy daemon for Playwright-driven traffic.
openghost zap start
openghost zap proxy-url

# Drive Chromium through ZAP and save HAR, trace, screenshot, console, and storage state.
openghost browser devtools --url https://<target> --zap

# Export findings from the daemon after browser coverage.
openghost zap alerts --format json
openghost zap alerts --format md
openghost zap report --format html

# Run passive spider + passive scan automation plan.
openghost zap baseline --target https://<target> --minutes 5

# Import OpenAPI or GraphQL and run passive scan. Add --confirm-active only when active testing is authorized.
openghost zap api-scan --target https://<target>/openapi.json --format openapi --target-url https://<target>
openghost zap api-scan --target https://<target>/graphql --format graphql
openghost zap api-scan --target https://<target>/openapi.json --format openapi --target-url https://<target> --confirm-active
```

## Use Cases

### Authenticated SPA Coverage

1. Start ZAP: `openghost zap start`.
2. Use `openghost browser devtools --url <login-or-app-url> --zap`.
3. If credentials or MFA require manual handling, create a Playwright script under the engagement `scripts/` directory and run it through `openghost python file`.
4. Export ZAP alerts and reports after exercising important workflows.
5. Validate any high or medium alert manually before creating an OpenGhost finding.

### Passive Baseline

Use for production-safe coverage or first-pass assessment. It spiders and waits for passive scanning; it should not send active attack payloads.

```bash
openghost zap baseline --target https://<target> --minutes 5
```

Artifacts are written under `.openghost/engagements/<name>/zap/runs/`.

### API Coverage

Use OpenAPI/GraphQL import when specs or endpoints are in scope. Passive API scans are safe by default. Active API scanning requires explicit authorization and `--confirm-active`.

```bash
openghost zap api-scan --target ./openapi.json --format openapi --target-url https://<target>
openghost zap api-scan --target https://<target>/graphql --format graphql --confirm-active
```

After importing APIs, still test authorization manually across roles. ZAP can find injection and configuration issues, but it cannot prove BOLA, BFLA, tenant isolation, or business logic without role-aware validation.

### Manual Validation

For each ZAP lead:

1. Save the alert JSON/Markdown and relevant HTTP request/response.
2. Reproduce with the smallest safe request, using `curl`, `http`, Playwright, or a custom script.
3. Confirm exploitability and impact, not only the presence of a header or reflected string.
4. Add an OpenGhost finding only after evidence reaches high confidence.

## Safety Defaults

- `openghost zap baseline` is passive.
- `openghost zap api-scan` is passive unless `--confirm-active` is set.
- Do not run active scans on production, payment, admin, destructive, or high-volume endpoints unless explicitly authorized.
- Avoid broad crawling when scope excludes paths, tenants, or test windows.
- Use unique test data and low request rates.

## Evidence Checklist

- ZAP alert export and report path.
- Playwright HAR/trace/screenshot path when browser behavior matters.
- Exact request/response proving the issue.
- Role/account used for authenticated evidence.
- Manual validation notes and impact statement.
