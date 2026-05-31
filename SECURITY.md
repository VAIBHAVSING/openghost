# Security Policy

OpenGhost is security tooling, so vulnerability reports need enough detail to reproduce safely without exposing targets or third-party systems.

## Supported Versions

Security fixes are handled on the `main` branch until the project publishes versioned releases.

## Reporting a Vulnerability

Use GitHub private vulnerability reporting for this repository when available. Do not open a public issue with exploit details, credentials, target data, or sensitive evidence.

Include:

- Affected commit, release, or sandbox image digest.
- Reproduction steps using only local fixtures, disposable labs, or intentionally vulnerable targets.
- Expected and actual behavior.
- Impact and any safe proof-of-concept output.
- Whether any secret, credential, customer data, or third-party target was involved.

If private vulnerability reporting is not available, open a public issue that says a private security report is needed, but do not include exploit details.

## Scope

In scope:

- OpenGhost launcher and engagement-state helpers.
- Skill instructions, bundled scripts, references, and templates.
- Published sandbox image build configuration.
- CI/CD configuration in this repository.

Out of scope:

- Findings in third-party systems tested with OpenGhost.
- Vulnerabilities in upstream security tools unless OpenGhost packages or invokes them unsafely.
- Reports that require destructive testing outside an authorized lab.

## Disclosure

Maintainers will acknowledge valid reports, triage impact, and publish fixes or mitigations before public disclosure when practical. Reporters should avoid accessing data beyond the minimum proof needed and should delete any sensitive evidence after resolution unless legal or contractual obligations require retention.
