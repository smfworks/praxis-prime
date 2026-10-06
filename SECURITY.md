# Security policy

Praxis Prime is **alpha** (M0–M3 roadmap complete; some blueprint MVP items deferred). It is not a security-supported release. `praxis-primed` listens on `127.0.0.1` only, and only when you start it. Compliance dials default to off. At monitor, a match is audited and the action still runs. At enforce, a pack rule can block, require approval, redact, or deny egress. That is not a certification, and a dial left off enforces nothing. Treat this alpha as an agent, not as a control you can rely on.

## Reporting a vulnerability

Please use GitHub private vulnerability reporting:

https://github.com/smfworks/praxis-prime/security/advisories/new

Do not open a public issue for a vulnerability, and do not include secrets, access tokens, or other people's private data in the report.

There is no security mailing list published yet. If private reporting on GitHub is unavailable, contact a maintainer of the `smfworks` organization directly and say the message is a security report.

## What to expect

We will acknowledge reports that include enough detail to understand the issue. There is no patch SLA. Fixes land on `main` when there is something to fix. We will credit reporters who want to be named.

## Supported versions

| Version | Status |
|---|---|
| 0.1.0 (alpha, unreleased, `main`) | Not a supported security release |

## Scope notes

- Default config must keep every compliance dial off, the gateway on loopback, and the sandbox network off. A change that flips those defaults is a bug even before the features exist.
- The project does not want proof-of-concept exploits against third-party systems. Reports should describe an issue in this repository.
- Compliance dials are technical controls. They are not HIPAA, FERPA, GDPR, SOC 2, or ISO certifications. Do not deploy this alpha as one.
