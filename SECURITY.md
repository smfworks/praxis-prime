# Security policy

Praxis Prime is **pre-alpha**. The `0.0.x` skeleton is not a security-supported release. The daemon does not listen, and the compliance dials do not enforce policy. Treat the code as a design skeleton, not as a control you can rely on.

## Reporting a vulnerability

Please use GitHub private vulnerability reporting:

https://github.com/smfworks/praxis-prime/security/advisories/new

Do not open a public issue for a vulnerability, and do not include secrets, access tokens, or other people's private data in the report.

There is no security mailing list published yet. If private reporting on GitHub is unavailable, contact a maintainer of the `smfworks` organization directly and say the message is a security report.

## What to expect

We will acknowledge reports that include enough detail to understand the issue. This skeleton has no patch SLA. Fixes land on `main` when there is something to fix. We will credit reporters who want to be named.

## Supported versions

| Version | Status |
|---|---|
| 0.0.x (pre-alpha, `main`) | Not a supported security release |

## Scope notes

- Default config must keep every compliance dial off, the gateway on loopback, and the sandbox network off. A change that flips those defaults is a bug even before the features exist.
- The project does not want proof-of-concept exploits against third-party systems. Reports should describe an issue in this repository.
- Compliance dials are technical controls on a roadmap. They are not HIPAA, FERPA, GDPR, SOC 2, or ISO certifications. Do not deploy this skeleton as one.
