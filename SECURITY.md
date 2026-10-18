# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes |
| < 0.1 | no |

While mainecoon is v0, only the latest minor release gets fixes.

## Reporting a vulnerability

Do not open a public issue. Use GitHub private vulnerability reporting:
**Security → Report a vulnerability** on this repository.

Include the affected package, version, a reproducer if you have one, and the impact you
expect. You get an acknowledgement within 3 working days and a fix or mitigation plan within
14 days for confirmed issues. Fixes ship as a patch release with a GitHub security advisory.

## Scope

mainecoon wraps the Go standard library, golang.org/x/crypto, cloudflare/circl, tink-go and
capitalone/fpe. A flaw in one of those is reported upstream; we pin and release a patched
version once it is fixed. Build with the latest Go patch release: `govulncheck` reports
standard-library advisories against older toolchains.
