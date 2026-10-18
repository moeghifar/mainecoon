# AGENTS.md

Entrypoint for AI coding agents (Claude, Codex, Gemini, Goose, …) in this repo. Read this
first. It is the single source of truth for **how** work is done here.

**What** to build lives in the brain vault (`plan/` → Jira). Its location is in
`.specify/AGENTS.md` (gitignored, never pushed). Start every session by reading
`plan/01-packages.md` there; it holds the target layout and the gap list.

---

## What this repo is

A Go library of cryptographic **primitives**, grouped by use case. No servers, no storage,
no KMS clients, no wire-format envelopes — those belong to the products that import it
(xandi, cryptop, sandibox).

Layout (final for v0.x): `symmetric/{aead,siv,xts,kwp,ff1,stream,cmac,gmac}`,
`asymmetric/{sign,kem,hpke,rsaoaep}`, `hash`, `mac`, `kdf`, `password`, `drbg`, `token`,
`registry`, `keys`, `kat`, `errors`, `internal/`.

Go **1.27** minimum (`go.mod`). Never lower it: ML-KEM, ML-DSA, SLH-DSA and HPKE must come
from the standard library, not a fallback.

## Rules for adding an algorithm

1. **Priority:** FIPS-approved → NIST PQC → others. Anything else needs a reason in the plan.
2. **Go 1.27 stdlib first.** Allowed deps: `golang.org/x/crypto`, `github.com/cloudflare/circl`,
   `github.com/tink-crypto/tink-go/v2` (`*/subtle` packages only), `github.com/capitalone/fpe/ff1`
   (non-test code only where stdlib lacks the algorithm). Ask before adding any other.
3. **No hand-written cryptography.** If stdlib and the allowed deps lack an algorithm, it is not
   offered.
4. Every algorithm ships with, in the same change:
   - a `registry` entry (family, standard, FIPS, PQ, hybrid);
   - a startup KAT in `kat/` (the coverage test fails without one);
   - unit tests against published vectors (NIST ACVP, Wycheproof, RFC) stored in `testdata/`
     with the source noted;
   - a fuzz test if it parses untrusted input.
5. **Floors are enforced by policy, not by the primitive:** each parameter set has a
   strength in `registry`; the default minimum is 128-bit and callers lower it explicitly.
   Fixed minimums: HMAC key ≥ hash size, PBKDF2 iterations, RSA ≥ 2048 and ≤ 8192.
6. **Fail closed.** Bad input returns a coded error from `errors`; never a partial result,
   never a panic. `Error()` is the code only; detail goes in `Detail()`.
7. Nonces and IVs are generated inside the library, never taken from callers (except
   documented KAT hooks in tests).
8. Zero every key the library decodes or generates internally. Caller buffers are the
   caller's.

## Frozen for v0.x

Algorithm ID strings (`AES-256-GCM`, `ML-DSA-65`, …) and error codes. Changing one is a
breaking change: ask first and record it in `CHANGELOG.md`.

## Testing

```
go test ./...                                   # all
go test -short ./...                            # skip slow PBKDF2
go test -race ./...
GODEBUG=fips140=only go test -run TestFIPSOnlyModule .
go vet ./...
```

- stdlib `testing`, table-driven; no assertion framework.
- **Run tests and vet before reporting done.** Report failures with output. If something
  could not be run, say so and call it unproven.

## Working agreement

- **Ask before:** adding a dependency, changing a frozen ID or error code, moving a package
  across the mainecoon/product boundary, widening scope beyond the task.
- **Don't:** commit or push unless asked; commit anything under `.specify/`; add speculative
  abstractions.
- **Do:** keep diffs minimal; match surrounding style; update `README.md` when the public API
  changes; record plan changes in the vault, not in this repo.

## Commits, PRs, releases

- Conventional Commits: `feat(sign): add ML-DSA-87`, `fix(token): …`, `docs: …`, `chore: …`.
  One logical change per commit; imperative subject ≤ 72 chars.
- **No AI attribution anywhere**: no `Co-Authored-By`, "Generated with …", tool names or
  emoji in commits, PR titles/bodies, tags, release notes, code comments or docs. The author
  is the git user.
- Work on a branch (`feat/…`, `fix/…`, `release/vX.Y.Z`); `main` changes only through a
  reviewed PR with green CI.
- Licence is Apache-2.0. New dependencies must be Apache-2.0/BSD/MIT compatible and listed
  in `NOTICE`.
- Releases follow `RELEASING.md`; every user-visible change gets a `CHANGELOG.md` entry.

## Docs

- `README.md`: purpose, install, one short how-to per package, algorithm table. To the point;
  no marketing, no internal history.
- Package doc comments say what the primitive is for and what it refuses.
