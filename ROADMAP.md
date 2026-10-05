# Roadmap

What is planned for quantum-safe-py, in priority order. These are intentions, not promises:
there are no dates, the order can change, and anything here can be dropped. Shipped changes
are in [CHANGELOG.md](CHANGELOG.md). Progress is tracked in the
[milestones](https://github.com/AnimeshShaw/quantum-safe-py/milestones).

While the version starts with `0.`, a **minor** release (0.3 to 0.4) is where breaking
changes happen, and each one is announced a release earlier with a `DeprecationWarning` and a
changelog entry. A patch release (0.3.1 to 0.3.2) does not break correct code.

## Now: 0.3.2 (patch)

- `Sign.sign_raw()` and a standard `Sign.verify_raw()`: plain FIPS 204 ML-DSA with a native
  context, for interoperating with other implementations
  ([#1](https://github.com/AnimeshShaw/quantum-safe-py/issues/1),
  [#2](https://github.com/AnimeshShaw/quantum-safe-py/issues/2)).
- liboqs licence text and third-party notices inside the wheels.

## Next: 0.4.0 (the breaking release)

The theme is "make the safe thing the only thing".

- **`verify(context=...)` and `Envelope.open(expected_aad=...)` become required.** Omitting them
  has warned since 0.3.1.
- **The default hybrid signature suite becomes `Ed25519+ML-DSA-65-v2`** (no prefix, native
  FIPS 204 context). New signatures from the default will not verify on 0.3.0 and earlier, so this
  is announced first; existing signatures and the old suite keep working when named explicitly.
- Benchmarks and timing-leakage figures **re-measured** with raw samples published, on more than
  one machine. The 0.3.0 decapsulation row is known to be wrong (it measured the
  implicit-rejection path); it is flagged now and will be replaced.
- An **independent review** of the `-v2` signature format and the streaming construction. We say
  "not independently reviewed" until this happens.
- Matching release of [quantum-safe-ts](https://github.com/AnimeshShaw/quantum-safe-ts) so both
  libraries change defaults together.

## Later (no release assigned)

- `StandardJwt` private keys (RFC 9964 stores a seed). Waiting for seeded ML-DSA key generation
  in liboqs.
- P-384 hybrids (`P-384+ML-KEM-1024`, `P-384+ML-DSA-87`). Only worth building if someone needs the
  TLS `SecP384r1MLKEM1024` group; NSA's CNSA 2.0 FAQ does not make any hybrid compliant, so it
  would still report `PARTIAL`.
- XMSS next to the existing LMS support (SP 800-208).
- More key-management examples (KMS and HSM wrappers) in the cookbook.
- A published artifact record for each release (DOI) and a reproducible build recipe for the
  vendored liboqs.

## What would make it 1.0

1.0 means the API and formats are stable and we will not break them without a major version.
We will not call it 1.0 before:

1. the 0.4.0 breaking changes have shipped and settled for at least one release cycle;
2. the signature and envelope formats have had an independent cryptographic review;
3. the benchmarks and leakage figures are re-measured and reproducible from published data;
4. the documentation and the TypeScript library are in step.

## What this library will not become

- A FIPS 140-3 validated module. It uses liboqs and says so; validation is a property of a
  module and a laboratory, not of a Python package.
- A replacement for a TLS stack. It helps build hybrid protocols; it does not implement TLS.

## Suggest or vote

Open an [issue](https://github.com/AnimeshShaw/quantum-safe-py/issues). Security reports go through
the private channel in [SECURITY.md](SECURITY.md), not a public issue.
