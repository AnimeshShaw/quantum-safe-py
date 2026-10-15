# Roadmap

What is planned for quantum-safe-py, in priority order. These are intentions, not promises:
there are no dates, the order can change, and anything here can be dropped. Shipped changes
are in [CHANGELOG.md](CHANGELOG.md). Progress is tracked in the
[milestones](https://github.com/AnimeshShaw/quantum-safe-py/milestones).

While the version starts with `0.`, a **minor** release (0.3 to 0.4) is where behaviour changes
happen, each with a changelog entry and an [upgrade guide](docs/guides/upgrading-0.4.rst). A patch
release (0.3.1 to 0.3.2) does not break correct code.

## Now: 0.4.0 (paired with quantum-safe-ts 0.2.0)

The theme is "make the safe thing the only thing", and the two libraries change defaults together.

- **Defaults.** The default hybrid signature suite is `Ed25519+ML-DSA-65-v2` (no prefix, native
  FIPS 204 context); the old suite keeps working when named. An omitted `context` means "expect an
  empty context" and an omitted `expected_aad` accepts any AAD; both emit a once-per-call-site
  warning that can be silenced.
- **Same bytes as TypeScript.** X-Wing, streaming envelopes (format v3), COSE_Sign1 and private
  JWKs for ML-DSA (RFC 9964), all twelve SLH-DSA parameter sets, and a cross-process migration store,
  each checked against quantum-safe-ts in both directions.
- **An optional `cryptography` backend** (`[pyca]`): ML-KEM and ML-DSA with seed keys and no
  compiler; `Sign.keypair_from_seed()` and `export_seed()`.
- **liboqs 0.16.0** vendored, with the pairing checked at build and import time.
- **638 NIST ACVP known-answer cases** run, including SLH-DSA verification and ML-DSA key generation.

## Next

- **Benchmarks and timing-leakage figures re-measured** on the liboqs 0.16.0 pair, with raw samples
  published, on more than one machine
  ([#5](https://github.com/AnimeshShaw/quantum-safe-py/issues/5)).
- **Envelope and key re-wrap**: open under the old key, seal to the new hybrid key, keep the AAD;
  then a resumable bulk driver on the migration state manager, a verification report, and migration
  status in the CBOM.
- **A Rust sibling**: publish the shared core as a crate, with the same vectors in its CI.

## Later (no release assigned)

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

1. the 0.4.0 changes have shipped and settled for at least one release cycle;
2. the benchmarks and leakage figures are re-measured and reproducible from published data;
3. the documentation and the TypeScript library are in step.

## What this library will not become

- A replacement for a TLS stack. It helps build hybrid protocols; it does not implement TLS.

## Suggest or vote

Open an [issue](https://github.com/AnimeshShaw/quantum-safe-py/issues). Security reports go through
the private channel in [SECURITY.md](SECURITY.md), not a public issue.
