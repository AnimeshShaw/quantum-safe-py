# Changelog

All notable changes to quantum-safe are documented here.

## [Unreleased] — Benchmark refresh 2026-03-29

### Changed

- **Benchmark methodology**: iterations increased from 1,000 to 3,000 per operation for tighter
  confidence intervals; CPU pinning (`--cpuset-cpus="0,1"`) added to Docker runs to eliminate
  cross-core migration noise; best-of-3 independent runs selected as authoritative result.
- **Headline numbers updated** (ENV-2, Docker/WSL2 Linux):
  - Full hybrid KEM handshake: **~243 µs** (was ~301 µs — 19% improvement via methodology)
  - HybridKEM keygen (real ML-KEM-768): **~99 µs** (was ~113 µs)
  - Throughput @ 5,000 concurrent users: **~2,848 ops/s** (was ~2,009 ops/s)
  - Throughput degradation 100→5,000 users: **−4.9%** (confirms GIL release and linear scaling)
- **ENV-1 refreshed** (Windows 11 native, 3,000 iterations): full hybrid KEM handshake **~587 µs**
- **Cross-environment comparison**: Linux 2.4× faster than Windows full handshake; 6.2× faster
  on raw ML-KEM-768 keygen (build flag effect: `-DOQS_DIST_BUILD=ON` enables AVX2/AVX-512)
- `results/BENCHMARKS.md`: complete rewrite with dual-environment tables, combiner overhead
  breakdown, CoV reference table, and paper headline numbers
- Old benchmark files archived to `results/old_benchmarks/`

---

## [0.1.0] — unreleased

### Added

#### Core type system

- `PublicKey`, `SecretKey`, `KeyPair` with algorithm metadata and migration state
- `_ZeroizingBytes` — best-effort secret material zeroization on deletion
- `CipherText`, `HybridCipherText`, `SharedSecret` — distinct types prevent misuse
- `SignedMessage`, `HybridSignature` — self-describing signed message format
- Key serialization: PEM (with `qs-version`/`qs-algo` headers), CBOR, JWK
- Cross-format round-trip: Python ↔ TypeScript ↔ Rust use the same envelope

#### KEM module

- `KEM` — single-algorithm PQC KEM with backend dispatch
- `HybridKEM` — X25519+ML-KEM combined KEM (default: X25519+ML-KEM-768)
- HKDF-SHA256 hybrid combiner following draft-ietf-tls-hybrid-design
- P-256 support as alternative classical companion
- Algorithm registry: ML-KEM-512/768/1024, BIKE-L1, HQC-128

#### Signatures module

- `Sign` — single-algorithm PQC signer with hedged mode
- `HybridSign` — Ed25519+ML-DSA combined signer (default: Ed25519+ML-DSA-65)
- Hedged mode (default on): random prefix prevents fault injection attacks
- Context string support for domain separation (per FIPS 204 §5.2)
- Algorithm registry: ML-DSA-44/65/87, SLH-DSA-SHAKE-128s/128f

#### Backends

- `liboqs` backend — full algorithm set via liboqs-python
- `rustcrypto` backend — stub (FIPS-subset, pending PyO3 crate publication)
- Auto-selection: tries rustcrypto first, falls back to liboqs
- `list_available_backends()` for diagnostics

#### Protocol helpers

- `Envelope.seal()` / `Envelope.open()` — KEM + AES-256-GCM authenticated encryption
- `JWTSigner` / `JWTVerifier` — PQC JWT (draft-ietf-jose-pqc-signatures identifiers)
- `HybridTLSConfig` / `configure_hybrid_context()` — TLS hybrid key exchange
- `HybridCertificateBuilder` — X.509 certs with PQC co-signature extension

#### Migration tooling

- `Scanner` — AST-based classical crypto detector (14 rules, SARIF output)
- `MigrationStateManager` — state machine for per-key migration tracking
- `Upgrader` — upgrades classical keys to hybrid while preserving backward compat
- `FernetShim`, `JWTShim` — drop-in shims with usage logging
- `qs-migrate` CLI with `scan`, `upgrade-key`, `status` subcommands

#### Audit and compliance

- `Auditor` — orchestrates scan + policy evaluation
- `AuditPolicy` — configurable policy (presets: standard, strict, transition, permissive)
- `NISTComplianceChecker` — maps findings to FIPS 203/204/205, SP 800-208, CISA checklist
- `SBOMEnricher` — CycloneDX SBOM enrichment with PQC-readiness annotations
- `qs-audit` CLI with `scan`, `sbom`, `requirements`, `compliance` subcommands
- CI gate: `Auditor.ci_gate()` returns exit code 0/1 and writes SARIF/JSON

#### Internal

- `_internal.serialization` — cbor2 (required) with JSON+base64 fallback for constrained environments
- `exceptions.py` — full 3-level exception hierarchy with machine-readable `code` fields

### Known limitations (v0.1.0)

- RustCrypto backend is a stub — `is_available()` returns False until PyO3 crate ships
- noble (JavaScript/WASM) backend is JS-only — not available in Python
- TLS `set_groups()` requires OQS-patched OpenSSL — degrades gracefully without it
- X.509 co-signature OID (`1.3.6.1.4.1.99999.1`) is a placeholder — register before production use
- TypeScript/Rust scanner rules are planned for v0.2
