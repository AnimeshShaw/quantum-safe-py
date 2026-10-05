# Changelog

All notable changes to quantum-safe are documented here.

## [Unreleased]

### Benchmarks

- Re-measured with raw samples: the ENV-2 and ENV-1 runs and the two-class leakage screen are in `results/` (see `results/README.md`). `--iterations` is now honoured by `bench_kem.py` and `bench_signatures.py` (it was parsed and ignored, so every earlier "3,000 iterations" table was measured with 1,000), the harnesses save every timed sample and the run environment, and `tests/bench/paper_numbers.py` computes every figure the papers print from those files. New: `bench_gil.py` (thread-scaling test with a pure-Python negative control), `aggregate_runs.py`, `run_env1.sh`, `run_env2.sh`.
- The Docker benchmark image builds again (the 0.3.2 licence files had not been copied into it) and has a `.dockerignore`.

## [0.3.2] - 2026-10-05

### Fixed

- **`Sign.verify_raw()` now verifies standard FIPS 204 ML-DSA signatures.** It verified `len(context) || context || message` under an empty FIPS 204 context, so it rejected every signature made by another implementation, empty context included, although it was documented for exactly that. It now passes the message and the context to ML-DSA.Verify natively. **Behaviour change:** it no longer verifies the raw part of a `Sign.sign()` signature (that signs a different byte string); use `verify()` for those. Reported in GitHub issues #1 and #2.

### Added

- `Sign.sign_raw()`: standard FIPS 204 `ML-DSA.Sign` with a native context and FIPS 204's own hedged randomness; returns the bare signature. Tested in both directions against liboqs's FIPS 204 interface for ML-DSA-44/65/87 with empty, short and 255-byte contexts.

### Packaging

- The wheels now carry the liboqs licence text (`quantum_safe/_licenses/liboqs-LICENSE.txt`) and `THIRD_PARTY_LICENSES.md`. The compiled liboqs they bundle is MIT-licensed and the licence requires its notice to travel with it; 0.3.1 and earlier did not include it. `licenses/liboqs-LICENSE.txt` is a verbatim copy of upstream's `LICENSE.txt`.

### Documentation

- The `Sign` documentation says plainly that `sign()`, its hedging prefix and its context prefix are the library's own construction, not the FIPS 204 interface, and points to `sign_raw` / `verify_raw` for interoperability.

## [0.3.1] - 2026-10-05

### Security

- **High: signature prefix forgery, present in every release up to and including 0.3.0** (CWE-347). In hedged mode (the default) the signed bytes are `prefix || message` and the blob stored `len(prefix) || prefix || signature`, but the length byte is not signed and the verifier trusted it. Whoever supplied a signed message could move bytes between message and prefix, so a signature on `M` also verified on a suffix of `M`, without the key (`PAY alice 5 USD
PAY mallory 1000000 USD
` verified as `PAY mallory 1000000 USD
`). Fixed: the verifier requires the prefix length of its own hedging mode. See `docs/guides/security.rst` and `tests/security/`. **Upgrade; 0.1.0, 0.2.1 and 0.3.0 on PyPI are affected.** The `-v2` format has no prefix at all.
- Five further issues of lower severity (S2 to S6: context taken from the message, loose hybrid payloads, loose key loaders, untyped parse errors, AAD not checked by the opener) are listed under Fixed and Added below.

### ⚠ Changed behaviour

- **Signatures made with `hedged=False` now need a verifier built with
  `hedged=False`.** This applies to `Sign`, `HybridSign`, `JWTVerifier` and
  `HybridCertificateBuilder.verify_cosig` (the last two gain a `hedged`
  argument, default `True`, for tokens and co-signatures made with a
  `hedged=False` signer). Hedged signatures, the
  default, are unaffected. Nothing is re-encoded: every signature 0.3.0
  wrote still verifies on a verifier in the matching mode.
- **CNSA 2.0: `cnsa2.report()` and `qs-audit cnsa2` now report X25519,
  P-256 and Ed25519 hybrids as `PARTIAL`, not compliant.** NSA's CNSA 2.0 FAQ
  (Dec 2024, Ver. 2.1) says hybrid products are not required and that a
  hybrid should not be used on NSS mission systems except for exceptions NSA
  specifically recommends (it names IKEv2). Every hybrid, including one with
  a P-384 classical half, is therefore `PARTIAL`. Standalone ML-KEM-1024 / ML-DSA-87 are the
  compliant choice; use the new `cnsa2.pqc_kem()` / `cnsa2.pqc_sign()`.
  `cnsa2.enforce()` is unchanged for these hybrids by default (it guards the
  post-quantum parameter set, as in quantum-safe-ts); pass `strict=True` to
  refuse anything `report()` does not call compliant.

### Fixed

- The registry listed `BIKE-L1`'s secret key as 3114 bytes; liboqs produces 5223. Found by the registry-size test on a liboqs build that enables BIKE.
- Signature verification now requires the signature prefix length to match
  the verifier's hedging mode (`hedged=True`, the default: 32 bytes;
  `hedged=False`: 0). Previously the length was read from the signature
  blob, where it is not covered by the signature. Use one hedging mode per
  key.
- Hybrid signature payloads must contain exactly the four documented
  entries, with the documented types, no duplicate keys and no trailing
  bytes, and their algorithm names must match the verifier's components.
  Previously extra entries were ignored, so different byte strings verified
  as the same signature.
- Key loaders require the key-type tag (`ktype`) and that it matches the
  loader (`"pub"` for `PublicKey`, `"sec"` for `SecretKey`, in CBOR, PEM and
  bundles), require `kty: "AKP"` for JWKs, and require the version to be an
  integer (`v: true` is no longer read as version 1). Every key this library
  has written carries these fields.
- Malformed keys (CBOR, PEM, JWK, bundles), signed messages and sealed
  messages raise `KeyParseError` instead of `AttributeError`, `TypeError`,
  `KeyError` or `IndexError`. Field types are checked rather than coerced:
  previously an integer `msg` or `kct` was silently read as that many zero
  bytes, and `SignedMessage` and `SealedMessage` accepted a non-integer
  version.
- ML-DSA sizes reported by the algorithm registry and both backends were
  round-3 Dilithium sizes, not FIPS 204's: secret keys are 2560 / 4032 / 4896
  bytes (ML-DSA-44 / 65 / 87) and signatures 2420 / 3309 / 4627 bytes. Keys
  and signatures themselves were always correct (they come from liboqs);
  only the reported numbers were wrong.
- CNSA 2.0 checks validate the whole algorithm name: a hybrid with an
  unrecognised classical half (e.g. `RSA-1024+ML-DSA-87`) is no longer
  reported compliant. `P-384` is removed from `CNSA2_HYBRID_CLASSICAL`
  because `HybridKEM` does not implement it. `cnsa2.describe()` no longer
  says LMS is unimplemented.
- `Upgrader` no longer reports `backward_compat=True`. The upgraded key is
  `u16(len(classical)) || classical || pqc`, which classical-only software
  cannot parse; the original key is retained inside it, and classical-only
  clients keep using the original key. Documentation that said old X25519
  senders could still encrypt to the upgraded key is corrected.

### Added

- **Compare-and-set migration store.** `MigrationStateManager` accepts a store with `compare_and_set(key, expected, value) -> bool` and then commits each transition through one atomic operation on the `<id>_history` entry, so it is safe across processes and hosts with no external lock: exactly one concurrent writer wins and the others get the stale-state `ValueError`. The layout is unchanged (`_current` and `_history`); in this mode the history is authoritative and `_current` is a derived copy, so a crash between the two leaves `_current` one record behind and the manager reads the history. New `MemoryMigrationStore` (a dict with an atomic `compare_and_set`) and `MigrationStateManager.cross_process_safe`. In a test with 16 managers racing on one store, every one of 300 races produced more than one winner on a plain dict and none did with compare-and-set. A plain dict still works as before, with in-process locking only.
- **Leakage harness controls** (`tests/bench/bench_leakage.py`): a *positive control* (a real decapsulation plus a deliberate secret-dependent delay at several magnitudes, on a random-vs-random baseline, with a 0 µs zero point that must not be flagged) that reports the smallest leak the harness detects, and two *public-data calibrations* that hold the secret fixed or involve no secret at all (same key with fixed vs fresh ciphertext; encapsulation with a fixed vs fresh public key). On the development host at 20,000 iterations, a mean difference of about 1 µs (a 2 µs delay on half the keys, ~7% of the operation) is detected; and the encapsulation calibration, which involves no secret, reproduces the fixed-vs-random decapsulation signal (|t| 15-23 against 21-43), so that signal is not secret dependence. The harness output no longer asserts a mechanism for the signal.
- **`StandardJwt` (RFC 9964):** ML-DSA JWTs that any compliant JOSE library can verify: `{"alg": "ML-DSA-65", "typ": "JWT"}` header, raw FIPS 204 signature over `header.payload` with an empty context, `AKP` public JWK; strict verification (algorithm must match the key, `crit` refused, canonical base64url signature). Pure ML-DSA only. Verified against quantum-safe-ts's `StandardJwt` in both directions for ML-DSA-44/65/87. Private AKP JWKs (RFC 9964's `priv` is a seed) are not supported because liboqs cannot derive a key pair from a seed. Existing `JWTSigner` tokens are unchanged and still verify only with quantum-safe.
- **Signature format `-v2`** (`Sign("ML-DSA-65-v2")`, `HybridSign("Ed25519", "ML-DSA-65-v2")`): no prefix or prefix length; the ML-DSA half is plain FIPS 204 with the native context `quantum-safe-sig-v2` over `M2 = len(algo)||algo||len(ctx)||ctx||message`; the classical half signs a labelled `M2` (Ed25519, or raw low-S ECDSA P-256); a hybrid blob is exactly `classical(64) || ML-DSA`. The durable fix for the prefix construction behind the S1 forgery. Byte-compatible with quantum-safe-ts: all eight v2 identifiers verified in both directions. Not the default in this release; versions before this one cannot read it. Adds `sign_native_context` / `verify_native_context` to the backend interface (liboqs implements them).
- **Envelope v2, the CNSA 2.0 profile:** `Envelope.seal()` of a pure `ML-KEM-1024` public key (no `kem=`) produces a version-2 envelope whose AES-256-GCM key is derived with HKDF-SHA-384 (info `qs-envelope-enc-v2-cnsa2`); hybrid keys still produce version-1 envelopes (HKDF-SHA-256), unchanged. Same bytes as quantum-safe-ts's envelope v2, checked in both directions. `Envelope.open()` now requires the envelope version to match its algorithm (a relabelled version is refused with `UnsupportedAlgorithm`). `SharedSecret.derive_key()` gains `hash_algorithm` (`SHA-256` default, `SHA-384`, `SHA-512`).
- `Envelope.open(..., expected_aad=...)`: the opener states the AAD it expects and the message's AAD must equal it, otherwise `InvalidTag` is raised. Anyone holding a recipient's public key can seal a message with any AAD and the AAD travels inside the message, so a message sealed for one user opened in another's context. Omitting it while the message carries AAD emits a `DeprecationWarning`; it will be required (default `b""`) in the next minor release. Mirrors `expectedAad` in quantum-safe-ts.
- A missing `cbor2` now raises `ImportError` at import instead of silently switching to a JSON+base64 format that no CBOR reader (including another installation of this library and quantum-safe-ts) can read. The fallback is removed.
- `cnsa2.pqc_kem()` and `cnsa2.pqc_sign()`: standalone ML-KEM-1024 and
  ML-DSA-87, the CNSA 2.0-compliant configurations.
- `cnsa2.report()` gains a key-derivation row (`check_key_derivation`, `include_key_derivation=`): this library's hybrid combiner and v1 envelopes derive keys with HKDF-SHA-256, below the SHA-384/512 CNSA 2.0 requires; a pure ML-KEM-1024 envelope (v2) uses HKDF-SHA-384. Matches quantum-safe-ts. `enforce()` is unaffected.
- `cnsa2.enforce(..., strict=True)`: also refuse configurations that
  `report()` calls `PARTIAL`, for use as a CI gate.
- `Sign.verify(..., context=...)` and `HybridSign.verify(..., context=...)`:
  the verifier states the context it expects, and a message carrying any
  other context is rejected (constant-time comparison). The context stored
  in a `SignedMessage` is supplied by whoever supplies the message, so
  without this a signature made for one purpose verified for another.
  `JWTVerifier` and `HybridCertificateBuilder.verify_cosig` now pass their
  own context instead of reading it from the token or bundle.

### Documentation and packaging

- Six new guides (upgrading, choosing, cookbook, interoperability, CNSA 2.0 and standards, security model); every Python block in them is executed by `tests/unit/test_docs_examples.py`. README: what's new, a documentation map, corrected thread-safety, hedging and timing text.
- `NOTICE` and `THIRD_PARTY_LICENSES.md` (the wheels bundle liboqs); `SECURITY.md` updated (supported versions, private reporting, both audits, no independent review).
- `CITATION.cff` points at arXiv:2605.17061.
- The README and benchmark text no longer present the 0.3.0 ML-KEM-768 decapsulation latency and CoV figures as normal-path measurements: the old harness shared one liboqs object, so decapsulation exercised the implicit-rejection path. The harness is fixed; the figures are being re-measured.

### Changed

- Without a compare-and-set store, `MigrationStateManager.transition()` now writes `<id>_history` before `<id>_current` (it was the reverse), so a crash between the two leaves `_current` behind the audit log instead of the log behind the state. No format change.

### Deprecated

- Calling `verify()` without `context=` emits a `DeprecationWarning`. It
  will be required (default `b""`) in the next minor release.

## [0.3.0] - 2026-09-28

### ⚠ Breaking

- **`SLH-DSA-*` algorithm names now resolve to FIPS 205, not pre-standard
  SPHINCS+.** They previously mapped to liboqs' `SPHINCS+-...-simple`
  mechanisms (the round-3 submission), while the algorithm registry marked
  them `is_nist_standard=True`. The two share key and signature sizes, so
  the substitution was invisible from lengths — confirmed by
  cross-verification that they are not interchangeable: a signature made
  under one does not verify under the other. **Any signature produced under
  the old `SLH-DSA-*` names in 0.2.x will not verify against 0.3.0.**
  Round-3 SPHINCS+ remains available under explicit `SPHINCS+-*` names, so
  it can no longer masquerade as a standard.

### Added

- **LMS stateful signatures** (RFC 8554) via the optional `[lms]` extra
  (`pip install 'quantum-safe-py[lms]'`), wrapping `pyhsslms` (maintained by
  an RFC 8554 co-author). LMS is stateful and fails catastrophically on
  one-time-key reuse — confirmed directly that restoring a stale snapshot
  rewinds the signing index and that two different messages signed at the
  rewound index both verify. The wrapper write-ahead reserves each index
  through a caller-supplied durable store *before* releasing a signature,
  and refuses a key presented at an already-issued index. See
  `quantum_safe.signatures.stateful`.
- **CNSA 2.0 compliance profile** (`quantum_safe.compliance.cnsa2`): reports
  or enforces the CNSA 2.0 mandated parameter sets (ML-KEM-1024, ML-DSA-87,
  SHA-384/512). This library's own defaults (ML-KEM-768, ML-DSA-65) are
  below the suite; `cnsa2.hybrid_kem()` / `cnsa2.hybrid_sign()` give a
  compliant configuration in one call. New `qs-audit cnsa2` CLI command.
- **CycloneDX 1.6 Cryptographic Bill of Materials** (`quantum_safe.audit.cbom`):
  emits `cryptographic-asset` components with OIDs and NIST quantum security
  levels, separating detected classical algorithms (file:line per
  occurrence) from post-quantum algorithms available to migrate to. New
  `qs-audit cbom` CLI command.
- **ACVP known-answer conformance testing** against NIST-published vectors
  (`tests/conformance/acvp_kat.py`), pinned to an upstream commit for
  reproducibility, wired into CI. 225/225 runnable cases pass: ML-KEM keyGen
  75/75 (seeded from the 64-byte `d‖z`), ML-KEM encapsulation 75/75 (via
  `OQS_KEM_encaps_derand` through ctypes, since the high-level binding can't
  accept ACVP-supplied randomness), ML-KEM decapsulation 30/30 (including
  implicit-rejection cases), ML-DSA sigVer 45/45 (both acceptance and
  rejection cases). Explicitly documented as conformance evidence, not a
  CAVP or CMVP validation.
- **Two-class timing-leakage harness** (`tests/bench/bench_leakage.py`):
  fixed-vs-random testing per operation, with a random-vs-random control
  in addition to the usual fixed-vs-fixed one. Without the second control
  this harness reports a stable false positive (|t| up to 39) on ML-KEM
  decapsulation, tracking the fixed class re-executing on byte-identical
  inputs rather than key material — the finding is documented in the
  companion timing-leakage paper.
- **Externally-derived production-readiness rubric**
  (`docs/production_readiness_rubric.md`): nine dimensions anchored to
  CNSA 2.0, CMVP, the TNO CADI market survey, and the IETF hybrid draft,
  applied to a September 2026 audit of nine PQC libraries. Three
  self-selected dimensions from an earlier version had no external anchor
  and are dropped. The audit scores this library below Bouncy Castle on
  stateful signing and conformance evidence, and below its own CNSA 2.0
  parameter sets on its own defaults.

### Fixed

- Benchmark harness (`bench_kem.py`, `bench_signatures.py`) shared one
  liboqs object across keygen, encapsulate, and decapsulate measurements.
  `generate_keypair()` overwrites the object's stored secret key, so the
  decapsulate benchmark silently measured the FIPS 203 implicit-rejection
  path rather than normal decapsulation. Each operation now gets its own
  object, with assertions pinning the success path.
- `Dockerfile` never copied `hatch_build.py`, which `pyproject.toml`
  registers as a required build hook, so the reproducibility image could
  not be built at all.

### Changed

- Benchmark run-selection rule: best-of-3 to median-of-3. Best-of-3 ran
  8.0% optimistic on average across 33 operations (range 0.4%–21.8%); the
  full hybrid handshake headline figure moves 243.26 → 245.55 µs (+0.94%).

## [0.2.1] - 2026-09-05

### Packaging

- **PyPI publishing fixed**: the 0.2.0 tag's release workflow built and
  smoke-tested wheels for all three platforms successfully, but the publish
  step failed — PyPI Trusted Publishing (OIDC) was never configured for this
  repo, so the token exchange was rejected. 0.2.0 was never actually uploaded.
  The workflow now publishes via a `PYPI_API_TOKEN` repository secret instead.

## [0.2.0] - 2026-09-04

### Packaging

- **Vendored liboqs binary for the `[liboqs]` extra** (`hatch_build.py`,
  `pyproject.toml`, `backends/liboqs.py`): released wheels for Linux x86_64,
  Windows x64, and macOS arm64 (14+) now bundle a precompiled liboqs binary,
  built via a `cibuildwheel` CI matrix. `pip install
  'quantum-safe-py[liboqs]'` no longer requires `git`/`CMake`/a C compiler on
  those platforms — `_import_oqs()` points `OQS_INSTALL_PATH` at the bundled
  binary before `liboqs-python` gets a chance to fall back to its normal
  build-from-source path. Other platforms/architectures are unaffected and
  keep the previous build-from-source behavior.
- Corrected documentation (`README.md`, `docs/guides/installation.rst`, the
  `backends/liboqs` module docstring) that had previously and incorrectly
  claimed `liboqs-python` itself vendors a prebuilt binary — it doesn't; the
  above is what actually makes that true now, and only for the platforms
  listed.

### Security

A comprehensive cryptographic security audit (14 findings) was performed against
v0.1.0 source.  All findings have been remediated in this release.

#### HIGH severity

- **Memory zeroization hardened** (`types/keys.py`, `types/kem.py`):
  `_ZeroizingBytes.__del__` and `SharedSecret.__del__` now use `ctypes.memset`
  against the live `bytearray` buffer instead of a Python byte-loop.  The Python
  optimizer can elide dead stores; `ctypes.memset` operates at the C level and
  cannot be optimized away.

- **`SecretKey._raw_bytearray` property added** (`types/keys.py`):
  Callers that need a mutable copy they can zero after use (e.g. backends passing
  key material to C libraries) now have a first-class way to obtain one.  The
  property documents the zero-after-use pattern with `ctypes.memset`.

- **Version rollback rejected** (`types/keys.py`):
  Deserialized CBOR key payloads with `version < 1` are now rejected with
  `KeyParseError`.  Previously an attacker who could tamper with stored key
  material could downgrade the version field to bypass future format hardening.

#### MEDIUM severity

- **Serialization payload size cap** (`_internal/serialization.py`):
  `loads()` now rejects payloads larger than 10 MB in both the cbor2 and JSON
  fallback paths, guarding against memory-exhaustion via deeply nested or padded
  structures.

- **P-256 ECDH output length guard** (`kem/hybrid.py`):
  `_encapsulate_classical` and `_decapsulate_classical` now assert the P-256 ECDH
  output is at least 32 bytes before passing it to the HKDF combiner.

- **liboqs secret key local copy zeroed** (`backends/liboqs.py`):
  `LiboqsKEMBackend.decapsulate` and `LiboqsSignatureBackend.sign` convert the
  incoming `bytes` to a `bytearray`, pass the bytes view to the C library, and
  zero the local copy in a `finally` block via `ctypes.memset`.

- **Public key size validation** (`types/keys.py`):
  `PublicKey.__init__` now validates the raw byte length against known FIPS sizes
  for all non-hybrid algorithms (ML-KEM-512/768/1024, ML-DSA-44/65/87,
  SLH-DSA variants).  This prevents key-type confusion attacks where, for example,
  ML-DSA bytes are accepted as an ML-KEM public key.

- **Migration state manager is thread-safe** (`migrate/state.py`):
  `MigrationStateManager.transition()` now holds a per-key `threading.Lock` across
  the read-check-write critical section, eliminating the TOCTOU race that could
  allow two concurrent callers to both observe the same current state and both
  commit conflicting transitions.

- **Hybrid signature verification is timing-safe** (`signatures/hybrid.py`):
  `HybridSign.verify()` previously returned early after the classical sub-signature
  failed, creating a timing oracle that revealed which component was invalid.
  Both sub-signatures are now verified unconditionally before the combined result
  is checked.

- **`HybridSign` constructor bypass removed** (`protocols/jwt.py`, `protocols/x509.py`):
  `JWTSigner`, `JWTVerifier`, and `HybridCertificateBuilder` were constructing
  `HybridSign` via `__new__` plus manual attribute assignment, bypassing
  `validate_hybrid_combination()`.  All three now use the normal constructor.

#### LOW severity

- **`PublicKey.__repr__` fingerprint cached** (`types/keys.py`):
  `_cached_fp` slot added; SHA-256 is computed once and cached, preventing
  repeated full-key hashing on every repr call (e.g. in log-heavy environments).

- **`generate_nonce()` warns on short nonces** (`types/keys.py`):
  Nonces shorter than 12 bytes now emit a `UserWarning` pointing to the 12-byte
  AEAD minimum (e.g. AES-GCM).

- **Hash-pinning documentation added** (`pyproject.toml`):
  A comment block above the liboqs optional dependency explains how to generate
  a hash-pinned `requirements.txt` for production installs.

- **liboqs-python upper version bound** (`pyproject.toml`):
  `liboqs-python` is now pinned to `>=0.10.0,<0.12` to prevent silent breakage
  if the upstream package makes incompatible API changes in a future minor release.

---

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

- `Scanner` — AST-based classical crypto detector (14 rules covering `cryptography`, `pycryptodome`, and stdlib `hashlib`; SARIF output)
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
