Unreleased
----------

Changed behaviour
~~~~~~~~~~~~~~~~~

- **Signatures made with** ``hedged=False`` **now need a verifier built with**
  ``hedged=False``. This applies to ``Sign``, ``HybridSign``, ``JWTVerifier``
  and ``HybridCertificateBuilder.verify_cosig`` (the last two gain a
  ``hedged`` argument, default ``True``). Hedged signatures, the default, are
  unaffected, and nothing is re-encoded: every signature 0.3.0 wrote still
  verifies on a verifier in the matching mode.
- **CNSA 2.0:** ``cnsa2.report()`` and ``qs-audit cnsa2`` report X25519, P-256
  and Ed25519 hybrids as ``PARTIAL``, not compliant. CNSA 2.0 makes hybrid
  optional and requires a hybrid's classical half to be CNSA 1.0 (P-384).
  Use ``cnsa2.pqc_kem()`` / ``cnsa2.pqc_sign()`` for a compliant
  configuration. ``cnsa2.enforce()`` still guards the post-quantum parameter
  set by default; ``strict=True`` also refuses ``PARTIAL``.

Fixed
~~~~~

- The signature prefix length must match the verifier's hedging mode (32 bytes
  hedged, 0 unhedged). It was read from the signature blob, where it is not
  covered by the signature, so bytes could be moved between prefix and
  message to forge a signature on a different message.
- Hybrid signature payloads must be exactly the four documented entries with
  the documented types, no duplicate keys or trailing bytes, and algorithm
  names matching the verifier.
- Key loaders require ``ktype`` (matching the loader), ``kty: "AKP"`` for JWKs
  and an integer version.
- Malformed keys, signed messages and sealed messages raise ``KeyParseError``
  instead of ``AttributeError`` / ``TypeError`` / ``KeyError`` /
  ``IndexError``, and wrong-typed fields are rejected rather than coerced.
- ML-DSA sizes reported by the registry and backends are FIPS 204's (secret
  keys 2560 / 4032 / 4896, signatures 2420 / 3309 / 4627 bytes); they were
  round-3 Dilithium sizes. Keys and signatures were always correct.
- CNSA 2.0 checks validate the whole algorithm name (``RSA-1024+ML-DSA-87`` is
  no longer compliant); ``P-384`` is removed from ``CNSA2_HYBRID_CLASSICAL``.
- ``Upgrader`` reports ``backward_compat=False``: classical-only software
  cannot parse the upgraded key and keeps using the original.
- Documentation: the context is a message prefix, not FIPS 204's native
  context; the hybrid combiner is library-specific, not TLS's; JWTs verify
  only with quantum-safe; cbor2 is required and the JSON fallback is not
  portable; envelope AAD is not compared on open; migration-store
  concurrency and durability limits.

Added
~~~~~

- ``verify(..., context=...)`` on ``Sign`` and ``HybridSign``: the verifier
  states the context it expects (constant-time comparison).
- ``Envelope.open(..., expected_aad=...)``: the opener states the AAD it expects
  (otherwise ``InvalidTag``). A message sealed for one context no longer opens
  in another. Omitting it while the message carries AAD emits a
  ``DeprecationWarning``.
- ``cnsa2.pqc_kem()``, ``cnsa2.pqc_sign()`` and ``cnsa2.enforce(strict=True)``.
- Interoperability tests against data written by quantum-safe-ts.

Deprecated
~~~~~~~~~~

- ``verify()`` without ``context=`` emits a ``DeprecationWarning``; it will be
  required (default ``b""``) in the next minor release.

0.3.0
-----

Added
~~~~~

- **LMS stateful signatures** (RFC 8554) via the optional ``[lms]`` extra,
  wrapping ``pyhsslms``. Write-ahead index reservation through a
  caller-supplied durable store, refusing a key presented at an
  already-issued index -- built after confirming directly that a naive
  restore-from-snapshot rewinds the index and produces two verifying
  signatures at one index.
- **CNSA 2.0 compliance profile** (``quantum_safe.compliance.cnsa2``):
  reports or enforces the CNSA 2.0 mandated parameter sets (ML-KEM-1024,
  ML-DSA-87, SHA-384/512). ``qs-audit cnsa2`` CLI command.
- **CycloneDX 1.6 Cryptographic Bill of Materials** (``quantum_safe.audit.cbom``).
  ``qs-audit cbom`` CLI command.
- **ACVP known-answer conformance testing** against NIST-published vectors
  (``tests/conformance/acvp_kat.py``), wired into CI. 225/225 runnable cases
  pass: ML-KEM keyGen, encapsulation, decapsulation, and ML-DSA sigVer.
  Explicitly not a CAVP/CMVP validation.
- **Two-class timing-leakage harness** (``tests/bench/bench_leakage.py``),
  replacing CoV as the tool for the secret-dependence question. Requires a
  random-vs-random control in addition to the usual fixed-vs-fixed one --
  without it the harness reports a stable false positive on this project's
  own hardware.
- Externally-derived production-readiness rubric
  (``docs/production_readiness_rubric.md``), re-auditing nine PQC libraries
  against nine dimensions anchored to CNSA 2.0, CMVP, the TNO CADI market
  survey, and the IETF hybrid draft.

Fixed
~~~~~

- **Breaking**: ``SLH-DSA-*`` algorithm names previously resolved to liboqs'
  pre-standard round-3 ``SPHINCS+-...-simple`` mechanisms rather than FIPS 205.
  Signatures made under the old mapping do not verify against the corrected
  one. Confirmed non-interchangeable by cross-verification.
- Benchmark harness shared one liboqs object across keygen, encapsulate, and
  decapsulate measurements; ``generate_keypair()`` overwrote the stored
  secret key, so the decapsulate benchmark silently measured the FIPS 203
  implicit-rejection path rather than normal decapsulation.
- ``Dockerfile`` never copied ``hatch_build.py``, so the reproducibility
  image could not build at all.

Changed
~~~~~~~

- Benchmark run selection: best-of-3 to median-of-3 (best-of-3 ran 8.0%
  optimistic on average across 33 operations).

Changelog
=========

0.2.0
------

Added
~~~~~

**Test suite — CLI integration (45 tests)**

- ``tests/unit/test_cli.py`` — full Click CliRunner test suite for both CLI tools
- Covers ``qs-audit scan``: clean→exit 0, classical→exit 1, ``--fail-on`` thresholds,
  JSON/SARIF/GitHub output formats, preset policies, ``--min-severity`` filtering,
  ``--exclude`` patterns, ``--output`` to file, ``--metadata`` key/value pairs,
  ``qs-audit compliance``, ``qs-audit requirements``, ``qs-audit sbom``
- Covers ``qs-migrate scan``: directory scan, exclude patterns, SARIF output,
  ``qs-migrate upgrade-key``, ``qs-migrate status``

**Test suite — statistical benchmark utilities (58 tests)**

- ``tests/unit/test_bench_stats.py`` — tests for all statistical analysis functions
- Covers bootstrap CI monotonicity and containment, Welch's t-test significance,
  Cohen's d sign/magnitude, throughput curve formula, CoV threshold logic,
  LaTeX booktabs structure, ``describe_samples`` unit conversion

**Benchmark harnesses — signatures**

- ``tests/bench/bench_signatures.py`` — signature benchmark harness with identical
  methodology to ``bench_kem.py`` (1000 iterations, 100 warmup, 1% trim)
- Ed25519 sign/verify baselines, ML-DSA-65 standalone (liboqs), HybridSign
  (Ed25519+ML-DSA-65), X.509 hybrid certificate build and cosignature verify

**Benchmark harnesses — KEM extensions**

- ``bench_hybrid_decomposition()`` — isolates X25519-only, ML-KEM-768-only, and
  combined HybridKEM costs to measure combiner overhead (HKDF + serialisation)
- ``bench_concurrent_load_extended()`` — 1000 and 5000 simultaneous users added
  to the throughput curve (extends the 100/500-user baseline)

**Statistical analysis utilities**

- ``tests/bench/bench_stats.py`` — research-grade statistical library (pure Python,
  no scipy dependency)
- ``bootstrap_ci`` — Efron (1979) percentile bootstrap, 2000 resamples, seeded
- ``welch_t_test`` — Welch's t-test from scratch via regularised incomplete beta
  (Abramowitz & Stegun 26.5.27, Lentz continued fraction)
- ``cohens_d`` — pooled standard deviation effect size
- ``throughput_curve`` — ops/s per concurrency tier with scaling efficiency
- ``cov_stability_report`` — CoV proxy summary for side-channel analysis
- ``latex_table`` — ready-to-paste ``booktabs`` table generator for ACM/IEEE/USENIX

**Bug fixes**

- ``audit/cli.py``: ``--fail-on never`` now suppresses all process exits, including
  policy-level failures (``report.passed`` check was unconditionally executed before)
- ``migrate/scanner.py``: ``--exclude`` patterns now match individual filenames via
  ``fnmatch``, not only directory names

0.1.0 — unreleased
-------------------

Added
~~~~~

**Core type system**

- ``PublicKey``, ``SecretKey``, ``KeyPair`` with algorithm metadata and migration state
- ``_ZeroizingBytes`` — best-effort secret material zeroization on deletion
- ``CipherText``, ``HybridCipherText``, ``SharedSecret`` — distinct types prevent misuse
- ``SignedMessage``, ``HybridSignature`` — self-describing signed message format
- Key serialization: PEM (with ``qs-version``/``qs-algo`` headers), CBOR, JWK
- Cross-format round-trip: Python ↔ TypeScript ↔ Rust use the same envelope

**KEM module**

- ``KEM`` — single-algorithm PQC KEM with backend dispatch
- ``HybridKEM`` — X25519+ML-KEM combined KEM (default: X25519+ML-KEM-768)
- HKDF-SHA256 hybrid combiner following draft-ietf-tls-hybrid-design
- P-256 support as alternative classical companion
- Algorithm registry: ML-KEM-512/768/1024, BIKE-L1, HQC-128

**Signatures module**

- ``Sign`` — single-algorithm PQC signer with hedged mode
- ``HybridSign`` — Ed25519+ML-DSA combined signer (default: Ed25519+ML-DSA-65)
- Hedged mode (default on): random prefix prevents fault injection attacks
- Context string support for domain separation (per FIPS 204 §5.2)
- Algorithm registry: ML-DSA-44/65/87, SLH-DSA-SHAKE-128s/128f

**Backends**

- ``liboqs`` backend — full algorithm set via liboqs-python
- ``rustcrypto`` backend — stub (FIPS-subset, pending PyO3 crate publication)
- Auto-selection: tries rustcrypto first, falls back to liboqs
- ``list_available_backends()`` for diagnostics

**Protocol helpers**

- ``Envelope.seal()`` / ``Envelope.open()`` — KEM + AES-256-GCM authenticated encryption
- ``JWTSigner`` / ``JWTVerifier`` — PQC JWT (draft-ietf-jose-pqc-signatures identifiers)
- ``HybridTLSConfig`` / ``configure_hybrid_context()`` — TLS hybrid key exchange
- ``HybridCertificateBuilder`` — X.509 certs with PQC co-signature extension

**Migration tooling**

- ``Scanner`` — AST-based classical crypto detector (14 rules, SARIF output)
- ``MigrationStateManager`` — state machine for per-key migration tracking
- ``Upgrader`` — upgrades classical keys to hybrid while preserving backward compat
- ``FernetShim``, ``JWTShim`` — drop-in shims with usage logging
- ``qs-migrate`` CLI with ``scan``, ``upgrade-key``, ``status`` subcommands

**Audit and compliance**

- ``Auditor`` — orchestrates scan + policy evaluation
- ``AuditPolicy`` — configurable policy (presets: standard, strict, transition, permissive)
- ``NISTComplianceChecker`` — maps findings to FIPS 203/204/205, SP 800-208, CISA checklist
- ``SBOMEnricher`` — CycloneDX SBOM enrichment with PQC-readiness annotations
- ``qs-audit`` CLI with ``scan``, ``sbom``, ``requirements``, ``compliance`` subcommands
- CI gate: ``Auditor.ci_gate()`` returns exit code 0/1 and writes SARIF/JSON

**Internal**

- ``_internal.serialization`` — cbor2 (required) with JSON+base64 fallback for constrained environments
- ``exceptions.py`` — full 3-level exception hierarchy with machine-readable ``code`` fields

Known limitations (v0.1.0)
~~~~~~~~~~~~~~~~~~~~~~~~~~~

- RustCrypto backend is a stub — ``is_available()`` returns False until PyO3 crate ships
- noble (JavaScript/WASM) backend is JS-only — not available in Python
- TLS ``set_groups()`` requires OQS-patched OpenSSL — degrades gracefully without it
- X.509 co-signature OID (``1.3.6.1.4.1.99999.1``) is a placeholder — register before production use
- TypeScript/Rust scanner rules are planned for v0.2
