Changelog
=========

0.2.0 — unreleased
-------------------

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
