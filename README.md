# quantum-safe

Production-grade post-quantum cryptography for Python. Hybrid KEM, hybrid signatures, migration tooling, protocol helpers, and a CI-ready audit scanner — all in one library.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-green.svg)](LICENSE)
[![FIPS 203/204/205](https://img.shields.io/badge/NIST-FIPS_203%2F204%2F205-purple.svg)](https://csrc.nist.gov/pubs/fips)
[![Documentation](https://img.shields.io/badge/docs-GitHub%20Pages-blue.svg)](https://animeshshaw.github.io/quantum-safe/)

---

## Why this library exists

Every PQC library today exposes algorithm primitives. None of them solve the production problem:

| Gap | Status in ecosystem | This library |
|-----|---------------------|--------------|
| Hybrid KEM (X25519+ML-KEM) | Only Cloudflare CIRCL (Go) | ✓ Default mode |
| Cross-language key format | Every library differs | ✓ PEM/CBOR/JWK parity |
| Migration path for existing keys | No library supports this | ✓ `Upgrader` + state machine |
| Protocol helpers (TLS, JWT, X.509) | Not implemented anywhere | ✓ `protocols` module |
| CI audit gate (SARIF output) | grep scripts | ✓ `qs-audit` CLI |
| SBOM PQC-readiness enrichment | None | ✓ CycloneDX enrichment |

---

## Quick start

```python
from quantum_safe import HybridKEM, HybridSign

# Key exchange — hybrid X25519 + ML-KEM-768 (NIST transition-period standard)
kem = HybridKEM()
kp  = kem.generate_keypair()
ct, shared_secret = kem.encapsulate(kp.public)
ss2 = kem.decapsulate(kp.secret, ct)
assert shared_secret == ss2

# Digital signatures — hybrid Ed25519 + ML-DSA-65
signer = HybridSign()
kp     = signer.generate_keypair()
sm     = signer.sign(b"important document", kp.secret, context=b"myapp-v1")
signer.verify(sm, kp.public)  # raises VerificationError if invalid
```

---

## Installation

### Core (classical crypto only, no PQC backend required)

```bash
pip install quantum-safe
```

The core package works without liboqs. Key generation, serialization, hybrid
construction, Envelope, JWT, TLS helpers, scanner, auditor, and SBOM enrichment
all work with the classical (X25519/Ed25519) components.

### With liboqs backend (full ML-KEM / ML-DSA support)

```bash
pip install 'quantum-safe[liboqs]'
```

Installs `liboqs-python` which vendors a pre-built liboqs binary for common
platforms (Linux x86-64, macOS ARM/x86, Windows x86-64). If you're on an
unusual architecture, build liboqs from source first.

Verify installation:
```bash
python -c "from quantum_safe.backends import list_available_backends; print(list_available_backends())"
# → {'rustcrypto': False, 'liboqs': True, 'noble': False}
```

### Development install

```bash
git clone https://github.com/quantum-safe/quantum-safe-py
cd quantum-safe-py
pip install -e '.[dev]'
pre-commit install
```

---

## Core concepts

### Hybrid mode is the default

During the NIST transition period, every security standard (NIST, CISA, BSI, NCSC)
recommends hybrid classical + PQC. This library makes hybrid the default so you
have to explicitly opt out, not in.

```python
# Default: X25519 + ML-KEM-768 (hybrid)
kem = HybridKEM()

# Override to pure PQC (not recommended for new deployments)
kem = KEM("ML-KEM-768")

# Override to a different hybrid combination
kem = HybridKEM(classical="X25519", pqc="ML-KEM-1024")
```

### Typed outputs prevent accidents

Raw bytes are never returned from key operations. Every output is a distinct type:

```python
kp:  KeyPair         # contains .public (PublicKey) and .secret (SecretKey)
ct:  HybridCipherText  # ciphertext — pass to decapsulate()
ss:  SharedSecret    # 32 bytes — call ss.derive_key() to get AES keys
sm:  SignedMessage   # message + signature + metadata — self-contained
```

This prevents the class of bug where you accidentally pass a `SharedSecret`
as a `CipherText`.

### Keys know their format

Every key carries its algorithm name, migration state, and supports multiple
serialization formats:

```python
pub = kp.public
print(pub.algorithm)         # "X25519+ML-KEM-768"
print(pub.migration_state)   # MigrationState.HYBRID_TRANSITION
print(pub.fingerprint())     # "3a7f1c2e..." (sha256 hex)

# Serialize
pem  = pub.to_pem()    # PEM string with qs-version and qs-algo headers
cbor = pub.to_cbor()   # CBOR bytes (compact, binary)
jwk  = pub.to_jwk()    # JSON Web Key dict

# Round-trip (Python ↔ TypeScript ↔ Rust — same format)
pub2 = PublicKey.from_pem(pem)
pub3 = PublicKey.from_cbor(cbor)
pub4 = PublicKey.from_jwk(jwk)
```

---

## Key encapsulation (KEM)

```python
from quantum_safe import HybridKEM
from quantum_safe.protocols import Envelope

# Option 1: Low-level (you manage the shared secret)
kem  = HybridKEM()
kp   = kem.generate_keypair()
ct, ss = kem.encapsulate(kp.public)
ss2    = kem.decapsulate(kp.secret, ct)

# Derive AES keys from shared secret
enc_key = ss.derive_key(32, info=b"myapp-encryption-v1")
mac_key = ss.derive_key(32, info=b"myapp-mac-v1")

# Option 2: High-level (recommended for most use cases)
# Envelope = KEM + AES-256-GCM, fully self-describing
sealed  = Envelope.seal(b"plaintext", kp.public)
plain   = Envelope.open(sealed, kp.secret)

# Serialize for network transport
wire   = sealed.to_bytes()   # or .to_hex()
sealed = SealedMessage.from_bytes(wire)  # or .from_hex()

# With authenticated metadata (visible but authenticated)
sealed = Envelope.seal(b"payload", pub, aad=b"recipient-id:user-42")
```

---

## Digital signatures

```python
from quantum_safe import HybridSign, Sign
from quantum_safe.types import SignedMessage

# Hybrid (Ed25519 + ML-DSA-65) — recommended
signer = HybridSign()
kp     = signer.generate_keypair()
sm     = signer.sign(b"document", kp.secret, context=b"myapp-v2-docs")
signer.verify(sm, kp.public)  # raises VerificationError if invalid

# Hedged mode is on by default — two signings of the same message differ
sm1 = signer.sign(b"same", kp.secret)
sm2 = signer.sign(b"same", kp.secret)
assert sm1.signature != sm2.signature  # different random prefix each time

# Store and retrieve a signed message
cbor_bytes = sm.to_cbor()
sm2 = SignedMessage.from_cbor(cbor_bytes)

# Include signer fingerprint for key lookup
sm = signer.sign_with_fingerprint(b"doc", kp)
print(sm.signer_fingerprint)  # "3a7f1c2e..."
```

---

## Protocol helpers

### Encrypted envelopes

See Key Encapsulation section above.

### JWT (PQC-aware)

```python
from quantum_safe.protocols.jwt import JWTSigner, JWTVerifier

# Sign
signer = JWTSigner(keypair, issuer="auth.myapp.com")
token  = signer.sign({"sub": "user123", "role": "admin"})

# Verify
verifier = JWTVerifier(keypair.public, issuer="auth.myapp.com")
claims   = verifier.verify(token)
# raises VerificationError on invalid, expired, or wrong issuer
```

### TLS hybrid key exchange

```python
import ssl
from quantum_safe.protocols.tls import configure_hybrid_context, HybridTLSConfig

ctx = ssl.create_default_context()
configure_hybrid_context(ctx, HybridTLSConfig(
    kem_algorithm="X25519+ML-KEM-768",
    fallback_classical=True,   # include X25519 as fallback
))
# ctx now prefers X25519MLKEM768 when the OQS provider is available
```

### Hybrid X.509 certificates

```python
from quantum_safe.protocols.x509 import HybridCertificateBuilder, generate_classical_keypair_for_cert

classical_key = generate_classical_keypair_for_cert("Ed25519")
hybrid_kp     = HybridSign().generate_keypair()

builder = HybridCertificateBuilder(
    subject_cn="service.internal",
    classical_private_key=classical_key,
    pqc_keypair=hybrid_kp,
    dns_names=["api.service.internal"],
    validity_days=365,
)
cert_pem, cosig_bundle = builder.build()
```

---

## Migration tooling

### Scan a codebase for classical crypto

```python
from quantum_safe.migrate import Scanner

report = Scanner.scan_directory("./src")
print(report.summary())
# Scanned 42 files in './src': 2 CRITICAL, 5 HIGH, 3 MEDIUM

for finding in report.high + report.critical:
    print(f"{finding.file}:{finding.line} [{finding.rule_id}] {finding.message}")
    print(f"  Fix: {finding.fix_hint}")

# Exit 1 in CI if blocking findings exist
if report.has_blocking_findings:
    sys.exit(1)
```

### Upgrade an existing key to hybrid

```python
from quantum_safe.migrate import Upgrader

result = Upgrader.upgrade_kem_key(
    classical_secret_bytes=x25519_private_bytes,  # your existing X25519 key
    classical_public_bytes=x25519_public_bytes,
    classical_algorithm="X25519",
    target_pqc="ML-KEM-768",
)
# result.new_keypair contains X25519 + ML-KEM-768
# Old senders using X25519-only can still encrypt to the new public key
print(result.notes)
```

### Track migration progress

```python
from quantum_safe.migrate import MigrationStateManager
from quantum_safe.types import MigrationState

store = {}  # replace with Redis / DynamoDB / Postgres
mgr   = MigrationStateManager(store)

mgr.transition(
    key_id="user-123",
    from_state=MigrationState.CLASSICAL_ONLY,
    to_state=MigrationState.HYBRID_TRANSITION,
    algorithm="X25519+ML-KEM-768",
    actor="key-rotation-v2",
)
print(mgr.migration_progress())
# {'classical_only': 0, 'hybrid_transition': 1, ...}
```

---

## Audit and compliance

### CI audit gate

```python
from quantum_safe.audit import Auditor, AuditPolicy

# Returns 0 (pass) or 1 (fail) — use directly in CI
exit_code = Auditor.ci_gate(
    "./src",
    policy=AuditPolicy(allow_classical_only=False, hybrid_required=True),
    output_sarif="audit.sarif",   # GitHub Code Scanning
    output_json="audit.json",
)
sys.exit(exit_code)
```

### NIST compliance report

```python
from quantum_safe.audit import NISTComplianceChecker
from quantum_safe.migrate import Scanner

scan   = Scanner.scan_directory("./src")
report = NISTComplianceChecker.check(scan, target="./src")
print(report.to_json())
# Maps findings to FIPS 203, FIPS 204, FIPS 205, SP 800-208, CISA checklist
```

### CycloneDX SBOM enrichment

```python
from quantum_safe.audit import SBOMEnricher

with open("sbom.json") as f:
    sbom = json.load(f)

enriched, assessments = SBOMEnricher.enrich(sbom)
# Each component gets quantum-safe:pqc-readiness: READY|PARTIAL|NOT_READY|UNKNOWN

not_ready = [a for a in assessments if a.readiness.value == "NOT_READY"]
for a in not_ready:
    print(f"NOT READY: {a.name} {a.version} → {a.action}")
```

---

## CLI tools

### qs-audit

```bash
# Scan for classical crypto — text output
qs-audit scan ./src

# SARIF output for GitHub Code Scanning
qs-audit scan ./src --format sarif --output audit.sarif

# JSON report with strict policy
qs-audit scan ./src --format json --preset-policy strict

# Fail CI if HIGH or above findings exist (default)
qs-audit scan ./src --fail-on high && echo "PASSED" || echo "FAILED"

# Enrich a CycloneDX SBOM
qs-audit sbom sbom.json --output sbom-pqc.json

# Quick requirements.txt check
qs-audit requirements requirements.txt

# NIST SP 800-208 compliance report
qs-audit compliance ./src --format json --output compliance.json
```

### qs-migrate

```bash
# Scan a codebase for classical crypto
qs-migrate scan ./src --format sarif --output migrate.sarif

# Check migration progress
qs-migrate status
```

---

## Security notes

### Memory safety

`SecretKey` and `SharedSecret` attempt to zero their memory on deletion.
Python's garbage collector makes hard guarantees impossible, but we reduce
the window during which secret material is visible in heap dumps.

For high-security deployments, use an HSM — see `docs/hsm.md`.

### Constant-time operations

We use `hmac.compare_digest()` for all secret comparisons. The underlying
liboqs implementations are designed for constant-time operation. ENV-2 benchmarks
(Docker/WSL2, 3,000 iterations) show ML-KEM-768 decapsulate CoV ~3.9% — within
the AES-256-GCM noise floor band of 2.1%, confirming timing stability in practice.

### Hedged signing

`HybridSign` and `Sign` default to hedged mode: a 32-byte random prefix
is prepended before signing. This prevents fault injection attacks that have
been demonstrated on lattice signatures in lab conditions. Opt out with
`hedged=False` only if you have a specific need for deterministic signatures.

### Hybrid mode rationale

ML-KEM was standardized in 2024. Hybrid mode (X25519 + ML-KEM-768) means:
- If ML-KEM is broken, X25519 still protects you.
- If X25519 is broken by a quantum computer, ML-KEM still protects you.
- Both would need to fail simultaneously.

This is the position of NIST, CISA, BSI, NCSC, and every TLS library
that has added PQC support.

---

## Algorithm reference

| Algorithm | Type | NIST Level | Standard | Notes |
|-----------|------|-----------|----------|-------|
| ML-KEM-512 | KEM | 1 | FIPS 203 | Smallest. Use ML-KEM-768 for new deployments. |
| ML-KEM-768 | KEM | 3 | FIPS 203 | **Recommended default.** |
| ML-KEM-1024 | KEM | 5 | FIPS 203 | Maximum security. |
| ML-DSA-44 | Sign | 2 | FIPS 204 | Smallest ML-DSA. |
| ML-DSA-65 | Sign | 3 | FIPS 204 | **Recommended default.** |
| ML-DSA-87 | Sign | 5 | FIPS 204 | Maximum security. |
| SLH-DSA-SHAKE-128s | Sign | 1 | FIPS 205 | Hash-based. Very slow to sign. |
| SLH-DSA-SHAKE-128f | Sign | 1 | FIPS 205 | Hash-based. Larger sigs, faster sign. |
| X25519+ML-KEM-768 | Hybrid KEM | — | IETF draft | **Default hybrid combination.** |
| Ed25519+ML-DSA-65 | Hybrid Sign | — | IETF draft | **Default hybrid combination.** |

---

## Development

### Running tests

```bash
# Unit tests only (no liboqs needed)
python -m pytest tests/unit/ -v

# With liboqs installed
python -m pytest tests/ -v -m "not slow"

# Integration tests
python -m pytest tests/integration/ -v

# Skip liboqs-dependent tests
python -m pytest tests/ -v -m "not requires_liboqs"
```

### Running benchmarks

The recommended environment is Docker (Linux kernel + from-source liboqs with AVX2):

```bash
# Build the benchmark image once (~3 min, compiles liboqs from source)
docker build -t quantum-safe-bench .

# Full KEM suite — CPU pinned, 3,000 iterations (recommended)
docker run --rm --cpuset-cpus="0,1" \
  -v "$(pwd)/results:/app/results" quantum-safe-bench \
  python -X utf8 tests/bench/bench_kem.py --with-pqc --iterations 3000 \
  --save /app/results/bench_kem_$(date +%Y-%m-%d).json

# Signature suite — CPU pinned, 3,000 iterations
docker run --rm --cpuset-cpus="0,1" \
  -v "$(pwd)/results:/app/results" quantum-safe-bench \
  python -X utf8 tests/bench/bench_signatures.py --with-pqc --iterations 3000 \
  --save /app/results/bench_sig_$(date +%Y-%m-%d).json
```

Native (Windows/Linux, no Docker):

```bash
python -X utf8 tests/bench/bench_kem.py --with-pqc --iterations 3000
python -X utf8 tests/bench/bench_signatures.py --with-pqc --iterations 3000
```

Benchmark results and methodology are in [results/BENCHMARKS.md](results/BENCHMARKS.md).
Headline numbers (ENV-2, Docker/WSL2, 2026-03-29): full hybrid KEM handshake **~243 µs**,
throughput **~2,848 ops/s** at 5,000 concurrent users.
The `cov_pct` (coefficient of variation) column is the timing side-channel proxy —
values near the AES-256-GCM baseline (~2.1%) indicate constant-time behaviour.

### Statistical analysis

`tests/bench/bench_stats.py` provides research-grade statistical utilities
used to generate paper-quality numbers from raw benchmark samples:

```python
from tests.bench.bench_stats import bootstrap_ci, welch_t_test, cohens_d, latex_table

lo, median, hi = bootstrap_ci(samples_us, confidence=0.95)
result = welch_t_test(classical_samples, hybrid_samples)
print(f"p={result.p_value:.4f}, d={cohens_d(classical_samples, hybrid_samples):.2f}")
```

### Code quality

```bash
# Type checking
mypy src/quantum_safe --strict

# Linting
ruff check src/ tests/

# Formatting
black src/ tests/
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

Apache 2.0. See [LICENSE](LICENSE).

---

## Acknowledgements

Built on:
- [Open Quantum Safe / liboqs](https://openquantumsafe.org/) — reference PQC implementations
- [PyCA cryptography](https://cryptography.io/) — classical primitives and X.509
- [NIST PQC Standardization](https://csrc.nist.gov/projects/post-quantum-cryptography) — FIPS 203/204/205
