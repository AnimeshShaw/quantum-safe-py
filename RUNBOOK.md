# quantum-safe — Manual Runbook

Complete step-by-step guide for setting up, running, testing, and extending
the library without any CI/CD. Every command is runnable from scratch.

---

## 1. Prerequisites

```bash
python3 --version   # must be 3.10+
pip --version
```

You need:
- Python 3.10 or higher
- pip
- (Optional) liboqs-python for ML-KEM/ML-DSA operations
- (Optional) cbor2 for compact key serialization

The library works without liboqs. Classical X25519 and Ed25519 operations
run with only the `cryptography` package (already installed on most systems).

---

## 2. Install from this directory

```bash
# Clone or unzip the package
cd quantum-safe   # this directory

# Install in editable mode with development tools
pip install -e '.[dev]'

# Or minimal install (just core + cryptography)
pip install -e .

# With liboqs backend (enables ML-KEM, ML-DSA)
pip install -e '.[liboqs]'
```

If you're on a system without network access, install just the dependencies
you have available:

```bash
pip install cryptography pydantic click rich cbor2
pip install -e . --no-deps
```

---

## 3. Verify installation

```bash
python3 -c "
import sys; sys.path.insert(0, 'src')
from quantum_safe import HybridKEM, HybridSign
from quantum_safe.backends import list_available_backends
print('Backends:', list_available_backends())
print('Import: OK')
"
```

Expected output (without liboqs):
```
Backends: {'rustcrypto': False, 'liboqs': False, 'noble': False}
Import: OK
```

Expected output (with liboqs):
```
Backends: {'rustcrypto': False, 'liboqs': True, 'noble': False}
Import: OK
```

---

## 4. Running the test suite

### Unit tests (no liboqs needed)

```bash
# From the quantum-safe directory
python3 -m pytest tests/unit/ -v
```

If pytest is not installed:
```bash
pip install pytest
python3 -m pytest tests/unit/ -v
```

Expected: all tests pass or skip (marked requires_liboqs).

### Integration tests (classical components only)

```bash
python3 -m pytest tests/integration/ -v -m "not requires_liboqs"
```

### Integration tests (with liboqs)

```bash
python3 -m pytest tests/ -v
```

### Run a specific test file

```bash
python3 -m pytest tests/unit/test_kem.py -v
python3 -m pytest tests/unit/test_signatures.py -v
python3 -m pytest tests/unit/test_audit.py -v
```

### Run tests without pytest (stdlib only)

```bash
# Each test module can be tested directly
python3 -c "
import sys; sys.path.insert(0,'src')
# Paste any smoke test from the module here
from quantum_safe.migrate.scanner import Scanner
r = Scanner.scan_source('from cryptography.hazmat.primitives.asymmetric import rsa')
print('Findings:', [(f.rule_id, f.severity.name) for f in r.findings])
"
```

---

## 5. Running the benchmarks

```bash
# Classical components (always works)
python3 tests/bench/bench_kem.py

# Save results to JSON
python3 tests/bench/bench_kem.py --save results/bench_$(date +%Y%m%d).json

# Higher iteration count for research-grade data
python3 tests/bench/bench_kem.py --iterations 10000 --save results/bench_10k.json
```

Sample output:
```
── Classical primitives ──
  X25519 keygen                               median=   14.2µs  p95=   17.8µs  CoV=4.2%
  X25519 DH exchange                          median=   12.6µs  p95=   15.1µs  CoV=3.1%
  Ed25519 sign                                median=   24.1µs  p95=   28.4µs  CoV=2.8%
  Ed25519 verify                              median=   62.3µs  p95=   70.2µs  CoV=1.9%

── HybridKEM (classical half) ──
  HybridKEM keygen (X25519+mock PQC)          median=   16.8µs  p95=   20.3µs  CoV=4.5%
  HybridKEM encapsulate (X25519+mock)         median=   15.2µs  p95=   18.9µs  CoV=3.8%
  HybridKEM decapsulate (X25519+mock)         median=   14.9µs  p95=   18.4µs  CoV=3.6%
```

With liboqs installed, ML-KEM benchmarks run automatically.

---

## 6. CLI tools

### Install CLI entry points

```bash
pip install -e .
qs-audit --help
qs-migrate --help
```

### qs-audit: scan a directory

```bash
# Scan current directory for classical crypto
qs-audit scan .

# Scan with SARIF output (GitHub Code Scanning format)
qs-audit scan ./src --format sarif --output audit.sarif

# Scan with JSON output
qs-audit scan ./src --format json --output audit.json

# Use strict policy (fails on MEDIUM and above)
qs-audit scan ./src --preset-policy strict

# Custom fail threshold
qs-audit scan ./src --fail-on critical

# With exempt paths
qs-audit scan ./src --exclude "tests/**" --exclude "scripts/**"
```

### qs-audit: SBOM enrichment

```bash
# Enrich a CycloneDX SBOM
qs-audit sbom sbom.json --output sbom-pqc.json

# Summary view
qs-audit sbom sbom.json --format summary
```

### qs-audit: requirements.txt check

```bash
qs-audit requirements requirements.txt
```

### qs-audit: NIST compliance report

```bash
qs-audit compliance ./src --format json --output compliance.json
qs-audit compliance ./src --format text
```

---

## 7. Manual API walkthrough

### 7.1 Key generation and serialization

```python
import sys; sys.path.insert(0, 'src')

from quantum_safe.kem.hybrid import HybridKEM
from quantum_safe.signatures.hybrid import HybridSign

# --- Without liboqs: use mock backend ---
class MockKEMBackend:
    name = "mock"
    def keygen(self, a): return b"\xAA" * 1184, b"\xBB" * 2400
    def encapsulate(self, a, p): return b"\xCC" * 1088, b"\xDD" * 32
    def decapsulate(self, a, s, c): return b"\xDD" * 32
    def is_available(self): return True
    def supported_algorithms(self): return []

kem = HybridKEM.__new__(HybridKEM)
kem._classical = "X25519"
kem._pqc = "ML-KEM-768"
kem._algorithm = "X25519+ML-KEM-768"
kem._backend = MockKEMBackend()

kp = kem.generate_keypair()
print("Algorithm:", kp.algorithm)
print("Public key size:", len(kp.public.raw_bytes), "bytes")
print("Fingerprint:", kp.public.fingerprint()[:16] + "...")

pem = kp.public.to_pem()
print("\nPEM:\n", pem[:120], "...")

from quantum_safe.types import PublicKey
kp2_pub = PublicKey.from_pem(pem)
assert kp2_pub.raw_bytes == kp.public.raw_bytes
print("PEM round-trip: OK")
```

### 7.2 Encryption and decryption

```python
from quantum_safe.protocols.envelope import Envelope, SealedMessage

plaintext = b"top secret message"
sealed = Envelope.seal(plaintext, kp.public, kem=kem, aad=b"recipient:animesh")
print("\nSealed message:")
print("  algo:", sealed.algorithm)
print("  ciphertext size:", len(sealed.ciphertext), "bytes")
print("  kem_ct size:", len(sealed.kem_ct), "bytes")
print("  aad:", sealed.aad)

wire = sealed.to_bytes()
print("  wire size:", len(wire), "bytes")

# Reconstruct from wire
sealed2 = SealedMessage.from_bytes(wire)
recovered = Envelope.open(sealed2, kp.secret, kem=kem)
print("\nDecrypted:", recovered)
assert recovered == plaintext
```

### 7.3 Signing and verification

```python
class MockSigBackend:
    name = "mock"
    def keygen(self, a): return b"\xAA" * 1952, b"\xBB" * 4000
    def sign(self, a, sk, msg, ctx=b""): return b"\xCC" * 3293
    def verify(self, a, pk, msg, sig, ctx=b""): return len(sig) == 3293
    def is_available(self): return True
    def supported_algorithms(self): return []

signer = HybridSign.__new__(HybridSign)
signer._classical = "Ed25519"
signer._pqc = "ML-DSA-65"
signer._algorithm = "Ed25519+ML-DSA-65"
signer._hedged = True
signer._backend = MockSigBackend()

sig_kp = signer.generate_keypair()
sm = signer.sign(b"critical document", sig_kp.secret, context=b"myapp-v1")
print("\nSigned message:")
print("  algorithm:", sm.algorithm)
print("  is_hybrid:", sm.is_hybrid)
print("  context:", sm.context)

signer.verify(sm, sig_kp.public)
print("  Verification: OK")

# Tamper test — Ed25519 is real, should fail
from quantum_safe.types.signatures import SignedMessage
from quantum_safe.exceptions import VerificationError

tampered = SignedMessage(
    message=b"tampered content",
    signature=sm.signature,
    algorithm=sm.algorithm,
    context=sm.context,
    signed_at=sm.signed_at,
)
try:
    signer.verify(tampered, sig_kp.public)
    print("  FAIL: should have raised VerificationError")
except VerificationError:
    print("  Tamper detection: OK")
```

### 7.4 Scanner

```python
from quantum_safe.migrate.scanner import Scanner

classical_code = """
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
import jwt

# Classical key generation
rsa_key = rsa.generate_private_key(65537, 2048)
ec_key  = ec.generate_private_key(ec.SECP256R1())
token   = jwt.encode({"sub": "user"}, rsa_key, algorithm="RS256")
"""

report = Scanner.scan_source(classical_code, filename="legacy_auth.py")
print("\nScan report:")
print(" ", report.summary())
for f in report.findings:
    print(f"  [{f.severity.name:<8}] {f.rule_id}: {f.message}")
    if f.fix_hint:
        print(f"    → {f.fix_hint}")
```

### 7.5 NIST compliance

```python
from quantum_safe.audit.compliance import NISTComplianceChecker

compliance = NISTComplianceChecker.check(report, target="legacy_auth.py")
print("\nNIST compliance:")
print("  Overall:", compliance.overall_level.value)
for ctrl in compliance.non_compliant_controls:
    print(f"  [{ctrl.control_id}] {ctrl.title}: {ctrl.level.value}")
    print(f"    Evidence: {ctrl.evidence[:1]}")
    print(f"    Remediation: {ctrl.remediation}")
```

### 7.6 Migration state tracking

```python
from quantum_safe.migrate.state import MigrationStateManager
from quantum_safe.types.keys import MigrationState

store = {}  # in production, back this with Redis / Postgres / DynamoDB
mgr = MigrationStateManager(store)

# Simulate a key being upgraded
mgr.transition(
    key_id="user-animesh",
    from_state=MigrationState.CLASSICAL_ONLY,
    to_state=MigrationState.HYBRID_TRANSITION,
    algorithm="X25519+ML-KEM-768",
    actor="key-rotation-job",
    reason="CISA PQC migration mandate",
)

print("\nMigration state for user-animesh:", mgr.get_current_state("user-animesh"))
print("Progress:", mgr.migration_progress())
print("History:")
for rec in mgr.get_history("user-animesh"):
    print(f"  {rec.from_state.value} → {rec.to_state.value} by {rec.actor}")
```

---

## 8. Environment variables

```bash
# Force a specific PQC backend
export QUANTUM_SAFE_BACKEND=liboqs   # or rustcrypto

# Then in Python
from quantum_safe.backends import get_kem_backend
b = get_kem_backend("auto")  # reads QUANTUM_SAFE_BACKEND
print(b.name)  # "liboqs"
```

---

## 9. Running with liboqs

After `pip install 'quantum-safe[liboqs]'`:

```python
import sys; sys.path.insert(0, 'src')
from quantum_safe import HybridKEM, HybridSign

# Full ML-KEM-768 hybrid KEM
kem = HybridKEM()
kp  = kem.generate_keypair()
print("Public key size:", len(kp.public.raw_bytes), "bytes")  # ~1218B (2B prefix + 32B X25519 + 1184B ML-KEM)

ct, ss = kem.encapsulate(kp.public)
ss2    = kem.decapsulate(kp.secret, ct)
assert ss == ss2
print("HybridKEM round-trip: OK")

# Full Ed25519 + ML-DSA-65 signing
signer = HybridSign()
sig_kp = signer.generate_keypair()
sm     = signer.sign(b"real document", sig_kp.secret, context=b"myapp-v1")
signer.verify(sm, sig_kp.public)
print("HybridSign round-trip: OK")
```

---

## 10. Troubleshooting

### `ModuleNotFoundError: No module named 'quantum_safe'`

Make sure you're running from the `quantum-safe` directory and have `src` in your path:
```bash
cd quantum-safe
python3 -c "import sys; sys.path.insert(0,'src'); from quantum_safe import HybridKEM"
```

Or install the package: `pip install -e .`

### `BackendNotAvailable: Backend 'auto' is not available`

Neither liboqs nor rustcrypto is installed. The library still works for
classical operations. For ML-KEM/ML-DSA, install liboqs:
```bash
pip install 'quantum-safe[liboqs]'
```

### `ModuleNotFoundError: No module named 'cbor2'`

cbor2 is optional. The library falls back to JSON+base64 encoding:
```python
from quantum_safe._internal.serialization import BACKEND
print(BACKEND)  # "json-b64" without cbor2, "cbor2" with it
```

Install cbor2 for more compact key storage: `pip install cbor2`

### `ssl.SSLError: Hybrid TLS is required but OQS provider is not available`

Remove `require_hybrid=True` from your `HybridTLSConfig`, or install the
OQS OpenSSL provider: https://github.com/open-quantum-safe/oqs-provider

### Tests fail with `ModuleNotFoundError: No module named 'pytest'`

```bash
pip install pytest pytest-benchmark
```

---

## 11. Research benchmarking workflow

For the Quantum-Safe Code Auditor paper:

```bash
# Phase 1: baseline classical primitives
python3 tests/bench/bench_kem.py --iterations 10000 --save results/phase1_classical.json

# Phase 2: with liboqs installed — full ML-KEM benchmarks
pip install 'quantum-safe[liboqs]'
python3 tests/bench/bench_kem.py --iterations 10000 --save results/phase2_mlkem.json

# The JSON structure is:
# {"results": [{"name": "...", "median_us": ..., "p95_us": ..., "cov_pct": ...}]}

# Parse and compare
python3 -c "
import json
with open('results/phase2_mlkem.json') as f:
    data = json.load(f)
for r in data['results']:
    print(f'{r[\"name\"]:<45} median={r[\"median_us\"]:8.1f}µs  CoV={r[\"cov_pct\"]:.1f}%')
"
```

The `cov_pct` (coefficient of variation) column in the benchmark output
is the key metric for the timing side-channel analysis in your paper.
Values below 2% suggest constant-time execution; above 5% warrants
investigation as a potential side-channel risk.
