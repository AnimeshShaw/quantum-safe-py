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

# CLI integration tests (qs-audit and qs-migrate via Click CliRunner)
python3 -m pytest tests/unit/test_cli.py -v

# Statistical benchmark utility tests
python3 -m pytest tests/unit/test_bench_stats.py -v
```

### Test file inventory

| File | What it covers | liboqs needed? |
|------|----------------|---------------|
| `tests/unit/test_kem.py` | KEM types, hybrid combiner, serialization | No |
| `tests/unit/test_signatures.py` | Signature types, HybridSign, hedged mode | No |
| `tests/unit/test_protocols.py` | Envelope, JWT, TLS, X.509 | No |
| `tests/unit/test_migrate.py` | Scanner rules, Upgrader, state machine | No |
| `tests/unit/test_audit.py` | Auditor, policy, compliance, SBOM | No |
| `tests/unit/test_cli.py` | `qs-audit` and `qs-migrate` CLI (45 tests) | No |
| `tests/unit/test_bench_stats.py` | Bootstrap CI, Welch t-test, Cohen's d, LaTeX (58 tests) | No |
| `tests/integration/` | End-to-end hybrid round-trips | Optional |

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

Two benchmark harnesses cover the full paper data. Both use 1000 iterations,
100 warmup, 1% outlier trim, and `time.perf_counter`.

### KEM benchmarks

```bash
# Classical + mock PQC (no liboqs needed)
python3 -X utf8 tests/bench/bench_kem.py

# Full suite with real ML-KEM-768 via liboqs (includes decomposition + extended load)
python3 -X utf8 tests/bench/bench_kem.py --with-pqc

# Save JSON snapshot
python3 -X utf8 tests/bench/bench_kem.py --with-pqc \
  --save results/bench_kem_$(date +%Y-%m-%d).json
```

The `--with-pqc` flag adds:
- Real ML-KEM-768 keygen / encapsulate / decapsulate (liboqs)
- Hybrid decomposition table (X25519-only, ML-KEM-768-only, combined — isolates combiner cost)
- Extended concurrent load: 100 / 500 / 1000 / 5000 simultaneous users

### Signature benchmarks

```bash
# Ed25519 baseline + HybridSign + X.509 certs (no liboqs needed for Ed25519/HybridSign)
python3 -X utf8 tests/bench/bench_signatures.py

# Add standalone ML-DSA-65 timing (liboqs required)
python3 -X utf8 tests/bench/bench_signatures.py --with-pqc

# Save JSON snapshot
python3 -X utf8 tests/bench/bench_signatures.py --with-pqc \
  --save results/bench_sigs_$(date +%Y-%m-%d).json
```

### Interpreting the output

| Column | Meaning |
|--------|---------|
| `median` | 50th percentile latency — the headline number |
| `p95` | 95th percentile — worst-case for 95% of requests |
| `CoV` | Coefficient of variation — side-channel proxy metric |
| `*` flag | CoV > 5% — high variance (Windows scheduler jitter on short ops) |
| `~` flag | CoV 3–5% — moderate variance, worth watching |

**CoV interpretation:** Values ≤ 2% indicate constant-time behaviour. ML-DSA sign
shows CoV ~50% — expected, because FIPS 204 uses hedged signing with fresh
randomness each call (not a timing side-channel).

Results are recorded in `results/BENCHMARKS.md`. JSON files are gitignored.

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

Full paper reproduction sequence:

```bash
# Step 1 — install with liboqs
pip install 'quantum-safe[liboqs]'

# Step 2 — KEM suite (classical baselines + ML-KEM-768 + decomposition + concurrent load)
python3 -X utf8 tests/bench/bench_kem.py --with-pqc \
  --save results/bench_kem_$(date +%Y-%m-%d).json

# Step 3 — Signature suite (Ed25519 + ML-DSA-65 + HybridSign + X.509 certs)
python3 -X utf8 tests/bench/bench_signatures.py --with-pqc \
  --save results/bench_sigs_$(date +%Y-%m-%d).json

# Step 4 — Post-process with statistical utilities
python3 -c "
import sys, json
sys.path.insert(0, 'tests/bench')
from bench_stats import bootstrap_ci, welch_t_test, cohens_d

with open('results/bench_kem_$(date +%Y-%m-%d).json') as f:
    data = json.load(f)

# Print all results with bootstrap CIs
for section, results in data['results'].items():
    for r in results:
        lo, med, hi = bootstrap_ci(r.get('samples_us', [r['median_us']]))
        print(f\"{r['name']:<50} {med:8.1f} µs  [{lo:.1f}, {hi:.1f}]  CoV={r['cov_pct']:.1f}%\")
"
```

The statistical utilities in `tests/bench/bench_stats.py` provide:

- `bootstrap_ci(samples, confidence=0.95)` — 95% CI via Efron percentile bootstrap
- `welch_t_test(samples_a, samples_b)` — significance test, p-value, overhead%
- `cohens_d(samples_a, samples_b)` — standardised effect size
- `latex_table(rows, columns)` — ready-to-paste LaTeX `booktabs` table
- `cov_stability_report(results)` — CoV proxy summary for side-channel section
