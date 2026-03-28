"""
KEM benchmark harness.

Run with::

    python tests/bench/bench_kem.py

or with pytest-benchmark installed::

    pytest tests/bench/ -v --benchmark-sort=mean

Results are printed as a table and optionally saved to JSON.

Design: each benchmark function is self-contained — it creates its own
backend, generates keys, and runs N iterations. We report median, p95,
p99, and CoV (coefficient of variation) because:

  - Median is more robust than mean for latency measurements.
  - p95/p99 captures tail latency that matters for SLO compliance.
  - CoV < 2% suggests constant-time execution; > 5% warrants investigation.

The warmup phase is critical: Python's JIT and OS scheduler create noise
in the first ~100 iterations. We discard them.
"""

from __future__ import annotations

import gc
import json
import os
import statistics
import sys
import time
from dataclasses import dataclass, field
from typing import Callable

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))


@dataclass
class BenchResult:
    name: str
    iterations: int
    warmup: int
    samples_us: list[float]   # microseconds

    @property
    def median_us(self) -> float:
        return statistics.median(self.samples_us)

    @property
    def mean_us(self) -> float:
        return statistics.mean(self.samples_us)

    @property
    def stdev_us(self) -> float:
        return statistics.stdev(self.samples_us) if len(self.samples_us) > 1 else 0.0

    @property
    def p95_us(self) -> float:
        s = sorted(self.samples_us)
        idx = int(len(s) * 0.95)
        return s[min(idx, len(s) - 1)]

    @property
    def p99_us(self) -> float:
        s = sorted(self.samples_us)
        idx = int(len(s) * 0.99)
        return s[min(idx, len(s) - 1)]

    @property
    def cov_pct(self) -> float:
        """Coefficient of variation as percentage."""
        if self.mean_us == 0:
            return 0.0
        return (self.stdev_us / self.mean_us) * 100.0

    def to_dict(self) -> dict:
        return {
            "name":         self.name,
            "iterations":   self.iterations,
            "warmup":       self.warmup,
            "median_us":    round(self.median_us, 2),
            "mean_us":      round(self.mean_us, 2),
            "p95_us":       round(self.p95_us, 2),
            "p99_us":       round(self.p99_us, 2),
            "stdev_us":     round(self.stdev_us, 2),
            "cov_pct":      round(self.cov_pct, 2),
        }

    def __str__(self) -> str:
        flag = ""
        if self.cov_pct > 5:
            flag = " [HIGH VARIANCE — timing side-channel risk?]"
        elif self.cov_pct > 2:
            flag = " [moderate variance]"
        return (
            f"  {self.name:<40} "
            f"median={self.median_us:8.1f}µs  "
            f"p95={self.p95_us:8.1f}µs  "
            f"CoV={self.cov_pct:.1f}%"
            f"{flag}"
        )


def _bench(name: str, fn: Callable, iterations: int = 1000, warmup: int = 100) -> BenchResult:
    """Run fn() for warmup+iterations times, return timing stats."""
    # Force GC before benchmarking
    gc.collect()
    gc.disable()

    try:
        # Warmup — discarded
        for _ in range(warmup):
            fn()

        # Measurement
        samples: list[float] = []
        for _ in range(iterations):
            t0 = time.perf_counter()
            fn()
            t1 = time.perf_counter()
            samples.append((t1 - t0) * 1_000_000)  # → microseconds
    finally:
        gc.enable()

    # Remove top and bottom 1% outliers (not 5% — see module docstring)
    samples.sort()
    clip = max(1, int(len(samples) * 0.01))
    samples = samples[clip: len(samples) - clip]

    return BenchResult(name=name, iterations=iterations, warmup=warmup, samples_us=samples)


# ---------------------------------------------------------------------------
# Benchmark functions
# ---------------------------------------------------------------------------


def bench_x25519_keygen() -> list[BenchResult]:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    results = []
    results.append(_bench(
        "X25519 keygen",
        lambda: X25519PrivateKey.generate(),
    ))
    return results


def bench_x25519_dh() -> list[BenchResult]:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    alice_priv = X25519PrivateKey.generate()
    bob_priv = X25519PrivateKey.generate()
    bob_pub = bob_priv.public_key()

    results = []
    results.append(_bench(
        "X25519 DH exchange",
        lambda: alice_priv.exchange(bob_pub),
    ))
    return results


def bench_ed25519_sign_verify() -> list[BenchResult]:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    msg = os.urandom(256)
    sig = priv.sign(msg)

    results = []
    results.append(_bench("Ed25519 sign",   lambda: priv.sign(msg)))
    results.append(_bench("Ed25519 verify", lambda: pub.verify(sig, msg)))
    return results


def bench_hybrid_kem_classical_only() -> list[BenchResult]:
    """Benchmark the X25519 half of HybridKEM in isolation."""
    from quantum_safe.kem.hybrid import HybridKEM

    from quantum_safe.backends.base import AbstractKEMBackend

    class MockPQCBackend(AbstractKEMBackend):
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
    kem._backend = MockPQCBackend()

    kp = kem.generate_keypair()

    results = []
    results.append(_bench("HybridKEM keygen (X25519+mock PQC)", lambda: kem.generate_keypair()))
    results.append(_bench("HybridKEM encapsulate (X25519+mock)", lambda: kem.encapsulate(kp.public)))

    hct, _ = kem.encapsulate(kp.public)
    results.append(_bench("HybridKEM decapsulate (X25519+mock)", lambda: kem.decapsulate(kp.secret, hct)))
    return results


def bench_aes_gcm() -> list[BenchResult]:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = os.urandom(32)
    nonce = os.urandom(12)
    aes = AESGCM(key)
    plaintext_1kb = os.urandom(1024)
    plaintext_64kb = os.urandom(65536)

    ct_1kb = aes.encrypt(nonce, plaintext_1kb, None)
    ct_64kb = aes.encrypt(nonce, plaintext_64kb, None)

    results = []
    results.append(_bench("AES-256-GCM encrypt 1 KB",  lambda: aes.encrypt(nonce, plaintext_1kb, None)))
    results.append(_bench("AES-256-GCM encrypt 64 KB", lambda: aes.encrypt(nonce, plaintext_64kb, None)))
    results.append(_bench("AES-256-GCM decrypt 1 KB",  lambda: aes.decrypt(nonce, ct_1kb, None)))
    return results


def bench_hkdf() -> list[BenchResult]:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    ikm = os.urandom(32)

    def do_hkdf():
        HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"bench").derive(ikm)

    results = []
    results.append(_bench("HKDF-SHA256 (32B → 32B)", do_hkdf))
    return results


def bench_envelope_seal_open() -> list[BenchResult]:
    """Full Envelope.seal() / open() cycle including HKDF + AES-GCM."""
    from quantum_safe.protocols.envelope import Envelope
    from quantum_safe.kem.hybrid import HybridKEM

    from quantum_safe.backends.base import AbstractKEMBackend

    class MockPQCBackend(AbstractKEMBackend):
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
    kem._backend = MockPQCBackend()

    kp = kem.generate_keypair()
    payload_1kb = os.urandom(1024)
    sealed = Envelope.seal(payload_1kb, kp.public, kem=kem)

    results = []
    results.append(_bench("Envelope.seal() 1KB (X25519+mock KEM)", lambda: Envelope.seal(payload_1kb, kp.public, kem=kem)))
    results.append(_bench("Envelope.open() 1KB (X25519+mock KEM)", lambda: Envelope.open(sealed, kp.secret, kem=kem)))
    return results


def bench_serialization() -> list[BenchResult]:
    """Key serialization / deserialization."""
    from quantum_safe.kem.hybrid import HybridKEM

    from quantum_safe.backends.base import AbstractKEMBackend

    class MockPQCBackend(AbstractKEMBackend):
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
    kem._backend = MockPQCBackend()

    kp = kem.generate_keypair()
    pem = kp.public.to_pem()
    cbor = kp.public.to_cbor()
    jwk = kp.public.to_jwk()

    from quantum_safe.types import PublicKey

    results = []
    results.append(_bench("PublicKey.to_pem()",    lambda: kp.public.to_pem()))
    results.append(_bench("PublicKey.from_pem()",  lambda: PublicKey.from_pem(pem)))
    results.append(_bench("PublicKey.to_cbor()",   lambda: kp.public.to_cbor()))
    results.append(_bench("PublicKey.from_cbor()", lambda: PublicKey.from_cbor(cbor)))
    results.append(_bench("PublicKey.fingerprint()", lambda: kp.public.fingerprint()))
    return results


def bench_hybrid_kem_real() -> list[BenchResult]:
    """Benchmark the full HybridKEM with real ML-KEM math via liboqs."""
    from quantum_safe.kem.hybrid import HybridKEM
    
    # This will use the real liboqs backend automatically if installed
    kem = HybridKEM()
    kp = kem.generate_keypair()

    results = []
    results.append(_bench("HybridKEM keygen (Real ML-KEM-768)", lambda: kem.generate_keypair()))
    results.append(_bench("HybridKEM encapsulate (Real ML-KEM-768)", lambda: kem.encapsulate(kp.public)))

    hct, _ = kem.encapsulate(kp.public)
    results.append(_bench("HybridKEM decapsulate (Real ML-KEM-768)", lambda: kem.decapsulate(kp.secret, hct)))
    return results


def bench_concurrent_load() -> list[BenchResult]:
    """Simulate heavy concurrent network load (100 and 500 simultaneous users)."""
    from quantum_safe.kem.hybrid import HybridKEM
    import concurrent.futures

    # This will automatically use liboqs if you pass --with-pqc, or mock if not
    kem = HybridKEM()
    kp = kem.generate_keypair()

    def handle_single_user():
        # Simulate one user completing a full key exchange handshake
        ct, ss = kem.encapsulate(kp.public)
        kem.decapsulate(kp.secret, ct)

    def simulate_users(num_users):
        # Fire off `num_users` threads at the exact same time
        with concurrent.futures.ThreadPoolExecutor(max_workers=num_users) as executor:
            futures = [executor.submit(handle_single_user) for _ in range(num_users)]
            concurrent.futures.wait(futures)

    results = []
    
    # Simulate 100 concurrent users (Run 50 times for a stable median)
    results.append(_bench(
        "Concurrent Handshakes (100 users)", 
        lambda: simulate_users(100), 
        iterations=50, 
        warmup=5
    ))
    
    # Simulate 500 concurrent users (Run 20 times because this is extremely heavy)
    results.append(_bench(
        "Concurrent Handshakes (500 users)", 
        lambda: simulate_users(500), 
        iterations=20, 
        warmup=2
    ))
    
    return results

# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def run_all(save_json: str | None = None, iterations: int = 1000, with_pqc: bool = False) -> None:
    print("\n" + "=" * 80)
    print("quantum-safe benchmark suite")
    print("=" * 80)
    print(f"Iterations: {iterations}  Warmup: 100  Outlier trim: 1%")
    print()

    all_results: list[BenchResult] = []

    suites = [
        ("Classical primitives", bench_x25519_keygen),
        ("Classical primitives", bench_x25519_dh),
        ("Classical primitives", bench_ed25519_sign_verify),
        ("HybridKEM (classical half)", bench_hybrid_kem_classical_only),
        ("AES-256-GCM", bench_aes_gcm),
        ("HKDF", bench_hkdf),
        ("Envelope seal/open", bench_envelope_seal_open),
        ("Key serialization", bench_serialization),
        ("Server Load Simulation", bench_concurrent_load),
    ]
    
    # Add the real PQC tests if the flag is passed
    if with_pqc:
        suites.append(("HybridKEM (Real PQC)", bench_hybrid_kem_real))

    current_section = ""
    for section, fn in suites:
        try:
            results = fn()
            if section != current_section:
                print(f"\n── {section} ──")
                current_section = section
            for r in results:
                print(r)
                all_results.append(r)
        except Exception as exc:
            print(f"  [SKIP] {fn.__name__}: {exc}")

    print()
    print("Note: ML-KEM/ML-DSA benchmarks require liboqs-python.")
    print("      Install with: pip install 'quantum-safe[liboqs]'")
    print("      Then run: python tests/bench/bench_kem.py --with-pqc")
    print()

    if save_json:
        import pathlib
        import json
        
        # Ensure the parent directory exists
        out_path = pathlib.Path(save_json)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(out_path, "w") as f:
            json.dump({"results": [r.to_dict() for r in all_results]}, f, indent=2)
        print(f"\nSaved results to {save_json}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="quantum-safe benchmark suite")
    parser.add_argument("--save", metavar="FILE", help="Save JSON results to FILE")
    parser.add_argument("--iterations", type=int, default=1000, help="Iterations per benchmark")
    parser.add_argument("--with-pqc", action="store_true", help="Run real PQC benchmarks")
    args = parser.parse_args()
    run_all(save_json=args.save, iterations=args.iterations, with_pqc=args.with_pqc)
