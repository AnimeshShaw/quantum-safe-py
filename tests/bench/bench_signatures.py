"""
Signature benchmark harness.

Benchmarks signing and verification for all signature schemes in the
quantum-safe library, providing the data for paper Contributions 2, 3, and 4.

Operations measured
-------------------
Classical baselines (known constant-time reference points for CoV analysis):
  - Ed25519 sign          (classical, known constant-time)
  - Ed25519 verify

ML-DSA-65 (FIPS 204 pure PQC, no classical combiner):
  - keygen
  - sign 32-byte message
  - verify 32-byte message

Hybrid (Ed25519 + ML-DSA-65):
  - keygen
  - sign 32-byte message
  - verify 32-byte message

X.509 hybrid certificate:
  - HybridCertificateBuilder.build()   (sign with classical + PQC co-sign)
  - HybridCertificateBuilder.verify_cosig()

Run with::

    # Classical + hybrid (mock PQC) only
    python -X utf8 tests/bench/bench_signatures.py

    # Include real ML-DSA-65 via liboqs
    python -X utf8 tests/bench/bench_signatures.py --with-pqc

    # Save JSON snapshot
    python -X utf8 tests/bench/bench_signatures.py --with-pqc --save results/bench_sigs_$(date +%Y-%m-%d).json

Design
------
Same harness as bench_kem.py:
  - 1000 measurement iterations per operation
  - 100 warmup iterations (discarded)
  - 1% outlier trim from each tail
  - time.perf_counter for nanosecond-resolution timing
  - GC disabled during measurement
  - Report: median, p95, p99, CoV
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


# ---------------------------------------------------------------------------
# Shared BenchResult (mirrors bench_kem.py to keep harnesses consistent)
# ---------------------------------------------------------------------------

@dataclass
class BenchResult:
    """Timing statistics for one benchmarked operation."""

    name: str
    iterations: int
    warmup: int
    samples_us: list[float]   # microseconds, after trim

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
        """Coefficient of variation as percentage (key CoV proxy metric)."""
        if self.mean_us == 0:
            return 0.0
        return (self.stdev_us / self.mean_us) * 100.0

    def to_dict(self) -> dict:
        return {
            "name":       self.name,
            "iterations": self.iterations,
            "warmup":     self.warmup,
            "median_us":  round(self.median_us, 2),
            "mean_us":    round(self.mean_us, 2),
            "p95_us":     round(self.p95_us, 2),
            "p99_us":     round(self.p99_us, 2),
            "stdev_us":   round(self.stdev_us, 2),
            "cov_pct":    round(self.cov_pct, 2),
        }

    def __str__(self) -> str:
        flag = ""
        if self.cov_pct > 5:
            flag = " *"  # HIGH VARIANCE — see paper Contribution 4
        elif self.cov_pct > 3:
            flag = " ~"  # moderate variance
        return (
            f"  {self.name:<45} "
            f"median={self.median_us:8.1f} µs  "
            f"p95={self.p95_us:8.1f} µs  "
            f"CoV={self.cov_pct:.1f}%"
            f"{flag}"
        )


def _bench(
    name: str,
    fn: Callable,
    iterations: int = 1000,
    warmup: int = 100,
) -> BenchResult:
    """Time fn() for warmup+iterations iterations, returning trimmed stats.

    The 1% trim removes extreme outliers caused by OS scheduling jitter
    without distorting the distribution — consistent with the harness in
    bench_kem.py and required for the paper's statistical methodology
    (Benchmark Methodology, §6 of paper outline).
    """
    gc.collect()
    gc.disable()
    try:
        for _ in range(warmup):
            fn()
        samples: list[float] = []
        for _ in range(iterations):
            t0 = time.perf_counter()
            fn()
            t1 = time.perf_counter()
            samples.append((t1 - t0) * 1_000_000)  # → µs
    finally:
        gc.enable()

    samples.sort()
    clip = max(1, int(len(samples) * 0.01))
    samples = samples[clip: len(samples) - clip]
    return BenchResult(name=name, iterations=iterations, warmup=warmup, samples_us=samples)


# ---------------------------------------------------------------------------
# Benchmark suites
# ---------------------------------------------------------------------------

def bench_classical_baselines() -> list[BenchResult]:
    """Ed25519 sign/verify — known constant-time reference points for CoV comparison.

    These form the AES-GCM-equivalent baseline for Contribution 4 (CoV proxy).
    Any PQC operation with CoV <= Ed25519's CoV is considered timing-stable.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    message = b"quantum-safe benchmark message 32"

    sig = priv.sign(message)  # pre-computed for verify bench

    results = []
    results.append(_bench("Ed25519 sign (32B)", lambda: priv.sign(message)))
    results.append(_bench("Ed25519 verify (32B)", lambda: pub.verify(sig, message)))

    return results


def bench_ml_dsa(message_sizes: list[int] | None = None) -> list[BenchResult]:
    """ML-DSA-65 (FIPS 204) benchmarks via liboqs.

    Measures the pure PQC overhead (no classical combiner) so that the
    combiner cost can be isolated: hybrid_overhead = hybrid - classical - pqc_alone.

    Args:
        message_sizes: List of message sizes to benchmark in bytes.
                       Default: [32] (paper uses 32-byte messages).
    """
    try:
        import oqs
    except ImportError:
        print("  [SKIP] liboqs not available — install oqs-python for ML-DSA benchmarks")
        return []

    if message_sizes is None:
        message_sizes = [32]

    results = []

    for msg_size in message_sizes:
        message = os.urandom(msg_size)
        with oqs.Signature("ML-DSA-65") as signer:
            pub_key = signer.generate_keypair()
            sig = signer.sign(message)  # pre-computed

            results.append(
                _bench(
                    f"ML-DSA-65 keygen",
                    lambda: signer.generate_keypair(),
                )
            )
            results.append(
                _bench(
                    f"ML-DSA-65 sign ({msg_size}B)",
                    lambda: signer.sign(message),
                )
            )
            results.append(
                _bench(
                    f"ML-DSA-65 verify ({msg_size}B)",
                    lambda: signer.verify(message, sig, pub_key),
                )
            )

    return results


def bench_hybrid_sign(message_sizes: list[int] | None = None) -> list[BenchResult]:
    """HybridSign (Ed25519 + ML-DSA-65) benchmarks — Contribution 2 data.

    These are the hybrid overhead numbers for the paper.  The combiner cost
    is: hybrid_sign - ed25519_sign - ml_dsa_sign (approx., ignoring KDF).

    Args:
        message_sizes: Message sizes to test. Default: [32].
    """
    from quantum_safe.signatures.hybrid import HybridSign

    if message_sizes is None:
        message_sizes = [32]

    signer = HybridSign()
    results = []

    for msg_size in message_sizes:
        message = os.urandom(msg_size)
        kp = signer.generate_keypair()
        sm = signer.sign(message, kp.secret)  # pre-computed for verify

        results.append(
            _bench(
                f"HybridSign keygen (Ed25519+ML-DSA-65)",
                lambda: signer.generate_keypair(),
            )
        )
        results.append(
            _bench(
                f"HybridSign sign ({msg_size}B)",
                lambda: signer.sign(message, kp.secret),
            )
        )
        results.append(
            _bench(
                f"HybridSign verify ({msg_size}B)",
                lambda: signer.verify(sm, kp.public),
            )
        )

    return results


def bench_x509_hybrid_cert() -> list[BenchResult]:
    """X.509 hybrid certificate build + co-signature verification.

    Measures the protocol-layer overhead for Contribution 5 (Protocol layer
    dimension of the Production Gap Matrix).

    Key data points for the paper:
    - Build time = classical signing + PQC co-signing overhead
    - Verify time = classical cert validation + PQC cosig verification
    """
    from quantum_safe.protocols.x509 import (
        HybridCertificateBuilder,
        generate_classical_keypair_for_cert,
    )
    from quantum_safe.signatures.hybrid import HybridSign

    classical_priv = generate_classical_keypair_for_cert("Ed25519")
    hybrid_signer = HybridSign()
    hybrid_kp = hybrid_signer.generate_keypair()

    builder = HybridCertificateBuilder(
        subject_cn="bench.quantum-safe.internal",
        classical_private_key=classical_priv,
        pqc_keypair=hybrid_kp,
        validity_days=365,
    )

    results = []

    # Build = classical X.509 sign + PQC co-sign
    def _build() -> tuple[bytes, bytes]:
        return builder.build(signer=hybrid_signer)

    results.append(_bench("X.509 HybridCert build (Ed25519+ML-DSA-65)", _build))

    # Verify the co-signature
    cert_pem, cosig_bundle = _build()

    results.append(
        _bench(
            "X.509 HybridCert verify_cosig",
            lambda: HybridCertificateBuilder.verify_cosig(
                cert_pem, cosig_bundle, hybrid_kp.public
            ),
        )
    )

    return results


# ---------------------------------------------------------------------------
# Table printing
# ---------------------------------------------------------------------------

def _print_section(title: str, results: list[BenchResult]) -> None:
    if not results:
        return
    print(f"\n### {title}")
    print(f"  {'Operation':<45} {'Median':>12}  {'p95':>12}  {'CoV':>6}")
    print(f"  {'-'*45} {'-'*12}  {'-'*12}  {'-'*6}")
    for r in results:
        print(r)
    print()


def _save_json(
    all_results: dict[str, list[BenchResult]],
    path: str,
    metadata: dict | None = None,
) -> None:
    """Save all benchmark results to a JSON file for paper reproducibility."""
    import datetime

    data: dict = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "harness": {
            "iterations": 1000,
            "warmup": 100,
            "outlier_trim_pct": 1,
            "timer": "time.perf_counter",
        },
        "metadata": metadata or {},
        "results": {},
    }
    for section, results in all_results.items():
        data["results"][section] = [r.to_dict() for r in results]

    os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    print(f"\nSaved to {path}")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse
    import platform

    parser = argparse.ArgumentParser(
        description="quantum-safe signature benchmarks"
    )
    parser.add_argument(
        "--with-pqc",
        action="store_true",
        help="Include real ML-DSA-65 via liboqs (slow, requires oqs-python)",
    )
    parser.add_argument(
        "--save",
        metavar="PATH",
        default=None,
        help="Save results to a JSON file at PATH",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=1000,
        help="Measurement iterations per operation (default: 1000)",
    )
    args = parser.parse_args()

    print("=" * 70)
    print("quantum-safe Signature Benchmarks")
    print("=" * 70)
    print(f"Platform : {platform.system()} {platform.release()}")
    print(f"Python   : {platform.python_version()}")
    print(f"Iter     : {args.iterations} (+ 100 warmup, 1% trim)")
    print()

    all_results: dict[str, list[BenchResult]] = {}

    print("### Classical Baselines")
    classical = bench_classical_baselines()
    _print_section("Classical Baselines (Ed25519)", classical)
    all_results["classical_baselines"] = classical

    print("### HybridSign (Ed25519 + ML-DSA-65)")
    hybrid = bench_hybrid_sign(message_sizes=[32])
    _print_section("HybridSign", hybrid)
    all_results["hybrid_sign"] = hybrid

    if args.with_pqc:
        print("### ML-DSA-65 Standalone (liboqs)")
        ml_dsa = bench_ml_dsa(message_sizes=[32])
        _print_section("ML-DSA-65 Standalone", ml_dsa)
        all_results["ml_dsa_standalone"] = ml_dsa

    print("### X.509 Hybrid Certificates")
    x509 = bench_x509_hybrid_cert()
    _print_section("X.509 Hybrid Certs", x509)
    all_results["x509_hybrid_cert"] = x509

    # CoV summary for Contribution 4
    print("### CoV Summary (side-channel proxy — threshold 3.0%)")
    print(f"  {'Operation':<45} {'CoV':>6}  {'Status'}")
    print(f"  {'-'*45} {'-'*6}  {'-'*15}")
    for section_results in all_results.values():
        for r in section_results:
            status = "OK" if r.cov_pct <= 3.0 else ("FLAG *" if r.cov_pct > 5 else "WATCH ~")
            print(f"  {r.name:<45} {r.cov_pct:>5.1f}%  {status}")

    print()
    print("* HIGH VARIANCE (CoV > 5%) — I/O-adjacent operations expected on Windows.")
    print("~ MODERATE (CoV 3-5%) — flag for further investigation.")

    if args.save:
        metadata = {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "with_pqc": args.with_pqc,
        }
        _save_json(all_results, args.save, metadata)


if __name__ == "__main__":
    main()
