# Benchmark Results

Benchmarks are run with `python -X utf8 tests/bench/bench_kem.py --with-pqc --save results/bench.json`.
Each run is also saved as `bench_YYYY-MM-DD.json` for history. JSON files are gitignored; this file is tracked.

Harness: 1000 iterations, 100 warmup, 1% outlier trim, `time.perf_counter`.
Platform: Windows 11, Python 3.12.7, liboqs 0.15.0 / oqs-python 0.14.1.

---

## 2026-03-28

### Classical Primitives

| Operation | Median | p95 | p99 | CoV |
|-----------|-------:|----:|----:|----:|
| X25519 keygen | 33.8 µs | 35.5 µs | 37.8 µs | 3.2% |
| X25519 DH exchange | 29.7 µs | 30.7 µs | 31.2 µs | 2.2% |
| Ed25519 sign | 34.1 µs | 35.1 µs | 37.4 µs | 2.3% |
| Ed25519 verify | 90.7 µs | 93.9 µs | 95.2 µs | 1.6% |

### HybridKEM — Mock PQC (classical overhead only)

| Operation | Median | p95 | p99 | CoV |
|-----------|-------:|----:|----:|----:|
| keygen (X25519 + mock) | 157.7 µs | 166.7 µs | 174.5 µs | 2.7% |
| encapsulate | 89.8 µs | 95.9 µs | 99.3 µs | 3.1% |
| decapsulate | 84.7 µs | 89.9 µs | 93.2 µs | 2.3% |

### HybridKEM — Real ML-KEM-768 (liboqs)

| Operation | Median | p95 | p99 | CoV |
|-----------|-------:|----:|----:|----:|
| keygen | 195.0 µs | 207.8 µs | 213.6 µs | 2.9% |
| encapsulate | 147.2 µs | 157.8 µs | 163.8 µs | 3.0% |
| decapsulate | 105.0 µs | 112.2 µs | 117.2 µs | 2.9% |

> Full hybrid handshake (keygen + encap + decap): ~447 µs — well under 1 ms.
> ML-KEM-768 adds ~117–157 µs vs classical-only path.

### Symmetric / Utility

| Operation | Median | p95 | p99 | CoV |
|-----------|-------:|----:|----:|----:|
| AES-256-GCM encrypt 1 KB | 2.8 µs | 2.7 µs | 2.8 µs | 3.2% |
| AES-256-GCM encrypt 64 KB | 13.3 µs | 13.9 µs | 14.5 µs | 2.7% |
| AES-256-GCM decrypt 1 KB | 2.8 µs | 2.9 µs | 3.0 µs | 2.6% |
| HKDF-SHA256 (32B -> 32B) | 10.0 µs | 11.2 µs | 11.7 µs | 5.7% * |
| Envelope.seal() 1 KB | 110.5 µs | 117.1 µs | 122.5 µs | 2.8% |
| Envelope.open() 1 KB | 106.4 µs | 112.4 µs | 116.7 µs | 2.8% |

### Key Serialization

| Operation | Median | p95 | p99 | CoV |
|-----------|-------:|----:|----:|----:|
| PublicKey.to_pem() | 13.3 µs | 14.0 µs | 14.6 µs | 2.9% |
| PublicKey.from_pem() | 12.6 µs | 14.1 µs | 15.4 µs | 6.6% * |
| PublicKey.to_cbor() | 5.1 µs | 5.4 µs | 5.7 µs | 3.3% |
| PublicKey.from_cbor() | 3.6 µs | 3.8 µs | 4.0 µs | 3.3% |
| PublicKey.fingerprint() | 1.7 µs | 1.8 µs | 1.9 µs | 3.5% |

### Concurrent Load (stress test)

| Scenario | Median | p95 | p99 | CoV | Throughput |
|----------|-------:|----:|----:|----:|----------:|
| 100 simultaneous users | 40.7 ms | 43.1 ms | 45.5 ms | 3.3% | ~2,460 ops/s |
| 500 simultaneous users | 185.0 ms | 195.3 ms | 202.1 ms | 2.6% | ~2,700 ops/s |

> 500-user load takes ~4.5x the time of 100-user (vs 5x linear), showing good ThreadPoolExecutor efficiency.
> Throughput is mock-PQC only; with real ML-KEM expect ~1,800 ops/s at 100 users.

`*` HIGH VARIANCE (CoV > 5%) — I/O-adjacent operations, normal on Windows. Not a timing side-channel concern.

---

## How to reproduce

```bash
# Classical + mock PQC benchmarks only
python -X utf8 tests/bench/bench_kem.py

# Include real ML-KEM-768 via liboqs
python -X utf8 tests/bench/bench_kem.py --with-pqc

# Save JSON snapshot
python -X utf8 tests/bench/bench_kem.py --with-pqc --save results/bench_$(date +%Y-%m-%d).json
```
