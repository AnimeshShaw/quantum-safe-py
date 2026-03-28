Benchmarking
============

The benchmark suite measures every cryptographic operation in the library and
provides the data for the research paper contributions. This guide explains how
to run the benchmarks, what each harness covers, and how to interpret the output.

Authoritative results are stored in ``results/BENCHMARKS.md``. That file is the
canonical record; this guide explains how to reproduce and extend them.

.. contents::
   :local:
   :depth: 2

----

Test environments
-----------------

Two environments are used. Results differ primarily due to the liboqs build and
the OS scheduler. **ENV-2 (Docker/Linux) is the primary reference** for paper claims.

.. list-table::
   :header-rows: 1
   :widths: 15 42 43

   * - Label
     - ENV-1 — Windows 11 Native
     - ENV-2 — Docker / WSL2 Linux (Primary)
   * - OS
     - Windows 11 Home 10.0.26200
     - Linux 6.6.87.2-microsoft-standard-WSL2 (Hyper-V)
   * - Python
     - 3.12.7
     - 3.12.13 (python:3.12-slim)
   * - liboqs
     - 0.15.0 MSYS2 DLL (generic build)
     - 0.15.0 compiled from source (``-DOQS_DIST_BUILD=ON``)
   * - Scheduler noise
     - 15.6 ms NT timer resolution inflates CoV
     - WSL2 vCPU adds ~2–4% CoV above bare-metal Linux

.. note::

   The from-source Docker build enables AVX2/AVX-512 CPUID detection at runtime
   (``-DOQS_DIST_BUILD=ON``), giving ML-KEM-768 keygen a **5.3× speedup** over the
   Windows MSYS2 DLL.  CoV analysis in the paper uses ENV-2 values exclusively.

----

Benchmark harnesses
-------------------

Two harness scripts live in ``tests/bench/``:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Script
     - What it measures
   * - ``bench_kem.py``
     - KEM operations: X25519 classical, mock-PQC hybrid, real ML-KEM-768 hybrid,
       hybrid decomposition (combiner overhead isolation), concurrent throughput curve
   * - ``bench_signatures.py``
     - Signature operations: Ed25519 baseline, ML-DSA-65 standalone, HybridSign
       (Ed25519+ML-DSA-65), X.509 hybrid certificate build and cosig verify

All harnesses share the same methodology:

- **1000** measurement iterations per operation
- **100** warmup iterations (discarded)
- **1%** outlier trim from each tail (removes OS-scheduler spikes)
- ``time.perf_counter`` for nanosecond-resolution timing
- GC disabled during measurement

----

Running the benchmarks
-----------------------

Docker (recommended — ENV-2)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The Docker image compiles liboqs 0.15.0 from source with AVX2/AVX-512 support.
This is the reproducible, ENV-2 path used for all primary paper numbers.

.. code-block:: bash

   # Build once — compiles liboqs 0.15.0 from source (~3 min on a modern laptop)
   docker build -t quantum-safe-bench .

   # KEM suite: classical + hybrid decomposition + concurrent load curve
   docker run --rm -v ${PWD}/results:/app/results quantum-safe-bench \
     python -X utf8 tests/bench/bench_kem.py --with-pqc \
     --save results/bench_kem_$(date +%Y-%m-%d).json

   # Signature suite: Ed25519 + ML-DSA-65 + HybridSign + X.509 certs
   docker run --rm -v ${PWD}/results:/app/results quantum-safe-bench \
     python -X utf8 tests/bench/bench_signatures.py --with-pqc \
     --save results/bench_sigs_$(date +%Y-%m-%d).json

   # Or run both in one go with docker-compose
   docker compose up

KEM benchmarks (native)
~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   # Classical + mock PQC (no liboqs needed)
   python -X utf8 tests/bench/bench_kem.py

   # Full suite — real ML-KEM-768 + decomposition + extended concurrent load
   python -X utf8 tests/bench/bench_kem.py --with-pqc

   # Save JSON snapshot for statistical post-processing
   python -X utf8 tests/bench/bench_kem.py --with-pqc \
     --save results/bench_kem_$(date +%Y-%m-%d).json

Signature benchmarks (native)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: bash

   # Ed25519 baselines + HybridSign + X.509 certs
   python -X utf8 tests/bench/bench_signatures.py

   # Add standalone ML-DSA-65 (requires liboqs)
   python -X utf8 tests/bench/bench_signatures.py --with-pqc

   # Save JSON snapshot
   python -X utf8 tests/bench/bench_signatures.py --with-pqc \
     --save results/bench_sigs_$(date +%Y-%m-%d).json

.. note::

   ``-X utf8`` forces UTF-8 output on Windows, which is required for the µ
   character in the timing output. On Linux/macOS this flag is harmless.

   On Windows, ``oqs.dll`` must be discoverable. Set ``OQS_DLL_DIR`` to the
   directory containing ``oqs.dll`` (e.g. ``C:\Users\<you>\_oqs\bin``), or place
   the DLL at ``~\_oqs\bin\oqs.dll`` — the ``_oqs_path.py`` helper registers it
   automatically via ``os.add_dll_directory``.

----

Reading the output
------------------

Each operation prints one line::

  Ed25519 sign (32B)                            median=   41.4 µs  p95=   46.4 µs  CoV=6.9% *

.. list-table::
   :header-rows: 1
   :widths: 15 85

   * - Column
     - Meaning
   * - ``median``
     - 50th-percentile latency — the headline number for the paper
   * - ``p95``
     - 95th-percentile — worst case for 95% of calls
   * - ``CoV``
     - Coefficient of variation (stdev / mean × 100) — side-channel proxy
   * - ``*``
     - CoV > 5% — high variance (see below)
   * - ``~``
     - CoV 3–5% — moderate variance

----

CoV as a side-channel proxy
----------------------------

The coefficient of variation (CoV) is the primary metric for the
timing side-channel analysis (paper Contribution 4).

The baseline reference is AES-256-GCM, which is universally accepted as
constant-time. Any operation with CoV ≤ AES-GCM's CoV is considered
timing-stable on that platform.

**ENV-2 (Docker/WSL2) noise floor: ~2.1%** — AES-256-GCM 1 KB encrypt.
Operations within ~2% CoV are timing-stable. The paper uses this per-environment
floor rather than a fixed global threshold, since the WSL2 hypervisor adds
residual jitter above bare-metal Linux (~0.5–1.5%).

.. list-table:: ENV-2 CoV reference values (2026-03-28)
   :header-rows: 1
   :widths: 40 15 45

   * - Operation
     - CoV
     - Assessment
   * - AES-256-GCM 1 KB (baseline)
     - 2.1%
     - Noise floor — constant-time reference
   * - Ed25519 verify
     - 2.2%
     - ✓ Timing-stable
   * - PublicKey.fingerprint()
     - 2.0%
     - ✓ Timing-stable
   * - HKDF-SHA256
     - 2.8%
     - ✓ Within noise floor
   * - ML-KEM-768 encapsulate
     - 9.4%
     - WSL2 vCPU scheduler noise; no secret-dep. branching in FIPS 203
   * - ML-DSA-65 sign
     - 52.4%
     - ✓ Expected — FIPS 204 hedged signing randomness

**Why ML-DSA sign has high CoV (~52%)**

ML-DSA-65 (FIPS 204) uses *hedged signing*: a fresh 32-byte random string
is generated per signing call and mixed into the lattice rejection-sampling
loop. Different random draws cause the loop to run a different number of
iterations, producing genuine timing variation at the µs scale. This is not
a timing side-channel — it is the intended behaviour of the algorithm.

**Why CoV is higher on Windows**

The Windows NT scheduler has a default timer resolution of 15.6 ms. For
sub-millisecond operations, a single scheduler interruption can spike a
sample by 10–20×. This is why operations that show CoV ~2% in Docker/Linux
show CoV ~5–10% on Windows. The paper reports ENV-2 (Linux) values for the
CoV analysis and notes ENV-1 (Windows) values as calibration reference only.

----

Hybrid decomposition
--------------------

The ``--with-pqc`` KEM run includes a *decomposition table* that isolates
each component's contribution:

.. list-table::
   :header-rows: 1
   :widths: 10 30 60

   * - Tier
     - Label
     - What it runs
   * - ①
     - X25519 only
     - Pure classical: keygen + DH exchange (no PQC)
   * - ②
     - ML-KEM-768 only
     - Pure PQC: keygen + encapsulate + decapsulate (liboqs, no classical)
   * - ③
     - HybridKEM full
     - Both combined: keygen + encapsulate + decapsulate

Combiner overhead ≈ ③ − ① − ② (per operation). This cost is dominated by
HKDF-SHA256 and key serialisation, not by the algorithms themselves.

ENV-2 combiner overhead (Docker/WSL2, 2026-03-28):

- **keygen combiner**: ~94.0 µs (Python wiring + HKDF + key serialisation)
- **encapsulate combiner**: ~57.0 µs
- **decapsulate combiner**: ~51.0 µs

ENV-1 combiner overhead (Windows native, 2026-03-28) — for reference:

- **keygen combiner**: ~110.6 µs
- **encapsulate combiner**: ~74.1 µs
- **decapsulate combiner**: ~90.6 µs

Combiner cost is dominated by HKDF-SHA256 and Python key serialisation (PEM/CBOR
encoding), not by the cryptographic algorithms.  The ENV-2 vs ENV-1 difference
reflects the Linux kernel's faster context-switch overhead for short Python calls.

----

Concurrent throughput curve
----------------------------

The ``--with-pqc`` KEM run measures throughput at four concurrency tiers using
``concurrent.futures.ThreadPoolExecutor``. Each task = one complete hybrid KEM
handshake (keygen + encapsulate + decapsulate) with real ML-KEM-768.

ENV-2 results (Docker/WSL2, 2026-03-28):

.. list-table::
   :header-rows: 1
   :widths: 20 25 25 30

   * - Concurrent users
     - Wall-clock median
     - Throughput
     - Note
   * - 100
     - 50.2 ms
     - ~1,992 ops/s
     - Baseline
   * - 500
     - 232.4 ms
     - ~2,151 ops/s
     - Peak throughput
   * - 1,000
     - 478.7 ms
     - ~2,089 ops/s
     - Stable
   * - 5,000
     - 2,487.8 ms
     - ~2,009 ops/s
     - −6.6% vs peak; −0.8% vs 100-user baseline

Throughput is near-constant at ~2,000–2,150 ops/s from 100 to 5,000 users.
This validates GIL-release during liboqs C calls — true thread parallelism
despite Python's GIL. The −6.6% drop from peak to 5,000 users is within
normal Python thread-pool scheduling variance.

----

Signature benchmark key numbers
---------------------------------

ENV-2 headline latencies (Docker/WSL2, 2026-03-28):

.. list-table::
   :header-rows: 1
   :widths: 40 15 15 15 15

   * - Operation
     - Median
     - p95
     - CoV
     - Note
   * - Ed25519 sign (32 B)
     - 33.5 µs
     - 42.0 µs
     - 10.1%
     - WSL2 vCPU noise
   * - Ed25519 verify (32 B)
     - 106.9 µs
     - 116.6 µs
     - 4.0%
     - ✓ Near noise floor
   * - ML-DSA-65 sign (32 B)
     - 100.5 µs
     - 242.6 µs
     - 52.4%
     - Expected — FIPS 204 hedged signing
   * - ML-DSA-65 verify (32 B)
     - 45.4 µs
     - 53.7 µs
     - 6.2%
     -
   * - HybridSign sign (32 B)
     - 138.8 µs
     - 253.6 µs
     - 31.3%
     - Dominated by ML-DSA hedged signing
   * - HybridSign verify (32 B)
     - 133.2 µs
     - 172.7 µs
     - 13.4%
     - +25% vs Ed25519 verify alone
   * - X.509 HybridCert build
     - 313.8 µs
     - 479.2 µs
     - 23.1%
     - Ed25519 + ML-DSA-65 cosign
   * - X.509 HybridCert verify_cosig
     - 255.4 µs
     - 300.3 µs
     - 14.8%
     -

**Paper headline figures (ENV-2):**

- Full hybrid KEM handshake (keygen + encap + decap): **~301 µs**
- Full hybrid signature cycle (keygen + sign + verify): **~468 µs**
- Full hybrid cert issuance: **~314 µs**
- Throughput at 5,000 users: **~2,009 ops/s** (−6.6% vs peak)

All values are sub-millisecond, confirming production viability at TLS handshake
rates. See ``results/BENCHMARKS.md`` for complete tables, ENV-1 comparison, and
the cross-environment speedup analysis.

----

Statistical post-processing
-----------------------------

``tests/bench/bench_stats.py`` provides pure-Python (no scipy) statistical
utilities for converting raw samples to paper-quality numbers.

.. code-block:: python

   import sys
   sys.path.insert(0, 'tests/bench')
   from bench_stats import (
       bootstrap_ci, welch_t_test, cohens_d,
       latex_table, cov_stability_report, describe_samples,
   )

   # 95% bootstrap confidence interval (Efron 1979 percentile method)
   lo, median, hi = bootstrap_ci(samples_us, confidence=0.95, n_resamples=2000)

   # Welch's t-test (no equal-variance assumption)
   result = welch_t_test(classical_samples, hybrid_samples)
   print(f"p={result.p_value:.4f}  significant={result.significant}")
   print(f"overhead={result.overhead_pct:.1f}%")

   # Cohen's d effect size
   d = cohens_d(classical_samples, hybrid_samples)

   # LaTeX booktabs table (paste directly into paper)
   table = latex_table(
       rows=[["X25519", "33", "35", "3.8%"],
             ["ML-KEM-768", "96", "130", "12.8%"]],
       columns=["Algorithm", "Median (µs)", "p95 (µs)", "CoV"],
       caption="KEM operation latency",
       label="tab:kem-latency",
   )
   print(table)

**Available functions:**

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Function
     - Purpose
   * - ``bootstrap_ci(samples, confidence, n_resamples, seed)``
     - Percentile bootstrap CI for the median
   * - ``welch_t_test(a, b, alpha)``
     - Welch's t-test → p-value, df, significance, overhead%
   * - ``cohens_d(a, b)``
     - Pooled-SD effect size
   * - ``throughput_curve(points)``
     - ops/s and scaling efficiency per concurrency tier
   * - ``cov_stability_report(results, threshold)``
     - Flag operations above CoV threshold
   * - ``describe_samples(samples)``
     - Full summary: median, mean, p95, p99, stdev, CoV
   * - ``latex_table(rows, columns, caption, label)``
     - booktabs-formatted LaTeX table string

----

Results storage
---------------

Benchmark runs produce two kinds of output:

.. list-table::
   :header-rows: 1
   :widths: 35 65

   * - File
     - Description
   * - ``results/BENCHMARKS.md``
     - Human-readable research record — **tracked in git**, canonical reference
   * - ``results/bench_*.json``
     - Machine-readable JSON snapshots — **gitignored** (large, machine-specific)

``results/BENCHMARKS.md`` is the authoritative document. It records methodology,
dual-environment descriptions (ENV-1 / ENV-2), full result tables, CoV analysis,
cross-environment comparison, and paper headline numbers. Update it after every
authoritative benchmark run.

The JSON structure::

    {
      "generated_at": "2026-03-28T...",
      "harness": {"iterations": 1000, "warmup": 100, "outlier_trim_pct": 1},
      "results": {
        "classical_baselines": [
          {"name": "X25519 keygen", "median_us": 36.9, "p95_us": 40.5,
           "cov_pct": 4.0, "mean_us": 37.1, "stdev_us": 1.5, ...}
        ]
      }
    }
