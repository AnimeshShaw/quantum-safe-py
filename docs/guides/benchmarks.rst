Benchmarking
============

The benchmark suite measures every cryptographic operation in the library and
provides the data for the research paper contributions. This guide explains how
to run the benchmarks, what each harness covers, and how to interpret the output.

.. contents::
   :local:
   :depth: 2

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

KEM benchmarks
~~~~~~~~~~~~~~

.. code-block:: bash

   # Classical + mock PQC (no liboqs needed)
   python -X utf8 tests/bench/bench_kem.py

   # Full suite — real ML-KEM-768 + decomposition + extended concurrent load
   python -X utf8 tests/bench/bench_kem.py --with-pqc

   # Save JSON snapshot for statistical post-processing
   python -X utf8 tests/bench/bench_kem.py --with-pqc \
     --save results/bench_kem_$(date +%Y-%m-%d).json

Signature benchmarks
~~~~~~~~~~~~~~~~~~~~

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
timing-stable. In practice the threshold used is **3%** (slightly above
AES-GCM's ~1.8% to allow for OS scheduling noise).

**Why ML-DSA sign has high CoV (~50%)**

ML-DSA-65 (FIPS 204) uses *hedged signing*: a fresh 32-byte random string
is generated per signing call and mixed into the lattice rejection-sampling
loop. Different random draws cause the loop to run a different number of
iterations, producing genuine timing variation at the µs scale. This is not
a timing side-channel — it is the intended behaviour of the algorithm.

**Why CoV is higher on Windows**

The Windows OS scheduler has a default timer resolution of 15.6 ms. For
sub-millisecond operations, a single scheduler interruption can spike a
sample by 10–20×. This is why operations that show CoV ~1–2% on Linux show
CoV ~5–10% on Windows. The paper reports Linux values for the CoV analysis
and notes Windows values as a calibration reference.

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

Benchmark result (run 2, 2026-03-28):

- **keygen combiner**: ~110.6 µs (Python wiring + HKDF + serialisation)
- **encapsulate combiner**: ~74.1 µs
- **decapsulate combiner**: ~90.6 µs

----

Concurrent throughput curve
----------------------------

The ``--with-pqc`` KEM run also measures throughput at four concurrency tiers
using ``concurrent.futures.ThreadPoolExecutor``:

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
     - 239.3 ms
     - ~2,090 ops/s
     - Near-linear scaling
   * - 1,000
     - 501.3 ms
     - ~1,996 ops/s
     - Stable
   * - 5,000
     - 2,549.9 ms
     - ~1,961 ops/s
     - −1.6% vs 100-user baseline

Throughput stays near-constant at ~2,000 ops/s from 100 to 5,000 users.
This validates GIL-release during liboqs C calls — true thread parallelism
despite Python's GIL.

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
     - Human-readable markdown summary — **tracked in git**
   * - ``results/bench_*.json``
     - Machine-readable JSON snapshots — **gitignored** (large, noisy)

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
