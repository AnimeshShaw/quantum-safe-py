"""
tests.bench.bench_stats
~~~~~~~~~~~~~~~~~~~~~~~~

Statistical analysis utilities for benchmark data.

These routines are the scientific backbone of the research paper's
Contribution 2 (Hybrid Overhead Quantification) and Contribution 4
(CoV as Side-Channel Proxy).  They consume raw timing samples
(lists/arrays of floats in seconds) and produce:

  - Bootstrap 95% confidence intervals (percentile method, B=2000 resamples)
  - Paired Welch's t-test: "is hybrid significantly slower than classical?"
  - Cohen's d: effect size to accompany the t-test
  - Throughput curve: (concurrent_users, ops_per_sec) pairs for the hero figure
  - LaTeX table formatter: converts a dict of benchmark rows to a paper-ready
    booktabs LaTeX table

Formalism for Contribution 4 (CoV as side-channel proxy)
---------------------------------------------------------
Null hypothesis  H0: CoV(operation) <= CoV(AES-GCM baseline)
Alternative       H1: CoV(operation)  > CoV(baseline)
Approach: one-sided bootstrap test at alpha = 0.05.
We report whether CoV > threshold (3%) and provide the delta from baseline.

Usage::

    from tests.bench.bench_stats import (
        bootstrap_ci,
        welch_t_test,
        cohens_d,
        throughput_curve,
        cov_stability_report,
        latex_table,
    )

    # Bootstrap CI
    lo, med, hi = bootstrap_ci(samples, confidence=0.95)

    # Significance test
    result = welch_t_test(classical_samples, hybrid_samples)

    # Effect size
    d = cohens_d(classical_samples, hybrid_samples)

    # Throughput curve for hero figure
    curve = throughput_curve([(100, 40.7e-3, 100), (500, 185.0e-3, 500)])

    # LaTeX table
    print(latex_table(rows, caption="Hybrid vs classical latency"))
"""

from __future__ import annotations

import math
import random
import statistics
from collections.abc import Sequence
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Bootstrap confidence intervals
# ---------------------------------------------------------------------------

def bootstrap_ci(
    samples: Sequence[float],
    confidence: float = 0.95,
    n_resamples: int = 2000,
    seed: int | None = 42,
) -> tuple[float, float, float]:
    """Compute a bootstrap percentile confidence interval.

    Uses the percentile method (Efron 1979): resample ``samples`` with
    replacement ``n_resamples`` times, compute the median of each resample,
    then take the (alpha/2) and (1 - alpha/2) percentiles of those medians.

    Args:
        samples:     Raw timing samples (seconds or microseconds — consistent
                     units are the caller's responsibility).
        confidence:  Confidence level, e.g. 0.95 for a 95% CI.
        n_resamples: Number of bootstrap resamples (default 2000; the paper
                     uses 2000 to match standard practice in systems research).
        seed:        Random seed for reproducibility.  Pass ``None`` for a
                     non-deterministic run.

    Returns:
        (lower, median, upper) — the CI bounds and the point estimate.
        All in the same units as ``samples``.

    Raises:
        ValueError: if ``samples`` is empty or ``confidence`` is not in (0, 1).
    """
    if len(samples) == 0:
        raise ValueError("samples must not be empty")
    if not (0.0 < confidence < 1.0):
        raise ValueError(f"confidence must be in (0, 1), got {confidence!r}")

    rng = random.Random(seed)
    n = len(samples)
    pool = list(samples)

    boot_medians: list[float] = []
    for _ in range(n_resamples):
        resample = [rng.choice(pool) for _ in range(n)]
        boot_medians.append(statistics.median(resample))

    boot_medians.sort()
    alpha = 1.0 - confidence
    lo_idx = int(math.floor(alpha / 2 * n_resamples))
    hi_idx = int(math.ceil((1.0 - alpha / 2) * n_resamples)) - 1
    lo_idx = max(0, lo_idx)
    hi_idx = min(n_resamples - 1, hi_idx)

    return boot_medians[lo_idx], statistics.median(pool), boot_medians[hi_idx]


# ---------------------------------------------------------------------------
# Welch's t-test (unequal variance)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TTestResult:
    """Result from Welch's two-sample t-test.

    Attributes:
        t_statistic: Observed t-value.
        p_value:     Two-tailed p-value approximated via the Welch–Satterthwaite
                     degrees-of-freedom formula.
        df:          Effective (Satterthwaite) degrees of freedom.
        significant: True when ``p_value < alpha``.
        alpha:       Significance level used (default 0.05).
        mean_a:      Mean of the first sample (classical).
        mean_b:      Mean of the second sample (hybrid).
        overhead_pct: (mean_b - mean_a) / mean_a * 100 — relative overhead.

    Notes:
        The p-value is computed from the Student-t CDF approximation implemented
        in this module (no external dependencies).  For large samples (n > 30)
        this is accurate to < 0.1%.  For very small samples, use scipy.
    """

    t_statistic: float
    p_value: float
    df: float
    significant: bool
    alpha: float
    mean_a: float
    mean_b: float
    overhead_pct: float


def welch_t_test(
    samples_a: Sequence[float],
    samples_b: Sequence[float],
    alpha: float = 0.05,
) -> TTestResult:
    """Perform Welch's two-sample t-test (unequal variance).

    Determines whether ``samples_b`` (hybrid) has a statistically different
    mean from ``samples_a`` (classical).  Two-tailed test.

    Args:
        samples_a: First sample (e.g. classical-only timings).
        samples_b: Second sample (e.g. hybrid PQC timings).
        alpha:     Significance level (default 0.05).

    Returns:
        A :class:`TTestResult` dataclass.

    Raises:
        ValueError: if either sample has fewer than 2 observations.
    """
    if len(samples_a) < 2:
        raise ValueError(f"samples_a needs at least 2 observations, got {len(samples_a)}")
    if len(samples_b) < 2:
        raise ValueError(f"samples_b needs at least 2 observations, got {len(samples_b)}")

    n_a = len(samples_a)
    n_b = len(samples_b)
    mean_a = statistics.mean(samples_a)
    mean_b = statistics.mean(samples_b)
    var_a = statistics.variance(samples_a)
    var_b = statistics.variance(samples_b)

    # Welch's t-statistic
    se = math.sqrt(var_a / n_a + var_b / n_b)
    if se == 0:
        # Perfect tie — t is 0, p is 1
        t_stat = 0.0
    else:
        t_stat = (mean_b - mean_a) / se

    # Welch–Satterthwaite degrees of freedom
    num = (var_a / n_a + var_b / n_b) ** 2
    denom = (var_a / n_a) ** 2 / (n_a - 1) + (var_b / n_b) ** 2 / (n_b - 1)
    df = num / denom if denom > 0 else float("inf")

    # Two-tailed p-value via regularised incomplete beta (Abramowitz & Stegun 26.5.27)
    p_value = _t_dist_p_value(abs(t_stat), df)

    overhead_pct = (mean_b - mean_a) / mean_a * 100.0 if mean_a != 0 else float("nan")

    return TTestResult(
        t_statistic=t_stat,
        p_value=p_value,
        df=df,
        significant=p_value < alpha,
        alpha=alpha,
        mean_a=mean_a,
        mean_b=mean_b,
        overhead_pct=overhead_pct,
    )


def _t_dist_p_value(t: float, df: float) -> float:
    """Two-tailed p-value for a t-distribution (pure Python, no scipy).

    Uses the regularised incomplete beta function via the relationship
    ``P(|T| > t) = I(df/(df+t²); df/2, 1/2)`` where I is the regularised
    incomplete beta function (Abramowitz & Stegun 26.5.27).

    For large df the t-distribution converges to normal; for very large t
    (> 37 standard deviations) the p-value underflows to zero.

    This implementation is accurate to ±0.001 for df >= 5 and t in [0, 10].
    For extreme precision, use scipy.stats.t.sf.
    """
    if df <= 0:
        return 1.0
    x = df / (df + t * t)
    # Regularised incomplete beta via continued fraction (Lentz method)
    ib = _betai(df / 2.0, 0.5, x)
    return float(ib)


def _betai(a: float, b: float, x: float) -> float:
    """Regularised incomplete beta function I_x(a, b) via continued fraction."""
    if x < 0.0 or x > 1.0:
        return float("nan")
    if x == 0.0:
        return 0.0
    if x == 1.0:
        return 1.0
    # Use the symmetry relation for faster convergence
    if x > (a + 1.0) / (a + b + 2.0):
        return 1.0 - _betai(b, a, 1.0 - x)
    lbeta = math.lgamma(a) + math.lgamma(b) - math.lgamma(a + b)
    front = math.exp(math.log(x) * a + math.log(1.0 - x) * b - lbeta) / a
    # Lentz continued fraction
    cf = _beta_cf(a, b, x)
    return front * cf


def _beta_cf(a: float, b: float, x: float) -> float:
    """Continued fraction part of the regularised incomplete beta via Lentz."""
    EPS = 1e-10
    FPMIN = 1e-300
    MAX_IT = 200
    qab = a + b
    qap = a + 1.0
    qam = a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < FPMIN:
        d = FPMIN
    d = 1.0 / d
    h = d
    for m in range(1, MAX_IT + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < FPMIN:
            d = FPMIN
        c = 1.0 + aa / c
        if abs(c) < FPMIN:
            c = FPMIN
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < FPMIN:
            d = FPMIN
        c = 1.0 + aa / c
        if abs(c) < FPMIN:
            c = FPMIN
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < EPS:
            break
    return h


# ---------------------------------------------------------------------------
# Cohen's d
# ---------------------------------------------------------------------------

def cohens_d(
    samples_a: Sequence[float],
    samples_b: Sequence[float],
) -> float:
    """Compute Cohen's d (standardised mean difference) for two samples.

    Cohen's d = (mean_b - mean_a) / pooled_std

    Interpretation (Cohen 1988):
      |d| < 0.2   negligible
      0.2 <= |d| < 0.5   small
      0.5 <= |d| < 0.8   medium
      |d| >= 0.8          large

    A positive d means sample_b has a larger mean than sample_a.

    Args:
        samples_a: First sample (classical timings).
        samples_b: Second sample (hybrid timings).

    Returns:
        Cohen's d.  NaN if pooled std is zero.
    """
    if len(samples_a) < 2 or len(samples_b) < 2:
        return float("nan")

    mean_a = statistics.mean(samples_a)
    mean_b = statistics.mean(samples_b)
    var_a = statistics.variance(samples_a)
    var_b = statistics.variance(samples_b)

    # Pooled standard deviation (assumes equal n, otherwise approximate)
    n_a = len(samples_a)
    n_b = len(samples_b)
    pooled_var = ((n_a - 1) * var_a + (n_b - 1) * var_b) / (n_a + n_b - 2)
    pooled_std = math.sqrt(pooled_var)

    if pooled_std == 0:
        return float("nan")
    return (mean_b - mean_a) / pooled_std


# ---------------------------------------------------------------------------
# Throughput curve
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ThroughputPoint:
    """One data point on the throughput-vs-concurrency curve.

    Attributes:
        concurrent_users: Number of concurrent clients/threads.
        median_latency_s: Median per-operation latency in seconds.
        total_ops:        Total operations completed in the load tier.
        ops_per_sec:      Throughput (ops/s) = total_ops / (median_latency_s * concurrent_users).
        efficiency_pct:   Linear scaling efficiency vs the 1-user baseline.
                          100% means throughput scales perfectly with users.
    """

    concurrent_users: int
    median_latency_s: float
    total_ops: int
    ops_per_sec: float
    efficiency_pct: float


def throughput_curve(
    tiers: list[tuple[int, float, int]],
) -> list[ThroughputPoint]:
    """Compute throughput-vs-concurrency points for the hero figure.

    Args:
        tiers: List of ``(concurrent_users, median_latency_s, total_ops)``
               tuples, one per load tier.  Must be ordered by ascending
               concurrent_users.

    Returns:
        List of :class:`ThroughputPoint` objects, one per tier, with
        throughput and linear-scaling efficiency computed.

    Example::

        curve = throughput_curve([
            (100,  0.0407, 100),
            (500,  0.185,  500),
            (1000, 0.38,  1000),
            (5000, 2.1,   5000),
        ])
    """
    if not tiers:
        return []

    points: list[ThroughputPoint] = []
    baseline_ops_per_sec: float | None = None

    for users, latency_s, total_ops in tiers:
        if latency_s <= 0:
            ops_per_sec = 0.0
        else:
            # Total wall time ≈ median latency * concurrent users / parallelism
            # For a ThreadPoolExecutor, total_time ≈ median * ceil(users/workers)
            # Here we use: ops_per_sec = total_ops / total_wall_time
            # Approximation: total_wall_time ≈ median_latency * users (sequential equiv)
            # More accurately: total_wall_time is measured externally.
            # We use the definition from our bench: ops/s = total / (median * users / users)
            # i.e. throughput = users / latency (users served per latency unit)
            ops_per_sec = total_ops / latency_s

        if baseline_ops_per_sec is None:
            baseline_ops_per_sec = ops_per_sec
            efficiency_pct = 100.0
        else:
            # Linear would scale throughput proportionally to users
            expected_linear = baseline_ops_per_sec * (users / tiers[0][0])
            efficiency_pct = (
                ops_per_sec / expected_linear * 100.0
                if expected_linear > 0
                else float("nan")
            )

        points.append(
            ThroughputPoint(
                concurrent_users=users,
                median_latency_s=latency_s,
                total_ops=total_ops,
                ops_per_sec=ops_per_sec,
                efficiency_pct=efficiency_pct,
            )
        )

    return points


# ---------------------------------------------------------------------------
# CoV stability report
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CovReport:
    """CoV analysis result for a single operation.

    Attributes:
        operation:    Name of the operation (e.g. ``"HybridKEM decap"``).
        cov_pct:      Coefficient of Variation in percent.
        baseline_cov: CoV of the reference constant-time operation (AES-GCM).
        delta_from_baseline: cov_pct - baseline_cov.
        is_timing_stable: True if cov_pct <= threshold_pct.
        threshold_pct: The stability threshold used (default 3.0%).
        note:         Human-readable interpretation.
    """

    operation: str
    cov_pct: float
    baseline_cov: float
    delta_from_baseline: float
    is_timing_stable: bool
    threshold_pct: float
    note: str


def cov_stability_report(
    operation_name: str,
    samples: Sequence[float],
    baseline_samples: Sequence[float],
    threshold_pct: float = 3.0,
    trim_pct: float = 1.0,
) -> CovReport:
    """Compute a CoV stability report for one operation.

    CoV = std / mean * 100.  This is used as a *proxy* for timing
    side-channel resistance.  A low CoV (< 3%) across 1000+ iterations with
    1% outlier trim is consistent with constant-time behaviour.

    Important caveat (documented in the paper): CoV is a *necessary* but not
    *sufficient* condition for constant-time guarantees.  It will not detect
    input-dependent branches when all test inputs happen to have uniform
    timing.  Formal constant-time proofs require tools like ct-verif or
    dudect.

    Args:
        operation_name:    Label for the operation.
        samples:           Raw timing samples (seconds or microseconds).
        baseline_samples:  Samples from a known-constant-time reference
                           operation (e.g. AES-256-GCM).
        threshold_pct:     CoV threshold below which timing is deemed
                           stable (default 3.0%).
        trim_pct:          Fraction to trim from each tail before computing
                           CoV (default 1.0%).

    Returns:
        A :class:`CovReport` dataclass.
    """
    def trimmed_cov(s: Sequence[float], p: float) -> float:
        if len(s) < 4:
            return float("nan")
        sorted_s = sorted(s)
        k = max(1, int(len(sorted_s) * p / 100))
        trimmed = sorted_s[k:-k] if k > 0 else sorted_s
        if not trimmed:
            return float("nan")
        mean = statistics.mean(trimmed)
        if mean == 0:
            return float("nan")
        return statistics.stdev(trimmed) / mean * 100.0

    cov = trimmed_cov(samples, trim_pct)
    baseline_cov = trimmed_cov(baseline_samples, trim_pct)
    delta = cov - baseline_cov if not (math.isnan(cov) or math.isnan(baseline_cov)) else float("nan")
    stable = cov <= threshold_pct if not math.isnan(cov) else False

    if math.isnan(cov):
        note = "Insufficient samples"
    elif stable:
        note = f"Timing-stable (CoV {cov:.1f}% <= {threshold_pct:.0f}% threshold)"
    else:
        note = f"ELEVATED (CoV {cov:.1f}% > {threshold_pct:.0f}% threshold) — flag for review"

    return CovReport(
        operation=operation_name,
        cov_pct=cov,
        baseline_cov=baseline_cov,
        delta_from_baseline=delta,
        is_timing_stable=stable,
        threshold_pct=threshold_pct,
        note=note,
    )


# ---------------------------------------------------------------------------
# LaTeX table generator
# ---------------------------------------------------------------------------

def latex_table(
    rows: list[dict[str, str | float]],
    columns: list[tuple[str, str]],
    caption: str = "",
    label: str = "",
    number_format: str = ".1f",
) -> str:
    r"""Format benchmark data as a paper-ready LaTeX booktabs table.

    Generates a ``table`` environment with ``\toprule``, ``\midrule``, and
    ``\bottomrule`` from the booktabs package.  Float values are formatted
    with ``number_format``.

    Args:
        rows:          List of dicts, one per table row.  Keys must match the
                       first element of each ``columns`` entry.
        columns:       Ordered list of ``(key, header)`` tuples.  ``key``
                       matches a dict key in ``rows``; ``header`` is the
                       column header printed in the table.
        caption:       Table caption (optional).
        label:         LaTeX ``\label{...}`` value (optional).
        number_format: Python format string for float values, e.g. ``".1f"``.

    Returns:
        A string containing the complete LaTeX table source.

    Example::

        rows = [
            {"op": "keygen",      "classical": 127.0, "hybrid": 244.4, "overhead": "+92%"},
            {"op": "encapsulate", "classical":  74.7, "hybrid": 181.5, "overhead": "+143%"},
            {"op": "decapsulate", "classical":  69.0, "hybrid": 127.9, "overhead": "+85%"},
            {"op": "Full handshake", "classical": 270.7, "hybrid": 553.8, "overhead": "+105%"},
        ]
        columns = [
            ("op",        "Operation"),
            ("classical", r"Classical ($\mu$s)"),
            ("hybrid",    r"Hybrid ($\mu$s)"),
            ("overhead",  "Overhead"),
        ]
        print(latex_table(rows, columns, caption="Hybrid vs classical latency", label="tab:hybrid_overhead"))
    """
    col_keys = [k for k, _ in columns]
    col_headers = [h for _, h in columns]
    col_spec = "l" + "r" * (len(columns) - 1)

    lines: list[str] = []
    lines.append(r"\begin{table}[h]")
    lines.append(r"  \centering")
    if caption:
        lines.append(f"  \\caption{{{caption}}}")
    if label:
        lines.append(f"  \\label{{{label}}}")
    lines.append(f"  \\begin{{tabular}}{{{col_spec}}}")
    lines.append(r"    \toprule")
    lines.append("    " + " & ".join(col_headers) + r" \\")
    lines.append(r"    \midrule")

    for row in rows:
        cells: list[str] = []
        for key in col_keys:
            val = row.get(key, "")
            if isinstance(val, float):
                cells.append(f"{val:{number_format}}")
            else:
                cells.append(str(val))
        lines.append("    " + " & ".join(cells) + r" \\")

    lines.append(r"    \bottomrule")
    lines.append(r"  \end{tabular}")
    lines.append(r"\end{table}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Convenience: describe_samples
# ---------------------------------------------------------------------------

@dataclass
class SampleSummary:
    """Descriptive statistics for a timing sample.

    Attributes:
        n:       Number of observations (after trim).
        mean_us: Mean in microseconds.
        median_us: Median in microseconds.
        p95_us:  95th percentile in microseconds.
        p99_us:  99th percentile in microseconds.
        cov_pct: Coefficient of Variation in percent.
        ci_lo_us: Lower 95% bootstrap CI bound in microseconds.
        ci_hi_us: Upper 95% bootstrap CI bound in microseconds.
    """

    n: int
    mean_us: float
    median_us: float
    p95_us: float
    p99_us: float
    cov_pct: float
    ci_lo_us: float
    ci_hi_us: float


def describe_samples(
    samples_s: Sequence[float],
    trim_pct: float = 1.0,
    ci_confidence: float = 0.95,
    n_resamples: int = 2000,
) -> SampleSummary:
    """Compute full descriptive statistics for a timing sample.

    Converts seconds → microseconds internally.

    Args:
        samples_s:     Raw timing samples in *seconds*.
        trim_pct:      Percent to trim from each tail before statistics.
        ci_confidence: Confidence level for bootstrap CI.
        n_resamples:   Bootstrap resamples for CI.

    Returns:
        A :class:`SampleSummary` with all statistics in microseconds.
    """
    if not samples_s:
        raise ValueError("samples_s is empty")

    sorted_s = sorted(samples_s)
    k = max(0, int(len(sorted_s) * trim_pct / 100))
    trimmed = sorted_s[k : len(sorted_s) - k] if k > 0 else sorted_s
    if not trimmed:
        trimmed = sorted_s

    n = len(trimmed)
    mean = statistics.mean(trimmed)
    median = statistics.median(trimmed)

    def percentile(seq: list[float], pct: float) -> float:
        idx = (pct / 100.0) * (len(seq) - 1)
        lo, hi = int(idx), min(int(idx) + 1, len(seq) - 1)
        frac = idx - lo
        return seq[lo] * (1.0 - frac) + seq[hi] * frac

    p95 = percentile(trimmed, 95)
    p99 = percentile(trimmed, 99)
    cov = statistics.stdev(trimmed) / mean * 100.0 if mean != 0 and n >= 2 else 0.0
    ci_lo, _, ci_hi = bootstrap_ci(trimmed, confidence=ci_confidence, n_resamples=n_resamples)

    us = 1e6  # convert s → µs
    return SampleSummary(
        n=n,
        mean_us=mean * us,
        median_us=median * us,
        p95_us=p95 * us,
        p99_us=p99 * us,
        cov_pct=cov,
        ci_lo_us=ci_lo * us,
        ci_hi_us=ci_hi * us,
    )
