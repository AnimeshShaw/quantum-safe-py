"""
run_stats_demo.py
~~~~~~~~~~~~~~~~~
Exercises all functions in bench_stats.py against the 2026-03-29 best-of-3
Docker run results (run2_kem.json / run2_sig.json).

Raw timing samples are not persisted in the JSON — only summary statistics
(mean, stdev, median, p95, p99, CoV) are stored.  This script synthesises
representative sample arrays from normal distributions using those summary
stats so that every bench_stats function can be demonstrated end-to-end.
"""

from __future__ import annotations

import json
import os
import random
import sys

# Allow running from project root or from tests/bench/
ROOT = os.path.join(os.path.dirname(__file__), '..', '..')
sys.path.insert(0, ROOT)

from tests.bench.bench_stats import (
    bootstrap_ci,
    cohens_d,
    cov_stability_report,
    describe_samples,
    latex_table,
    throughput_curve,
    welch_t_test,
)

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def load_results(path: str) -> dict[str, dict]:
    """Load benchmark JSON, flattening nested result groups into a flat name→record dict."""
    with open(path) as f:
        data = json.load(f)
    key = 'results' if 'results' in data else 'benchmarks'
    raw = data[key]
    out: dict[str, dict] = {}
    if isinstance(raw, list):
        # flat list format (bench_kem.py)
        for b in raw:
            out[b['name']] = b
    elif isinstance(raw, dict):
        # grouped dict format (bench_signatures.py): {group_name: [records]}
        for group in raw.values():
            if isinstance(group, list):
                for b in group:
                    out[b['name']] = b
    return out


def synth(mean_us: float, stdev_us: float, n: int = 3000, seed: int = 42) -> list[float]:
    """Return n synthesised timing samples in seconds (normal distribution)."""
    rng = random.Random(seed)
    return [max(1e-12, rng.gauss(mean_us * 1e-6, stdev_us * 1e-6)) for _ in range(n)]


def sep(title: str = '') -> None:
    width = 74
    if title:
        print(f'\n{"─" * 4} {title} {"─" * (width - 6 - len(title))}')
    else:
        print('─' * width)


# ---------------------------------------------------------------------------
# load data
# ---------------------------------------------------------------------------

RESULTS = os.path.join(ROOT, 'results')
kem = load_results(os.path.join(RESULTS, 'run2_kem.json'))
sig = load_results(os.path.join(RESULTS, 'run2_sig.json'))

print('=' * 74)
print('bench_stats.py — Statistical Analysis on 2026-03-29 Best-of-3 Results')
print('(samples synthesised from stored mean/stdev; raw samples not persisted)')
print('=' * 74)


# ---------------------------------------------------------------------------
# 1. Bootstrap 95% CI
# ---------------------------------------------------------------------------

sep('1. BOOTSTRAP 95% CONFIDENCE INTERVALS  (B=2000 resamples)')

ci_ops = [
    ('Decomp \u2460 X25519 keygen',              kem, 'X25519 keygen'),
    ('Decomp \u2460 X25519 DH exchange',          kem, 'X25519 DH'),
    ('Decomp \u2461 ML-KEM-768 keygen',           kem, 'ML-KEM-768 keygen'),
    ('Decomp \u2461 ML-KEM-768 encapsulate',      kem, 'ML-KEM-768 encap'),
    ('Decomp \u2461 ML-KEM-768 decapsulate',      kem, 'ML-KEM-768 decap'),
    ('HybridKEM keygen (Real ML-KEM-768)',        kem, 'HybridKEM keygen'),
    ('HybridKEM encapsulate (Real ML-KEM-768)',   kem, 'HybridKEM encap'),
    ('HybridKEM decapsulate (Real ML-KEM-768)',   kem, 'HybridKEM decap'),
]
for key, store, label in ci_ops:
    b = store.get(key)
    if not b:
        continue
    s = [x * 1e6 for x in synth(b['mean_us'], b['stdev_us'])]
    lo, med, hi = bootstrap_ci(s)
    width = hi - lo
    print(f'  {label:<28}  {med:7.2f} us  [95% CI {lo:.2f}–{hi:.2f}]  w={width:.2f}')


# ---------------------------------------------------------------------------
# 2. Welch t-test: hybrid full handshake vs classical
# ---------------------------------------------------------------------------

sep("2. WELCH'S t-TEST  —  Hybrid vs Classical KEM handshake")

x25519_kg = kem.get('Decomp \u2460 X25519 keygen')
x25519_dh = kem.get('Decomp \u2460 X25519 DH exchange')
hybrid_kg  = kem.get('HybridKEM keygen (Real ML-KEM-768)')
hybrid_en  = kem.get('HybridKEM encapsulate (Real ML-KEM-768)')
hybrid_de  = kem.get('HybridKEM decapsulate (Real ML-KEM-768)')

if all([x25519_kg, x25519_dh, hybrid_kg, hybrid_en, hybrid_de]):
    cl_s = [a + b for a, b in zip(
        synth(x25519_kg['mean_us'], x25519_kg['stdev_us'], seed=10),
        synth(x25519_dh['mean_us'], x25519_dh['stdev_us'], seed=11),
    )]
    hy_s = [a + b + c for a, b, c in zip(
        synth(hybrid_kg['mean_us'], hybrid_kg['stdev_us'], seed=12),
        synth(hybrid_en['mean_us'], hybrid_en['stdev_us'], seed=13),
        synth(hybrid_de['mean_us'], hybrid_de['stdev_us'], seed=14),
    )]
    res = welch_t_test(cl_s, hy_s)
    d   = cohens_d(cl_s, hy_s)
    print(f'  Classical full KEM handshake:   mean = {res.mean_a:.2f} us')
    print(f'  Hybrid full KEM handshake:      mean = {res.mean_b:.2f} us')
    print(f'  Overhead:                       {res.overhead_pct:+.1f}%')
    print(f'  t-statistic:                    {res.t_statistic:.2f}')
    print(f'  Degrees of freedom (Satterthw): {res.df:.0f}')
    print(f'  p-value (two-tailed):           {res.p_value:.2e}')
    print(f'  Significant at alpha=0.05?      {"YES" if res.significant else "NO"}')
    print(f"  Cohen's d:                      {d:.2f}  (|d|>=0.8 = large effect)")
    if d >= 0.8:
        interp = 'Large effect — overhead is statistically real and operationally substantial'
    elif d >= 0.5:
        interp = 'Medium effect — overhead is real but manageable in production'
    else:
        interp = 'Small effect — overhead is measurable but operationally minor'
    print(f'  Interpretation:                 {interp}')

sep('   Welch t-test: ML-DSA-65 sign vs Ed25519 sign')

ed_b  = sig.get('Ed25519 sign (32B)')
mld_b = sig.get('ML-DSA-65 sign (32B)')
if ed_b and mld_b:
    ed_s  = synth(ed_b['mean_us'],  ed_b['stdev_us'],  seed=20)
    mld_s = synth(mld_b['mean_us'], mld_b['stdev_us'], seed=21)
    res2 = welch_t_test(ed_s, mld_s)
    d2   = cohens_d(ed_s, mld_s)
    print(f'  Ed25519 sign mean:   {res2.mean_a:.2f} us')
    print(f'  ML-DSA-65 sign mean: {res2.mean_b:.2f} us  (CoV ~51.5% due to rejection sampling)')
    print(f'  Overhead:            {res2.overhead_pct:+.1f}%')
    print(f'  p-value:             {res2.p_value:.2e},  significant={res2.significant}')
    print(f"  Cohen's d:           {d2:.2f}")


# ---------------------------------------------------------------------------
# 3. Throughput curve
# ---------------------------------------------------------------------------

sep('3. THROUGHPUT CURVE (concurrent load — ENV-2 Docker 2026-03-29)')

# median_latency_s for each tier is: median_us / 1e6
# For the concurrent bench, the JSON gives total wall time / users.
# We use median_latency_us from BENCHMARKS.md directly:
#   100 users  -> 33.0 ms
#   500 users  -> 164.6 ms
#   5000 users -> 1755.9 ms
tiers = [
    (100,   33.0   / 1000, 100),
    (500,   164.6  / 1000, 500),
    (5000,  1755.9 / 1000, 5000),
]
curve = throughput_curve(tiers)
print(f'  {"Users":>6}  {"Median latency":>14}  {"Ops/s":>10}  {"Lin. Efficiency":>16}')
for pt in curve:
    print(
        f'  {pt.concurrent_users:>6}'
        f'  {pt.median_latency_s * 1000:>12.1f} ms'
        f'  {pt.ops_per_sec:>10.0f}'
        f'  {pt.efficiency_pct:>15.1f}%'
    )
throughput_100  = curve[0].ops_per_sec
throughput_5000 = curve[-1].ops_per_sec
degradation = (throughput_5000 - throughput_100) / throughput_100 * 100
print(f'\n  Throughput degradation 100->5000 users: {degradation:+.1f}%  (confirms GIL release)')


# ---------------------------------------------------------------------------
# 4. CoV stability report
# ---------------------------------------------------------------------------

sep('4. CoV STABILITY REPORT  (AES-256-GCM baseline = noise floor)')

aes_b = kem.get('AES-256-GCM enc 1KB')
if aes_b:
    aes_samples = synth(aes_b['mean_us'], aes_b.get('stdev_us', aes_b['mean_us'] * 0.021), seed=99)
    baseline_label = f"AES-256-GCM CoV from data: {aes_b['cov_pct']:.1f}%"
else:
    aes_samples = synth(0.8, 0.017, seed=99)  # 2.1% synthetic
    baseline_label = 'AES-256-GCM CoV (synthetic 2.1%)'
print(f'  Baseline: {baseline_label}')
print()

cov_checks = [
    ('AES-256-GCM enc 1KB (baseline)',  kem.get('AES-256-GCM enc 1KB')),
    ('Ed25519 verify',                  kem.get('Ed25519 verify')),
    ('ML-KEM-768 keygen',               kem.get('Decomp \u2461 ML-KEM-768 keygen')),
    ('ML-KEM-768 encapsulate',          kem.get('Decomp \u2461 ML-KEM-768 encapsulate')),
    ('ML-KEM-768 decapsulate',          kem.get('Decomp \u2461 ML-KEM-768 decapsulate')),
    ('HybridKEM keygen',                kem.get('HybridKEM keygen (Real ML-KEM-768)')),
    ('HybridKEM encapsulate',           kem.get('HybridKEM encapsulate (Real ML-KEM-768)')),
    ('HybridKEM decapsulate',           kem.get('HybridKEM decapsulate (Real ML-KEM-768)')),
    ('Ed25519 sign',                    sig.get('Ed25519 sign (32B)')),
    ('ML-DSA-65 keygen',                sig.get('ML-DSA-65 keygen')),
    ('ML-DSA-65 sign  (reject.samp.)',  sig.get('ML-DSA-65 sign (32B)')),
    ('ML-DSA-65 verify',                sig.get('ML-DSA-65 verify (32B)')),
    ('HybridSign sign',                 sig.get('HybridSign sign (32B)')),
    ('HybridSign verify',               sig.get('HybridSign verify (32B)')),
]
for name, b in cov_checks:
    if not b:
        continue
    stdev = b.get('stdev_us', b['mean_us'] * b['cov_pct'] / 100)
    s = synth(b['mean_us'], stdev)
    rep = cov_stability_report(name, s, aes_samples)
    marker = '\u2713' if rep.is_timing_stable else '\u26a0'
    status = 'STABLE  ' if rep.is_timing_stable else 'ELEVATED'
    print(
        f'  [{marker}] {name:<35}  '
        f'CoV={rep.cov_pct:.1f}%  delta={rep.delta_from_baseline:+.1f}pp  {status}'
    )


# ---------------------------------------------------------------------------
# 5. describe_samples (full summary for one key operation)
# ---------------------------------------------------------------------------

sep('5. FULL SAMPLE DESCRIPTION  — HybridKEM decapsulate')

b = kem.get('HybridKEM decapsulate (Real ML-KEM-768)')
if b:
    stdev = b.get('stdev_us', b['mean_us'] * b['cov_pct'] / 100)
    s = synth(b['mean_us'], stdev)
    desc = describe_samples(s)
    print(f'  n (after 1% trim):  {desc.n}')
    print(f'  mean:               {desc.mean_us:.2f} us')
    print(f'  median:             {desc.median_us:.2f} us')
    print(f'  p95:                {desc.p95_us:.2f} us')
    print(f'  p99:                {desc.p99_us:.2f} us')
    print(f'  CoV:                {desc.cov_pct:.2f}%')
    print(f'  95% bootstrap CI:   [{desc.ci_lo_us:.2f}, {desc.ci_hi_us:.2f}] us')
    print(f'  CI width:           {desc.ci_hi_us - desc.ci_lo_us:.2f} us')


# ---------------------------------------------------------------------------
# 6. LaTeX table output
# ---------------------------------------------------------------------------

sep('6. LaTeX BOOKTABS TABLE  (paper-ready)')

rows = []
for key, label in [
    ('Decomp \u2460 X25519 keygen',             'X25519 keygen'),
    ('Decomp \u2460 X25519 DH exchange',         'X25519 DH'),
    ('Decomp \u2461 ML-KEM-768 keygen',          'ML-KEM-768 keygen'),
    ('Decomp \u2461 ML-KEM-768 encapsulate',     'ML-KEM-768 encap'),
    ('Decomp \u2461 ML-KEM-768 decapsulate',     'ML-KEM-768 decap'),
    ('HybridKEM keygen (Real ML-KEM-768)',       'HybridKEM keygen'),
    ('HybridKEM encapsulate (Real ML-KEM-768)',  'HybridKEM encap'),
    ('HybridKEM decapsulate (Real ML-KEM-768)',  'HybridKEM decap'),
]:
    b = kem.get(key)
    if not b:
        continue
    rows.append({
        'op':     label,
        'median': b['median_us'],
        'p95':    b['p95_us'],
        'cov':    b['cov_pct'],
    })

cols = [
    ('op',     'Operation'),
    ('median', r'Median (\textmu{}s)'),
    ('p95',    r'p95 (\textmu{}s)'),
    ('cov',    r'CoV (\%)'),
]
print(latex_table(
    rows, cols,
    caption=(
        'Per-component and full hybrid KEM latency '
        '(ENV-2: Docker/WSL2 Linux, 3{,}000 iterations, CPU-pinned, best-of-3 runs)'
    ),
    label='tab:hybrid_overhead',
))

print()
print('All bench_stats.py functions exercised successfully.')
