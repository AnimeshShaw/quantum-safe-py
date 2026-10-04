"""
Timing-leakage assessment harness (fixed-vs-random two-class testing).

Run with::

    python tests/bench/bench_leakage.py --iterations 20000
    python tests/bench/bench_leakage.py --save results/leakage.json

Why this exists separately from ``bench_kem.py``
------------------------------------------------
``bench_kem.py`` measures *latency* and reports CoV (sigma/mu) alongside it.
CoV answers "is this operation's execution time stable?".  It cannot answer
"does this operation's execution time depend on the secret?", because a single
dispersion figure cannot separate a key-dependent component from measurement
noise of comparable magnitude: both land in the same number.

This module answers the second question using the two-class design that
``dudect`` (Reparaz et al., 2017) uses:

    class FIXED  — the same secret, reused for every measurement
    class RANDOM — a different secret for every measurement

Environmental noise (scheduler, cache, frequency scaling) is present in *both*
classes, so it cancels in a between-class comparison.  A statistically
significant difference in the two timing distributions is attributable to the
thing that differs between them, which is the secret.  We test with Welch's
t-test (unequal variance) from ``bench_stats``.

Three experiments
-----------------
``decap_fixed_vs_random``
    ML-KEM-768 decapsulation, fixed secret key vs. a fresh secret key per
    measurement.  Screens for key-dependent decapsulation timing.

``decap_valid_vs_invalid``
    ML-KEM-768 decapsulation of a *valid* ciphertext vs. one that fails the
    FIPS 203 re-encryption check and takes the implicit-rejection path.  This
    is the attack-relevant question for an FO-transform KEM: if the two paths
    are distinguishable by timing, an adversary can test ciphertext validity
    against a victim key, which is the entry point for chosen-ciphertext
    attacks on the decapsulation oracle.  FIPS 203 requires the selection
    between the two results to be constant-time; this measures whether the
    requirement holds end-to-end through the Python binding.

``sign_fixed_vs_random``
    ML-DSA-65 signing, fixed key vs. fresh key per measurement.  ML-DSA
    signing has high dispersion by construction (FIPS 204 hedged rejection
    sampling).  Dispersion alone cannot show that the variance is
    *key-independent* — this test can, by holding the key fixed in one class.

Methodology notes that matter for interpretation
------------------------------------------------
* **Measurements are interleaved**, not run class-by-class.  Thermal drift and
  frequency scaling are monotonic over a long run; measuring all of class A
  then all of class B would attribute drift to the class difference.
* **No upper-tail trimming by default.**  ``bench_kem._bench`` trims 1% from
  *both* tails, which is right for estimating a typical latency and wrong
  here: a rare secret-dependent slow path lives precisely in the upper tail.
  Results are reported untrimmed and again with only the top 0.5% removed, so
  a reader can see the verdict does not depend on that choice.
* **Keys for the RANDOM class are pre-generated** outside the timed region.
  Generating a keypair inside the measurement would swamp the signal.
* A null result bounds leakage at the resolution of this setup; it is not a
  proof of constant-time behaviour.  Formal verification (``dudect`` against
  the compiled backend, ``ct-verif``) remains the stronger instrument, and
  this screen is intended to run cheaply and often, ahead of it.

Controls
--------
Negative controls: fixed-vs-fixed (the apparatus is quiet) and random-vs-random
(both classes vary their key). Equal-size object pools in both classes, so cache
footprint is not what distinguishes them.

Public-data calibrations. ``decap_public_calibration``: the secret key is the
same in both classes and only the public ciphertext differs. The FIXED class of
fixed-vs-random repeats the same secret key *and* the same ciphertext, and much
of ML-KEM decapsulation depends on public data and on cache and branch state, so
a fixed class can run faster with no secret dependence at all. Random-vs-random
rules out apparatus noise, not that; this calibration shows how much of a
fixed-vs-random signal public inputs alone can produce.
``encap_public_key_calibration``: encapsulation, which uses only the public
key, with a fixed vs fresh public key. No secret is involved in either class, so
a class difference there is not secret dependence. (An ML-KEM secret key embeds
the public key.)

Positive control (``positive_control_sensitivity``): a genuine decapsulation plus
a deliberate secret-dependent delay of known size, run through the same harness
at several magnitudes. It reports the smallest leak this harness detects at the
configured iteration count on this host, which bounds what a clean result means.

Remaining limitation: everything is measured through the Python binding, so a
leak smaller than the binding's own jitter is below the detection threshold
whatever the compiled backend does.
"""

from __future__ import annotations

import argparse
import gc
import json
import os
import random
import statistics
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field
from typing import Any

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))
import _oqs_path  # noqa: F401 — registers oqs.dll dir on Windows
from bench_stats import welch_t_test  # noqa: E402

# |t| thresholds. dudect treats |t| > 10 as clear evidence of leakage and
# |t| > 5 as suspicious; with large n even a tiny effect becomes significant,
# so we report the effect size alongside and never rely on p alone.
T_CLEAR = 10.0
T_SUSPICIOUS = 5.0


@dataclass
class ClassStats:
    """Summary of one measurement class."""

    label: str
    n: int
    mean_us: float
    median_us: float
    stdev_us: float
    cov_pct: float

    @classmethod
    def from_samples(cls, label: str, samples: Sequence[float]) -> ClassStats:
        mean = statistics.mean(samples)
        stdev = statistics.stdev(samples) if len(samples) > 1 else 0.0
        return cls(
            label=label,
            n=len(samples),
            mean_us=mean,
            median_us=statistics.median(samples),
            stdev_us=stdev,
            cov_pct=(stdev / mean * 100.0) if mean else 0.0,
        )


@dataclass
class LeakageResult:
    """Outcome of one two-class leakage test."""

    name: str
    class_a: ClassStats
    class_b: ClassStats
    t_statistic: float
    p_value: float
    df: float
    delta_mean_us: float
    verdict: str
    trim_description: str
    notes: list[str] = field(default_factory=list)

    def __str__(self) -> str:
        # ASCII-only: this runs on consoles without a UTF-8 code page.
        return (
            f"  {self.name:<46} "
            f"t={self.t_statistic:+8.2f}  "
            f"p={self.p_value:.2e}  "
            f"d_mean={self.delta_mean_us:+7.3f}us  "
            f"{self.verdict}"
        )


def _verdict(t_statistic: float) -> str:
    t = abs(t_statistic)
    if t > T_CLEAR:
        return "LEAK (|t|>10)"
    if t > T_SUSPICIOUS:
        return "SUSPICIOUS (|t|>5)"
    return "no leak detected"


def _crop(samples: Sequence[float], top_pct: float) -> list[float]:
    """Drop the slowest ``top_pct`` of samples. Lower tail is never cropped."""
    if top_pct <= 0:
        return list(samples)
    ordered = sorted(samples)
    keep = len(ordered) - max(1, int(len(ordered) * top_pct / 100.0))
    return ordered[:keep]


def measure_two_class(
    name: str,
    fn_a: Callable[[int], None],
    fn_b: Callable[[int], None],
    label_a: str,
    label_b: str,
    iterations: int,
    warmup: int = 200,
    crop_sweep: Sequence[float] = (0.0, 0.1, 0.5, 1.0, 5.0),
    notes: Sequence[str] | None = None,
    seed: int = 20260927,
) -> list[LeakageResult]:
    """Interleave two measurement classes and test them against each other.

    ``fn_a`` and ``fn_b`` each take the iteration index so a caller can rotate
    through a pre-built pool of keys without allocating inside the timed region.

    Class order is randomised per iteration. Measuring A then B in a fixed order
    lets position leak into the result — the second call of each pair runs with a
    warmer cache — and since one class would always occupy that position, the
    bias would appear as a consistent between-class t. Randomising the order
    distributes that effect across both classes instead.
    """
    rng = random.Random(seed)
    gc.collect()
    gc.disable()
    try:
        for i in range(warmup):
            fn_a(i)
            fn_b(i)

        samples_a: list[float] = []
        samples_b: list[float] = []
        for i in range(iterations):
            # Interleaved so drift affects both classes equally, in randomised
            # order so neither class is consistently the warmed-up one.
            first_is_a = rng.random() < 0.5
            first_fn, second_fn = (fn_a, fn_b) if first_is_a else (fn_b, fn_a)

            t0 = time.perf_counter()
            first_fn(i)
            t1 = time.perf_counter()
            first_sample = (t1 - t0) * 1_000_000

            t0 = time.perf_counter()
            second_fn(i)
            t1 = time.perf_counter()
            second_sample = (t1 - t0) * 1_000_000

            if first_is_a:
                samples_a.append(first_sample)
                samples_b.append(second_sample)
            else:
                samples_b.append(first_sample)
                samples_a.append(second_sample)
    finally:
        gc.enable()

    # Analyse the *same* samples at every crop threshold. Re-measuring per
    # threshold would compare different sample sets, and the spread between them
    # would mix run-to-run variation with genuine sensitivity to the cropping
    # choice — which is the thing we actually want to see.
    results: list[LeakageResult] = []
    for crop in crop_sweep:
        a = _crop(samples_a, crop)
        b = _crop(samples_b, crop)
        tt = welch_t_test(a, b)
        stats_a = ClassStats.from_samples(label_a, a)
        stats_b = ClassStats.from_samples(label_b, b)
        trim = "untrimmed" if crop <= 0 else f"top {crop}% dropped"
        results.append(
            LeakageResult(
                name=f"{name} [{trim}]",
                class_a=stats_a,
                class_b=stats_b,
                t_statistic=tt.t_statistic,
                p_value=tt.p_value,
                df=tt.df,
                delta_mean_us=stats_b.mean_us - stats_a.mean_us,
                verdict=_verdict(tt.t_statistic),
                trim_description=trim,
                notes=list(notes or []),
            )
        )
    return results


# ---------------------------------------------------------------------------
# ML-KEM material helpers — keep pool construction identical across classes
# ---------------------------------------------------------------------------


def _kem_material(alg: str = "ML-KEM-768") -> tuple[bytes, bytes]:
    """Generate one (secret_key, matching_ciphertext) pair, then release the object."""
    import oqs

    kem = oqs.KeyEncapsulation(alg)
    try:
        pk = kem.generate_keypair()
        ct, _ = kem.encap_secret(pk)
        return bytes(kem.export_secret_key()), bytes(ct)
    finally:
        kem.free()


def _kem_from_material(
    secret_key: bytes, ciphertext: bytes, alg: str = "ML-KEM-768"
) -> tuple[Any, bytes]:
    """Build a decapsulation object from exported key bytes."""
    import oqs

    return oqs.KeyEncapsulation(alg, secret_key=bytes(secret_key)), bytes(ciphertext)


# ---------------------------------------------------------------------------
# Experiment 0 — negative control: fixed vs. fixed
# ---------------------------------------------------------------------------


def control_fixed_vs_fixed(iterations: int, pool_size: int = 256) -> list[LeakageResult]:
    """Calibration run: both classes hold the *same* key, so t should be ~0.

    This is what makes the other results interpretable. If this control returns
    a large |t|, the apparatus is producing a class difference where none exists
    and no positive result from it can be trusted. It also gives an empirical
    noise floor for this machine, which is more honest than assuming the
    nominal |t| > 5 threshold is achievable here.
    """
    seed_sk, seed_ct = _kem_material()
    pool_a = [_kem_from_material(seed_sk, seed_ct) for _ in range(pool_size)]
    pool_b = [_kem_from_material(seed_sk, seed_ct) for _ in range(pool_size)]

    def do_a(i: int) -> None:
        kem, ct = pool_a[i % pool_size]
        kem.decap_secret(ct)

    def do_b(i: int) -> None:
        kem, ct = pool_b[i % pool_size]
        kem.decap_secret(ct)

    notes = [
        "NEGATIVE CONTROL: both classes use the same key and ciphertext. Any |t| "
        "reported here is apparatus noise, not signal, and sets the floor below "
        "which the other tests in this run cannot resolve anything.",
    ]
    out = measure_two_class(
        "CONTROL ML-KEM-768 decap: fixed vs fixed",
        do_a,
        do_b,
        "fixed key (A)",
        "fixed key (B)",
        iterations=iterations,
        notes=notes,
    )
    for kem, _ in pool_a + pool_b:
        kem.free()
    return out


def control_random_vs_random(iterations: int, pool_size: int = 256) -> list[LeakageResult]:
    """Second control: both classes vary their key. Disambiguates interpretation.

    ``control_fixed_vs_fixed`` shows the apparatus is quiet. This one separates
    two very different readings of a positive fixed-vs-random result:

    * If this control is clean while fixed-vs-random is not, the difference
      tracks *repetition* rather than any particular key — the fixed class
      re-executes on byte-identical data every call, so its branch predictors
      and data caches reach a steady state the varying class never does. That
      is a property of the measurement design, not a key-recovery channel, and
      it means a fixed-vs-random t cannot be read directly as leakage here.
    * If this control also shows a large |t|, the apparatus produces class
      differences between two statistically identical treatments, and nothing
      in the run is interpretable.

    Either way this is the result that decides what a positive fixed-vs-random
    number is allowed to mean.
    """
    material_a = [_kem_material() for _ in range(pool_size)]
    material_b = [_kem_material() for _ in range(pool_size)]
    pool_a = [_kem_from_material(sk, ct) for sk, ct in material_a]
    pool_b = [_kem_from_material(sk, ct) for sk, ct in material_b]

    def do_a(i: int) -> None:
        kem, ct = pool_a[i % pool_size]
        kem.decap_secret(ct)

    def do_b(i: int) -> None:
        kem, ct = pool_b[i % pool_size]
        kem.decap_secret(ct)

    notes = [
        "NEGATIVE CONTROL: both classes cycle distinct keys, so the two treatments "
        "are statistically identical and |t| should be ~0.",
        "Compare against the fixed-vs-random result: if that one is large and this "
        "one is not, the signal is about data repetition, not key dependence.",
    ]
    out = measure_two_class(
        "CONTROL ML-KEM-768 decap: random vs random",
        do_a,
        do_b,
        "fresh key (A)",
        "fresh key (B)",
        iterations=iterations,
        notes=notes,
    )
    for kem, _ in pool_a + pool_b:
        kem.free()
    return out


# ---------------------------------------------------------------------------
# Experiment 1 — ML-KEM-768 decapsulation, fixed key vs. fresh key
# ---------------------------------------------------------------------------


def decap_fixed_vs_random(iterations: int, pool_size: int = 256) -> list[LeakageResult]:
    """Both classes cycle equally sized object pools; only key *contents* differ.

    A naive version of this test gives the FIXED class one object reused for
    every measurement while the RANDOM class cycles a pool of distinct ones.
    That difference is not the secret — it is memory locality. The reused
    object stays in L1/L2 while the pool does not, and the resulting few-
    microsecond gap reads as a leak when it is really a cache artifact. (This
    is not hypothetical: the naive arrangement produced |t| > 13 on the same
    machine where the symmetric arrangement below produces |t| < 2.)

    So the FIXED class here is also a pool of ``pool_size`` objects and
    ``pool_size`` distinct ciphertext buffers, cycled identically — every one
    of them simply holds the *same* secret key and the same ciphertext bytes.
    Allocation count, cycling stride and cache pressure then match across
    classes, and the remaining difference is the key material itself.
    """
    # Both pools are built the same way — by injecting exported key bytes — so
    # that objects in either class have identical internal state and layout. If
    # one pool were built by generate_keypair() and the other by injection, the
    # objects could differ in what they hold (e.g. a retained public key), which
    # is another asymmetry that is not the secret.
    seed_sk, seed_ct = _kem_material()
    random_material = [_kem_material() for _ in range(pool_size)]

    fixed_pool = [_kem_from_material(seed_sk, seed_ct) for _ in range(pool_size)]
    random_pool = [_kem_from_material(sk, ct) for sk, ct in random_material]

    def do_fixed(i: int) -> None:
        kem, ct = fixed_pool[i % pool_size]
        kem.decap_secret(ct)

    def do_random(i: int) -> None:
        kem, ct = random_pool[i % pool_size]
        kem.decap_secret(ct)

    notes = [
        f"Both classes cycle {pool_size} distinct KeyEncapsulation objects and "
        f"{pool_size} distinct ciphertext buffers, so allocation and cache "
        "behaviour are matched; only the key material differs between classes.",
        "Every decapsulation in both classes uses a ciphertext correctly bound to "
        "the key decapsulating it, so both classes take the success path.",
    ]
    out = measure_two_class(
        "ML-KEM-768 decap: fixed key vs fresh key",
        do_fixed,
        do_random,
        "fixed key",
        "fresh key",
        iterations=iterations,
        notes=notes,
    )
    for kem, _ in fixed_pool:
        kem.free()
    for kem, _ in random_pool:
        kem.free()
    return out


# ---------------------------------------------------------------------------
# Experiment 2 — ML-KEM-768 decapsulation, success path vs implicit rejection
# ---------------------------------------------------------------------------


def decap_valid_vs_invalid(iterations: int) -> list[LeakageResult]:
    """Valid ciphertext vs. one that fails the FIPS 203 re-encryption check.

    ML-KEM decapsulation never reports failure. When the re-encryption check
    fails it returns J(z||c), a pseudorandom value derived from the implicit
    rejection key, selected in constant time. If the two paths are separable
    by timing, ciphertext validity leaks against a fixed victim key.
    """
    import oqs

    kem = oqs.KeyEncapsulation("ML-KEM-768")
    pk = kem.generate_keypair()
    valid_ct, valid_ss = kem.encap_secret(pk)

    # An invalid ciphertext of the correct length: encapsulated to a *different*
    # key, so the re-encryption check against this key fails.
    other = oqs.KeyEncapsulation("ML-KEM-768")
    other_pk = other.generate_keypair()
    invalid_ct, _ = other.encap_secret(other_pk)
    assert len(invalid_ct) == len(valid_ct)

    # Confirm the premise: this key really does take the rejection path on
    # invalid_ct, and the success path on valid_ct.
    assert kem.decap_secret(valid_ct) == valid_ss, "valid ciphertext did not decapsulate"
    rejected = kem.decap_secret(invalid_ct)
    assert rejected != valid_ss, "invalid ciphertext unexpectedly produced the valid secret"

    def do_valid(_i: int) -> None:
        kem.decap_secret(valid_ct)

    def do_invalid(_i: int) -> None:
        kem.decap_secret(invalid_ct)

    notes = [
        "Both classes use the same secret key; only ciphertext validity differs, "
        "so a class difference isolates the re-encryption-check branch.",
        "Invalid ciphertext is a well-formed ML-KEM-768 ciphertext encapsulated to "
        "an unrelated key — correct length, fails the re-encryption check.",
    ]
    out = measure_two_class(
        "ML-KEM-768 decap: valid ct vs implicit reject",
        do_valid,
        do_invalid,
        "valid ciphertext",
        "invalid ciphertext",
        iterations=iterations,
        notes=notes,
    )
    kem.free()
    other.free()
    return out


# ---------------------------------------------------------------------------
# Experiment 3 — ML-DSA-65 signing, fixed key vs. fresh key
# ---------------------------------------------------------------------------


def sign_fixed_vs_random(iterations: int, pool_size: int = 256) -> list[LeakageResult]:
    """Tests the paper's claim that ML-DSA signing variance is key-independent.

    FIPS 204 hedged signing rejection-samples until the candidate response is
    safe to release, so signing time varies by construction. That variance is
    only benign if the iteration count is independent of the signing key. A
    fixed-vs-random comparison is what actually tests that; dispersion is not.
    """
    import oqs

    message = b"\x5a" * 32

    # Seed key whose bytes the FIXED pool replicates (see decap_fixed_vs_random
    # for why both classes must cycle equally sized pools).
    seed_signer = oqs.Signature("ML-DSA-65")
    seed_signer.generate_keypair()
    seed_sk = seed_signer.export_secret_key()
    seed_signer.free()

    fixed_pool: list[Any] = [
        oqs.Signature("ML-DSA-65", secret_key=bytes(seed_sk)) for _ in range(pool_size)
    ]

    random_pool: list[Any] = []
    for _ in range(pool_size):
        s = oqs.Signature("ML-DSA-65")
        s.generate_keypair()
        random_pool.append(s)

    def do_fixed(i: int) -> None:
        fixed_pool[i % pool_size].sign(message)

    def do_random(i: int) -> None:
        random_pool[i % pool_size].sign(message)

    notes = [
        f"Both classes cycle {pool_size} distinct Signature objects; the FIXED pool "
        "holds the same signing key in all of them, the RANDOM pool a different key "
        "in each, so allocation and cache behaviour are matched across classes.",
        "Message is identical in both classes, so message-dependent cost cancels.",
        "High dispersion is expected in both classes (FIPS 204 rejection sampling); "
        "the question is whether the distributions differ by key.",
    ]
    out = measure_two_class(
        "ML-DSA-65 sign: fixed key vs fresh key",
        do_fixed,
        do_random,
        "fixed key",
        "fresh key",
        iterations=iterations,
        notes=notes,
    )
    for s in fixed_pool:
        s.free()
    for s in random_pool:
        s.free()
    return out


# ---------------------------------------------------------------------------
# Experiment 4 — HybridKEM combiner, fixed key vs. fresh key
# ---------------------------------------------------------------------------


def hybrid_decap_fixed_vs_random(iterations: int, pool_size: int = 256) -> list[LeakageResult]:
    """The combiner is this library's own code, so it gets its own screen.

    liboqs' ML-KEM implementation is widely studied; the HKDF-plus-serialisation
    combiner layered on top of it is not. This measures the full hybrid
    decapsulation path, which is where a library-level screen has the most to
    contribute.
    """
    import copy

    from quantum_safe.kem.hybrid import HybridKEM

    kem = HybridKEM()

    # Seed keypair/ciphertext, then deep-copied into a pool so the FIXED class
    # allocates and cycles exactly like the RANDOM one (see
    # decap_fixed_vs_random for why the naive arrangement measures cache, not keys).
    seed_kp = kem.generate_keypair()
    seed_ct, _ = kem.encapsulate(seed_kp.public)

    fixed_pool: list[tuple[Any, Any]] = [
        (copy.deepcopy(seed_kp).secret, copy.deepcopy(seed_ct)) for _ in range(pool_size)
    ]

    random_pool: list[tuple[Any, Any]] = []
    for _ in range(pool_size):
        kp = kem.generate_keypair()
        ct, _ = kem.encapsulate(kp.public)
        random_pool.append((kp.secret, ct))

    def do_fixed(i: int) -> None:
        sk, ct = fixed_pool[i % pool_size]
        kem.decapsulate(sk, ct)

    def do_random(i: int) -> None:
        sk, ct = random_pool[i % pool_size]
        kem.decapsulate(sk, ct)

    notes = [
        f"Both classes cycle {pool_size} distinct secret-key and ciphertext objects; "
        "the FIXED pool is deep-copied from one keypair so every entry holds identical "
        "material, matching the RANDOM pool's allocation and cache behaviour.",
        "Covers X25519 scalar multiplication, ML-KEM decapsulation, HKDF-SHA256 "
        "combination and CBOR/PEM deserialisation in one measurement.",
    ]
    out = measure_two_class(
        "HybridKEM decap: fixed key vs fresh key",
        do_fixed,
        do_random,
        "fixed key",
        "fresh key",
        iterations=iterations,
        notes=notes,
    )
    return out


# ---------------------------------------------------------------------------
# Calibration - public inputs only: the SECRET is fixed in both classes
# ---------------------------------------------------------------------------


def decap_public_calibration(iterations: int, pool_size: int = 256) -> list[LeakageResult]:
    """Same secret key in both classes; only the *public* ciphertext differs.

    Much of ML-KEM decapsulation depends on public data (the re-encryption over
    the ciphertext) and on cache and branch-predictor state, so a FIXED class
    can run faster with no secret dependence at all. This calibration holds the
    secret key identical in both classes and varies only the ciphertext:

        class A: pool of objects with the same key, all decapsulating the SAME ciphertext
        class B: pool of objects with the same key, each decapsulating a DIFFERENT valid ciphertext

    Nothing secret differs between the classes, so any |t| here is explained by
    public inputs and microarchitectural state. If fixed-vs-random reaches a
    similar |t|, the signal need not involve the secret at all.
    """
    import oqs

    seed = oqs.KeyEncapsulation("ML-KEM-768")
    try:
        pk = seed.generate_keypair()
        sk = bytes(seed.export_secret_key())
        same_ct, _ = seed.encap_secret(pk)
        fresh_cts = [bytes(seed.encap_secret(pk)[0]) for _ in range(pool_size)]
    finally:
        seed.free()

    pool_same = [_kem_from_material(sk, bytes(same_ct)) for _ in range(pool_size)]
    pool_fresh = [_kem_from_material(sk, ct) for ct in fresh_cts]

    def do_same(i: int) -> None:
        kem, ct = pool_same[i % pool_size]
        kem.decap_secret(ct)

    def do_fresh(i: int) -> None:
        kem, ct = pool_fresh[i % pool_size]
        kem.decap_secret(ct)

    notes = [
        "The secret key is IDENTICAL in both classes; only the (public) ciphertext "
        "differs. Any |t| is therefore explained by public inputs and cache or branch "
        "state, not by the secret. Compare with 'fixed key vs fresh key'.",
        f"Both classes cycle {pool_size} distinct objects and buffers (equal footprint).",
    ]
    out = measure_two_class(
        "CALIBRATION ML-KEM-768 decap: same key, same vs fresh ciphertext",
        do_same,
        do_fresh,
        "same ciphertext",
        "fresh ciphertexts",
        iterations=iterations,
        notes=notes,
    )
    for kem, _ in pool_same + pool_fresh:
        kem.free()
    return out


def encap_public_key_calibration(iterations: int, pool_size: int = 256) -> list[LeakageResult]:
    """Encapsulation (no secret anywhere), fixed public key vs fresh public keys.

    Encapsulation uses only the public key, so nothing secret is involved in
    either class. If this shows a class difference of the same kind as the
    fixed-vs-random decapsulation test, then a fixed-vs-random signal does not
    need a secret at all: it tracks the content or repetition of key-shaped
    data. (An ML-KEM secret key embeds the public key, so a fixed secret key is
    also a fixed public key.)

        class A: pool of distinct buffers all holding the SAME public key
        class B: pool of distinct buffers holding DIFFERENT public keys
    """
    import oqs

    kem = oqs.KeyEncapsulation("ML-KEM-768")
    try:
        pks = [
            bytes(oqs.KeyEncapsulation("ML-KEM-768").generate_keypair()) for _ in range(pool_size)
        ]
        same = pks[0]
        # bytes(bytearray(...)) forces distinct buffers so both pools have the same footprint.
        pool_same = [bytes(bytearray(same)) for _ in range(pool_size)]
        pool_fresh = [bytes(bytearray(pk)) for pk in pks]

        def do_same(i: int) -> None:
            kem.encap_secret(pool_same[i % pool_size])

        def do_fresh(i: int) -> None:
            kem.encap_secret(pool_fresh[i % pool_size])

        return measure_two_class(
            "CALIBRATION ML-KEM-768 encap: fixed vs fresh PUBLIC key (no secret)",
            do_same,
            do_fresh,
            "same public key",
            "fresh public keys",
            iterations=iterations,
            notes=[
                "Encapsulation uses only the public key: NO SECRET is involved in either "
                "class. A class difference here is explained by public key content or "
                "repetition, not by secret dependence.",
                f"Both classes cycle {pool_size} distinct buffers (equal footprint).",
            ],
        )
    finally:
        kem.free()


# ---------------------------------------------------------------------------
# Positive control - a deliberately leaky operation through the same harness
# ---------------------------------------------------------------------------

#: Secret-dependent delays (microseconds) the positive control injects.
LEAK_MAGNITUDES_US = (0.0, 0.25, 0.5, 1.0, 2.0, 5.0)


def _spin_us(microseconds: float) -> None:
    """Busy-wait: a delay that does not yield to the scheduler."""
    end = time.perf_counter_ns() + int(microseconds * 1000)
    while time.perf_counter_ns() < end:
        pass


def positive_control_sensitivity(
    iterations: int, pool_size: int = 256, magnitudes: Sequence[float] = LEAK_MAGNITUDES_US
) -> list[LeakageResult]:
    """Run the same two-class harness on an operation that really leaks.

    Baseline: BOTH classes cycle pools of random keys (the random-vs-random
    arrangement, which carries no fixed-key artifact). Class A does a plain
    ML-KEM-768 decapsulation. Class B does the same decapsulation and then spins
    for ``magnitude`` microseconds when a per-key "secret" bit is set (half of its
    keys), so the true mean difference is ``magnitude / 2``. A magnitude of 0 is
    included as a zero point: it must NOT be flagged, otherwise the baseline is
    contaminated and the other rows mean nothing.

    Running several magnitudes shows the smallest leak this harness, at this
    iteration count on this host, actually detects. A clean result elsewhere in
    the report can only be read as bounded by that sensitivity.
    """
    material_a = [_kem_material() for _ in range(pool_size)]
    material_b = [_kem_material() for _ in range(pool_size)]
    rng = random.Random(20260927)
    secret_bits = [rng.random() < 0.5 for _ in range(pool_size)]

    pool_a = [_kem_from_material(sk, ct) for sk, ct in material_a]
    pool_b = [_kem_from_material(sk, ct) for sk, ct in material_b]

    out: list[LeakageResult] = []
    try:
        for magnitude in magnitudes:

            def do_a(i: int) -> None:
                kem, ct = pool_a[i % pool_size]
                kem.decap_secret(ct)

            def do_b(i: int, magnitude: float = magnitude) -> None:
                kem, ct = pool_b[i % pool_size]
                kem.decap_secret(ct)
                if secret_bits[i % pool_size]:  # secret-dependent extra work
                    _spin_us(magnitude)

            out.extend(
                measure_two_class(
                    f"POSITIVE CONTROL ML-KEM-768 decap + secret-dependent delay {magnitude:.2f}us",
                    do_a,
                    do_b,
                    "random keys",
                    "random keys + delay on half",
                    iterations=iterations,
                    crop_sweep=(0.0, 0.5),
                    notes=[
                        "Random-vs-random baseline plus a DELIBERATE secret-dependent delay of "
                        f"{magnitude:.2f}us on half of class B's keys (true mean difference "
                        f"{magnitude / 2:.3f}us). 0.00us is the zero point and must not be flagged."
                    ],
                )
            )
    finally:
        for kem, _ in pool_a + pool_b:
            kem.free()
    return out


def detection_threshold_us(
    results: Sequence[LeakageResult],
) -> tuple[float | None, float | None, bool]:
    """(smallest non-zero magnitude flagged at every crop level, largest tried, zero-point flagged).

    ``zero-point flagged`` True means the 0us row exceeded the threshold: the
    baseline is contaminated and the sensitivity figure must not be trusted.
    """
    by_magnitude: dict[float, list[float]] = {}
    for r in results:
        if not r.name.startswith("POSITIVE CONTROL"):
            continue
        magnitude = float(r.name.split("delay ")[1].split("us")[0])
        by_magnitude.setdefault(magnitude, []).append(abs(r.t_statistic))
    if not by_magnitude:
        return None, None, False
    zero_flagged = any(t > T_SUSPICIOUS for t in by_magnitude.get(0.0, []))
    detected = [m for m, ts in by_magnitude.items() if m > 0 and all(t > T_CLEAR for t in ts)]
    return (min(detected) if detected else None), max(by_magnitude), zero_flagged


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def run_all(iterations: int = 10_000, save_json: str | None = None) -> list[LeakageResult]:
    try:
        import oqs  # noqa: F401
    except Exception as exc:  # pragma: no cover - depends on environment
        print(f"liboqs unavailable ({exc}); leakage tests need the [liboqs] extra.")
        return []

    print("=" * 96)
    print("TIMING-LEAKAGE ASSESSMENT - fixed-vs-random two-class testing")
    print(f"{iterations:,} measurements per class per test, interleaved")
    print("=" * 96)

    results: list[LeakageResult] = []
    for title, experiment in (
        ("NEGATIVE CONTROL A - apparatus noise floor (fixed vs fixed)", control_fixed_vs_fixed),
        (
            "NEGATIVE CONTROL B - repetition vs key effect (random vs random)",
            control_random_vs_random,
        ),
        ("ML-KEM-768 decapsulation - key dependence", decap_fixed_vs_random),
        (
            "CALIBRATION - public inputs only (secret fixed, ciphertext varies)",
            decap_public_calibration,
        ),
        (
            "CALIBRATION - public key only (encapsulation, no secret)",
            encap_public_key_calibration,
        ),
        (
            "POSITIVE CONTROL - detection sensitivity (deliberate leak)",
            positive_control_sensitivity,
        ),
        ("ML-KEM-768 decapsulation - ciphertext validity", decap_valid_vs_invalid),
        ("ML-DSA-65 signing - key dependence", sign_fixed_vs_random),
        ("HybridKEM decapsulation - key dependence", hybrid_decap_fixed_vs_random),
    ):
        print(f"\n{title}")
        print("-" * 96)
        try:
            batch = experiment(iterations)
        except Exception as exc:
            print(f"  skipped: {type(exc).__name__}: {exc}")
            continue
        for r in batch:
            print(r)
        results.extend(batch)

    print("\n" + "=" * 96)
    controls = [r for r in results if r.name.startswith("CONTROL")]
    positive = [r for r in results if r.name.startswith("POSITIVE CONTROL")]
    calibration = [r for r in results if r.name.startswith("CALIBRATION")]
    tests = [
        r for r in results if not r.name.startswith(("CONTROL", "POSITIVE CONTROL", "CALIBRATION"))
    ]
    control_floor = max((abs(r.t_statistic) for r in controls), default=0.0)

    if controls:
        print(f"Negative control reached |t| = {control_floor:.2f} with no secret varying.")
        if control_floor > T_SUSPICIOUS:
            print(
                "  WARNING: the control alone exceeds the significance threshold, so this "
                "run cannot distinguish leakage from apparatus noise. Treat every result "
                "below as inconclusive and re-run on a quieter machine."
            )
        else:
            print(f"  Apparatus noise is below the |t| > {T_SUSPICIOUS} threshold.")

    # Group the crop sweep back together per test and check the conclusion is
    # stable across it. A verdict that depends on how much of the upper tail was
    # discarded is not a verdict — on a noisy host the t-statistic is dominated
    # by how heavy tails are handled, not by the secret.
    floor = max(T_SUSPICIOUS, control_floor)
    grouped: dict[str, list[LeakageResult]] = {}
    for r in tests:
        grouped.setdefault(r.name.split(" [")[0], []).append(r)

    unstable: list[str] = []
    flagged: list[str] = []
    for base, variants in grouped.items():
        ts = [abs(v.t_statistic) for v in variants]
        exceeds = [t > floor for t in ts]
        if all(exceeds):
            flagged.append(f"{base}: |t| = {min(ts):.2f}-{max(ts):.2f} across crop sweep")
        elif any(exceeds):
            unstable.append(f"{base}: |t| = {min(ts):.2f}-{max(ts):.2f} across crop sweep")

    print(
        f"\nVerdict threshold: |t| > {floor:.2f} (nominal {T_SUSPICIOUS}, control {control_floor:.2f})"
    )

    # Disambiguate a positive fixed-vs-random result using control B. If varying
    # the key between two classes produces nothing, then a fixed-vs-random signal
    # is not tracking key values; it is tracking the fact that one class repeats
    # byte-identical work. Saying so here keeps the distinction from being lost.
    rvr = [abs(r.t_statistic) for r in controls if "random vs random" in r.name]
    fvr = [abs(r.t_statistic) for r in tests if "fixed key vs fresh key" in r.name]
    if rvr and fvr and max(fvr) > floor and max(rvr) < floor:
        print(
            f"\nINTERPRETATION: fixed-vs-random reaches |t| = {max(fvr):.2f} while "
            f"random-vs-random stays at |t| = {max(rvr):.2f}.\n"
            "  Varying the key alone produces no class difference, so the positive\n"
            "  result is not explained by key values. What separates the classes is that\n"
            "  the fixed class repeats byte-identical key and ciphertext data. The\n"
            "  mechanism is not established by this harness (repetition reaching a\n"
            "  microarchitectural steady state is one candidate). The calibrations below\n"
            "  test whether data with NO secret reproduces the signal. A fixed-vs-random\n"
            "  t taken on its own would have been a false positive here."
        )

    # Positive control: what the harness can actually detect.
    if positive:
        found, largest, zero_flagged = detection_threshold_us(positive)
        if zero_flagged:
            print(
                "\nPOSITIVE CONTROL: the 0us zero point was flagged, so the baseline is "
                "contaminated on this host and no sensitivity figure can be trusted."
            )
        elif found is None:
            print(
                f"\nPOSITIVE CONTROL: no deliberate leak up to {largest}us per affected "
                "call was flagged. This run could not have detected a leak of that size, "
                "so a clean result above is NOT evidence of absence at that scale."
            )
        else:
            print(
                f"\nPOSITIVE CONTROL: a secret-dependent delay of {found}us (mean "
                f"difference {found / 2:.3f}us between classes) was flagged at every crop "
                "level and the 0us zero point was not. Leakage smaller than that is not "
                "excluded by a clean result."
            )

    # Calibrations: can data with NO secret (or a fixed secret) reproduce the signal?
    if fvr:
        for r_group in (
            [r for r in calibration if "same vs fresh ciphertext" in r.name],
            [r for r in calibration if "PUBLIC key" in r.name],
        ):
            if not r_group:
                continue
            cal_t = [abs(r.t_statistic) for r in r_group]
            label = r_group[0].name.split(" [")[0]
            print(
                f"\n{label}:\n  |t| = {min(cal_t):.2f}-{max(cal_t):.2f} "
                f"(fixed-vs-random decapsulation: |t| = {min(fvr):.2f}-{max(fvr):.2f})"
            )
            if max(cal_t) > floor:
                print(
                    "  This arrangement reaches the threshold with no secret varying, so a "
                    "fixed-vs-random signal of similar size need not involve the secret."
                )
            else:
                print("  This arrangement does not reach the threshold.")

    if flagged:
        print("\nExceeded the threshold at EVERY crop level (robust signal):")
        for line in flagged:
            print(f"  - {line}")
    if unstable:
        print("\nExceeded the threshold at SOME crop levels only (NOT a conclusion):")
        for line in unstable:
            print(f"  - {line}")
        print(
            "  A verdict that flips with the cropping threshold is dominated by tail\n"
            "  handling, not by the secret. Re-run on a quiet, CPU-pinned host with\n"
            "  more iterations before reporting either way."
        )
    if not flagged and not unstable:
        print("\nNo test exceeded the threshold at any crop level.")
        print("Leakage is bounded at this setup's resolution; not a constant-time proof.")
    print("=" * 96)

    if save_json:
        os.makedirs(os.path.dirname(save_json) or ".", exist_ok=True)
        payload = {
            "iterations_per_class": iterations,
            "t_clear_threshold": T_CLEAR,
            "t_suspicious_threshold": T_SUSPICIOUS,
            "results": [asdict(r) for r in results],
        }
        with open(save_json, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        print(f"\nSaved to {save_json}")

    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=10_000)
    parser.add_argument("--save", type=str, default=None)
    args = parser.parse_args()
    run_all(iterations=args.iterations, save_json=args.save)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
