"""``--iterations`` must change how many samples the benchmarks take.

It was parsed and ignored: every published "3,000 iterations" table was measured with the
built-in 1,000 (980 samples after the 1% trim).
"""

from __future__ import annotations

import pytest

from tests.bench import bench_kem, bench_signatures


@pytest.fixture(autouse=True)
def _restore_default():
    before_kem, before_sig = bench_kem._DEFAULT_ITERATIONS, bench_signatures._DEFAULT_ITERATIONS
    yield
    bench_kem._DEFAULT_ITERATIONS = before_kem
    bench_signatures._DEFAULT_ITERATIONS = before_sig


@pytest.mark.parametrize("module", [bench_kem, bench_signatures])
def test_default_iterations_is_used_when_a_benchmark_names_none(module) -> None:
    module.set_default_iterations(300)
    result = module._bench("x", lambda: None, warmup=5)
    # 300 samples, 1% trimmed from each end -> 294
    assert result.iterations == 300 and len(result.samples_us) == 294


@pytest.mark.parametrize("module", [bench_kem, bench_signatures])
def test_an_explicit_count_still_wins(module) -> None:
    module.set_default_iterations(300)
    result = module._bench("x", lambda: None, iterations=50, warmup=5)
    assert result.iterations == 50 and len(result.samples_us) == 48


@pytest.mark.parametrize("module", [bench_kem, bench_signatures])
def test_too_few_iterations_are_refused(module) -> None:
    with pytest.raises(ValueError):
        module.set_default_iterations(5)
