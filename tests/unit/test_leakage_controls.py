"""The leakage harness's calibration and positive control (finding D10).

A clean result from a two-class timing test means little unless the harness
can be shown to detect a leak, and a fixed-vs-random signal means little unless
it is shown that data with no secret does not reproduce it. These tests check
the control machinery, not any claim about liboqs: the timing assertions use
magnitudes far above the noise so they do not flake.
"""

from __future__ import annotations

import pytest

from tests.bench import bench_leakage as bl
from tests.bench.bench_leakage import ClassStats, LeakageResult


def _result(name: str, t: float) -> LeakageResult:
    stats = ClassStats(label="x", n=10, mean_us=1.0, median_us=1.0, stdev_us=0.1, cov_pct=10.0)
    return LeakageResult(
        name=name,
        class_a=stats,
        class_b=stats,
        t_statistic=t,
        p_value=0.0,
        df=10.0,
        delta_mean_us=0.0,
        verdict="",
        trim_description="untrimmed",
    )


def _pc(magnitude: float, *ts: float) -> list[LeakageResult]:
    return [
        _result(
            f"POSITIVE CONTROL ML-KEM-768 decap + secret-dependent delay {magnitude:.2f}us [x]", t
        )
        for t in ts
    ]


class TestDetectionThreshold:
    def test_smallest_magnitude_flagged_at_every_crop_level(self) -> None:
        rows = [
            *_pc(0.0, 1.0, 0.5),
            *_pc(0.5, 4.0, 3.0),
            *_pc(1.0, 11.0, 9.0),
            *_pc(2.0, 12.0, 30.0),
        ]
        found, largest, zero_flagged = bl.detection_threshold_us(rows)
        assert found == 2.0  # 1.0 is flagged at one crop level only
        assert largest == 2.0
        assert not zero_flagged

    def test_nothing_detected(self) -> None:
        found, largest, zero_flagged = bl.detection_threshold_us([*_pc(0.0, 1.0), *_pc(0.5, 2.0)])
        assert found is None and largest == 0.5 and not zero_flagged

    def test_a_flagged_zero_point_means_the_baseline_is_contaminated(self) -> None:
        _, _, zero_flagged = bl.detection_threshold_us([*_pc(0.0, 8.0), *_pc(5.0, 40.0)])
        assert zero_flagged

    def test_ignores_other_rows_and_handles_no_rows(self) -> None:
        assert bl.detection_threshold_us([_result("CONTROL x", 50.0)]) == (None, None, False)
        assert bl.detection_threshold_us([]) == (None, None, False)

    def test_the_zero_point_is_part_of_the_default_magnitudes(self) -> None:
        assert 0.0 in bl.LEAK_MAGNITUDES_US and min(bl.LEAK_MAGNITUDES_US) == 0.0


@pytest.mark.requires_liboqs
class TestControlsRunThroughTheHarness:
    def test_a_large_deliberate_leak_is_detected_and_the_zero_point_is_not(self) -> None:
        # This measures real time, so on a busy shared runner a single run can put the
        # zero point over the threshold (|t| = 10.3 was seen on a CI VM). That is the
        # contamination the harness exists to report, not a defect in it. A 20 us leak
        # must be detected in every attempt; the zero point must be clean in at least
        # one of three attempts.
        zero_ts: list[list[float]] = []
        for _ in range(3):
            results = bl.positive_control_sensitivity(
                iterations=4000, pool_size=64, magnitudes=(0.0, 20.0)
            )
            by_name = {r.name: abs(r.t_statistic) for r in results}
            zero = [t for n, t in by_name.items() if "delay 0.00us" in n]
            big = [t for n, t in by_name.items() if "delay 20.00us" in n]
            assert zero and big
            assert min(big) > bl.T_CLEAR, f"a 20us secret-dependent delay was not detected: {big}"
            zero_ts.append(zero)
            if max(zero) < bl.T_CLEAR:
                return
        raise AssertionError(f"the zero point was flagged in all three attempts: {zero_ts}")
        found, largest, zero_flagged = bl.detection_threshold_us(results)
        assert found == 20.0 and largest == 20.0 and not zero_flagged

    def test_the_public_data_calibrations_run_and_hold_no_secret_constant(self) -> None:
        for fn, expect in (
            (bl.decap_public_calibration, "same vs fresh ciphertext"),
            (bl.encap_public_key_calibration, "PUBLIC key"),
        ):
            rows = fn(iterations=600, pool_size=16)
            assert rows and all(r.name.startswith("CALIBRATION") for r in rows)
            assert all(expect in r.name for r in rows)
            # equal sample counts per class within each crop level (n shrinks as the tail is cropped)
            assert all(r.class_a.n == r.class_b.n for r in rows)

    def test_calibrations_and_controls_are_excluded_from_the_tested_results(self) -> None:
        """run_all() must not count them as tests of a secret."""
        src = open(bl.__file__, encoding="utf-8").read()
        assert 'startswith(("CONTROL", "POSITIVE CONTROL", "CALIBRATION"))' in src
