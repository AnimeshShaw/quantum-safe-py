"""paper_numbers.py: the statistics behind every benchmark figure in the papers."""

from __future__ import annotations

import json
import math
from pathlib import Path

import pytest

from tests.bench import paper_numbers as pn


def test_welch_matches_the_textbook_formula() -> None:
    a = [10.0, 11.0, 12.0, 13.0, 14.0]
    b = [20.0, 21.0, 23.0, 22.0, 24.0]
    w = pn.welch(a, b)
    va, vb = 2.5, 2.5
    expected_t = (22.0 - 12.0) / math.sqrt(va / 5 + vb / 5)
    assert w["t"] == pytest.approx(expected_t)
    assert w["df"] == pytest.approx(8.0)  # equal variances and sizes: Welch df = n_a + n_b - 2
    assert w["cohens_d"] == pytest.approx(10.0 / math.sqrt(2.5))


def test_bootstrap_interval_is_deterministic_and_brackets_the_median() -> None:
    values = [10.0, 11.0, 12.0, 13.0, 14.0, 15.0, 30.0]
    lo, hi = pn.bootstrap_ci(values)
    assert (lo, hi) == pn.bootstrap_ci(values)  # fixed seed: the paper's numbers are reproducible
    assert lo <= 13.0 <= hi
    s = pn.summarise(values)
    assert s["median"] == 13.0 and s["run_min"] == 10.0 and s["run_max"] == 30.0 and s["runs"] == 7


def _write_runs(directory: Path, prefix: str, per_run_medians: list[float], name: str) -> None:
    for i, m in enumerate(per_run_medians, start=1):
        row = {"name": name, "median_us": m, "p95_us": m * 1.2, "p99_us": m * 1.5, "cov_pct": 4.0}
        (directory / f"{prefix}_run{i}.json").write_text(
            json.dumps({"results": [row]}), encoding="utf-8"
        )


def test_the_first_run_is_discarded_as_warm_up(tmp_path: Path) -> None:
    _write_runs(tmp_path, "kem", [1000.0, 10.0, 12.0, 14.0], "x")  # run 1 is the cold run
    runs = pn.load_runs(str(tmp_path), "kem")
    assert [r["x"]["median_us"] for r in runs] == [10.0, 12.0, 14.0]
    assert pn.row_stats(runs, "x")["median"] == 12.0


def test_fewer_than_three_runs_are_refused(tmp_path: Path) -> None:
    _write_runs(tmp_path, "kem", [1.0, 2.0], "x")
    with pytest.raises(SystemExit):
        pn.load_runs(str(tmp_path), "kem")
