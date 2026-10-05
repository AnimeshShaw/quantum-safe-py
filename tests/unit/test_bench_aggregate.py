"""The aggregator reports the median across runs, not the best run."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.bench.aggregate_runs import aggregate


def _write(path: Path, medians: dict[str, float], sections: bool = False) -> Path:
    rows = [{"name": n, "median_us": m} for n, m in medians.items()]
    data = {"results": {"s": rows} if sections else rows, "metadata": {"machine": "x"}}
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


def test_median_of_runs_not_best_of_runs(tmp_path: Path) -> None:
    files = [
        _write(tmp_path / "r1.json", {"op": 10.0}),
        _write(tmp_path / "r2.json", {"op": 12.0}),
        _write(tmp_path / "r3.json", {"op": 20.0}),
    ]
    row = aggregate(files)["rows"][0]
    assert row["median_of_run_medians_us"] == 12.0  # not the fastest, 10.0
    assert row["fastest_run_us"] == 10.0 and row["slowest_run_us"] == 20.0
    assert row["runs"] == 3


def test_discard_first_drops_the_warm_up_run(tmp_path: Path) -> None:
    files = [
        _write(tmp_path / "r1.json", {"op": 100.0}),  # cold: discarded
        _write(tmp_path / "r2.json", {"op": 10.0}),
        _write(tmp_path / "r3.json", {"op": 12.0}),
    ]
    result = aggregate(files, discard_first=True)
    assert result["rows"][0]["slowest_run_us"] == 12.0
    assert result["rows"][0]["runs"] == 2 and result["discarded_first"] is True


def test_accepts_both_result_layouts(tmp_path: Path) -> None:
    a = _write(tmp_path / "a.json", {"op": 5.0}, sections=False)
    b = _write(tmp_path / "b.json", {"op": 7.0}, sections=True)
    assert aggregate([a, b])["rows"][0]["median_of_run_medians_us"] == 6.0


def test_runs_with_different_benchmarks_are_refused(tmp_path: Path) -> None:
    a = _write(tmp_path / "a.json", {"op": 5.0})
    b = _write(tmp_path / "b.json", {"other": 5.0})
    with pytest.raises(ValueError):
        aggregate([a, b])


def test_discard_first_needs_two_files(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        aggregate([_write(tmp_path / "a.json", {"op": 5.0})], discard_first=True)
