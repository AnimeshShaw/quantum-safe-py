"""Aggregate several saved benchmark runs into one table, from the files alone.

    python tests/bench/aggregate_runs.py results/env2/kem_run*.json --discard-first \\
        --out results/env2/kem_aggregate.json

For each benchmark the table gives the **median across runs of each run's median**, the
fastest and slowest run median, and the spread between runs (CoV of the run medians). Taking the
median across runs, not the fastest run, is what the papers' methodology section says; the
best-of-three tables the papers carried before were about 8% optimistic against it.

``--discard-first`` drops the first file in sorted order (the warm-up run) before aggregating.
Both result layouts the harnesses write are accepted: a flat ``"results"`` list (bench_kem) and a
``"results"`` dict of sections (bench_signatures).
"""

from __future__ import annotations

import argparse
import glob
import json
import statistics
import sys
from pathlib import Path
from typing import Any


def _flatten(data: dict[str, Any]) -> dict[str, float]:
    """name -> median_us for one run file."""
    results = data["results"]
    rows: list[dict[str, Any]] = []
    if isinstance(results, list):
        rows = results
    else:
        for section in results.values():
            rows.extend(section)
    out: dict[str, float] = {}
    for row in rows:
        name = row["name"]
        if name in out:
            raise ValueError(f"duplicate benchmark name in one run: {name!r}")
        out[name] = float(row["median_us"])
    return out


def aggregate(paths: list[Path], discard_first: bool = False) -> dict[str, Any]:
    paths = sorted(paths)
    if discard_first:
        if len(paths) < 2:
            raise ValueError("--discard-first needs at least two run files")
        paths = paths[1:]
    if not paths:
        raise ValueError("no run files")

    runs = [_flatten(json.loads(p.read_text(encoding="utf-8"))) for p in paths]
    names = list(runs[0])
    for i, run in enumerate(runs[1:], start=2):
        if set(run) != set(names):
            raise ValueError(f"run {i} ({paths[i - 1].name}) has a different set of benchmarks")

    metadata = json.loads(paths[0].read_text(encoding="utf-8")).get("metadata", {})
    rows = []
    for name in names:
        medians = [run[name] for run in runs]
        spread = (
            statistics.stdev(medians) / statistics.mean(medians) * 100.0
            if len(medians) > 1
            else 0.0
        )
        rows.append(
            {
                "name": name,
                "runs": len(medians),
                "median_of_run_medians_us": round(statistics.median(medians), 3),
                "fastest_run_us": round(min(medians), 3),
                "slowest_run_us": round(max(medians), 3),
                "run_to_run_cov_pct": round(spread, 2),
            }
        )
    return {
        "files": [str(p) for p in paths],
        "discarded_first": discard_first,
        "metadata_of_first_file": metadata,
        "rows": rows,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("files", nargs="+", help="run JSON files (globs allowed)")
    parser.add_argument("--discard-first", action="store_true", help="drop the first (warm-up) run")
    parser.add_argument("--out", help="write the aggregate as JSON")
    args = parser.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # benchmark names contain arrows

    paths = [Path(p) for pattern in args.files for p in glob.glob(pattern)] or [
        Path(p) for p in args.files
    ]
    result = aggregate(paths, discard_first=args.discard_first)

    print(f"{len(result['files'])} runs" + (" (first discarded)" if args.discard_first else ""))
    print(f"{'benchmark':<58} {'median':>10} {'fastest':>10} {'slowest':>10} {'run CoV':>8}")
    for r in result["rows"]:
        print(
            f"{r['name']:<58} {r['median_of_run_medians_us']:>10.2f} {r['fastest_run_us']:>10.2f} "
            f"{r['slowest_run_us']:>10.2f} {r['run_to_run_cov_pct']:>7.1f}%"
        )
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"\nSaved to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
