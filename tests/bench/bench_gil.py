"""Does the Python binding release the GIL during liboqs calls? A scaling test with controls.

    python tests/bench/bench_gil.py --threads 1 2 4 --total 24000 --repeats 7 --save results/gil.json

A fixed amount of work (``--total`` operations) is split across T threads and the wall-clock time is
measured. ``speedup(T) = time(1 thread) / time(T threads)``. Run it with at least as many CPUs as the
largest T (for Docker: ``--cpuset-cpus="0-3"``).

Three workloads, so the number can be interpreted:

* ``python busy loop`` (negative control): pure Python holds the GIL, so threads must give no speedup.
  If this shows a speedup the machine or the method is wrong.
* ``liboqs ML-KEM-768 decapsulate``: the binding call alone. A speedup well above the control means
  the GIL is released while liboqs runs.
* ``HybridKEM encapsulate+decapsulate``: what a server actually calls. The Python combiner around the C
  calls holds the GIL, so this scales less than the raw call (Amdahl's law).

The concurrent-handshake table in the paper does NOT answer this question: its throughput is below the
single-thread rate, so it shows thread overhead, not parallelism.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import threading
import time
import warnings
from collections.abc import Callable
from pathlib import Path

try:
    from ._provenance import environment
except ImportError:  # run as a script
    from _provenance import environment


def _run(threads: int, total: int, make_worker: Callable[[], Callable[[int], None]]) -> float:
    """Wall-clock seconds for ``total`` operations split over ``threads`` threads."""
    per = total // threads
    workers = [make_worker() for _ in range(threads)]  # one object per thread: no shared state
    barrier = threading.Barrier(threads + 1)

    def target(w: Callable[[int], None]) -> None:
        barrier.wait()
        w(per)

    ts = [threading.Thread(target=target, args=(w,)) for w in workers]
    for t in ts:
        t.start()
    barrier.wait()
    t0 = time.perf_counter()
    for t in ts:
        t.join()
    return time.perf_counter() - t0


def _busy_worker() -> Callable[[int], None]:
    def work(n: int) -> None:
        for _ in range(n):
            x = 0
            for i in range(180):  # a few microseconds of pure-Python work
                x += i * i

    return work


def _oqs_worker() -> Callable[[int], None]:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        import oqs

    sender = oqs.KeyEncapsulation("ML-KEM-768")
    pub = sender.generate_keypair()
    ct, _ = sender.encap_secret(pub)

    def work(n: int) -> None:
        for _ in range(n):
            sender.decap_secret(ct)

    return work


def _hybrid_worker() -> Callable[[int], None]:
    from quantum_safe.kem.hybrid import HybridKEM

    kem = HybridKEM()
    kp = kem.generate_keypair()

    def work(n: int) -> None:
        for _ in range(n):
            ct, _ss = kem.encapsulate(kp.public)
            kem.decapsulate(kp.secret, ct)

    return work


WORKLOADS = {
    "python busy loop (negative control)": _busy_worker,
    "liboqs ML-KEM-768 decapsulate": _oqs_worker,
    "HybridKEM encapsulate+decapsulate": _hybrid_worker,
}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--threads", type=int, nargs="+", default=[1, 2, 4])
    ap.add_argument(
        "--total", type=int, default=24000, help="operations per measurement, split across threads"
    )
    ap.add_argument("--repeats", type=int, default=7)
    ap.add_argument("--save")
    args = ap.parse_args(argv)
    if 1 not in args.threads:
        ap.error("--threads must include 1 (the baseline)")
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]

    results: dict[str, dict[str, dict[str, float]]] = {}
    for name, factory in WORKLOADS.items():
        _run(1, 1000, factory)  # warm-up
        per_thread: dict[int, list[float]] = {}
        for _ in range(args.repeats):
            for t in args.threads:  # interleave thread counts so drift hits all equally
                per_thread[t] = per_thread.get(t, []) + [_run(t, args.total, factory)]
        base = statistics.median(per_thread[1])
        results[name] = {}
        print(f"\n{name}")
        for t in args.threads:
            med = statistics.median(per_thread[t])
            results[name][str(t)] = {
                "median_s": med,
                "min_s": min(per_thread[t]),
                "max_s": max(per_thread[t]),
                "speedup_vs_1_thread": base / med,
                "ops_per_s": args.total / med,
            }
            print(
                f"  {t} thread(s): {med * 1000:8.1f} ms   {args.total / med:10.0f} ops/s   speedup {base / med:4.2f}x"
            )

    if args.save:
        Path(args.save).parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "metadata": {**environment(), "total_ops": args.total, "repeats": args.repeats},
            "results": results,
        }
        Path(args.save).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"\nSaved to {args.save}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
