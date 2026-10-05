"""Every benchmark number the papers print, computed from saved run files.

    python tests/bench/paper_numbers.py results/env2/<dir> [--env1 results/env1/<dir>] --out numbers.json

Inputs are the per-run JSON files written by bench_kem.py / bench_signatures.py (``kem_run*.json``,
``sigs_run*.json``); the first run is discarded as warm-up. For each benchmark the centre is the
**median across runs of each run's median**. The 95% interval is a percentile bootstrap over the
*runs* (B = 10,000): it describes how much the figure moves from run to run on this machine, not
the sampling error inside one run, because samples inside a run are not independent. Nothing is typed
by hand; the papers' tables, figures and text numbers are all read from the output.
"""

from __future__ import annotations

import argparse
import glob
import json
import math
import random
import statistics as st
import sys
from pathlib import Path
from typing import Any

B = 10_000
SEED = 20261006


def _rows(path: str) -> dict[str, dict[str, Any]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = data["results"]
    if isinstance(rows, dict):
        rows = [r for section in rows.values() for r in section]
    return {r["name"]: r for r in rows}


def load_runs(directory: str, prefix: str) -> list[dict[str, dict[str, Any]]]:
    files = sorted(glob.glob(f"{directory}/{prefix}_run*.json"))
    if len(files) < 3:
        raise SystemExit(f"need at least 3 run files for {prefix} in {directory}")
    return [_rows(f) for f in files[1:]]  # sorted order: kem_run1 first; it is the warm-up


def bootstrap_ci(
    values: list[float], stat=st.median, b: int = B, seed: int = SEED
) -> tuple[float, float]:
    rng = random.Random(seed)
    n = len(values)
    est = sorted(stat([values[rng.randrange(n)] for _ in range(n)]) for _ in range(b))
    return est[int(0.025 * b)], est[int(0.975 * b) - 1]


def summarise(per_run: list[float]) -> dict[str, float]:
    lo, hi = bootstrap_ci(per_run)
    return {
        "median": st.median(per_run),
        "run_min": min(per_run),
        "run_max": max(per_run),
        "ci95_lo": lo,
        "ci95_hi": hi,
        "runs": len(per_run),
    }


def row_stats(runs: list[dict[str, dict[str, Any]]], name: str) -> dict[str, float]:
    rows = [r[name] for r in runs]
    out = summarise([r["median_us"] for r in rows])
    out["p95"] = st.median(r["p95_us"] for r in rows)
    out["p99"] = st.median(r["p99_us"] for r in rows)
    out["cov_in_run"] = st.median(r["cov_pct"] for r in rows)
    return out


def welch(a: list[float], b: list[float]) -> dict[str, float]:
    """Welch t, Satterthwaite df and Cohen's d for two samples of per-run values."""
    na, nb = len(a), len(b)
    ma, mb = st.mean(a), st.mean(b)
    va, vb = st.variance(a), st.variance(b)
    se2 = va / na + vb / nb
    t = (mb - ma) / math.sqrt(se2)
    df = se2**2 / ((va / na) ** 2 / (na - 1) + (vb / nb) ** 2 / (nb - 1))
    sp = math.sqrt(((na - 1) * va + (nb - 1) * vb) / (na + nb - 2))
    return {"t": t, "df": df, "cohens_d": (mb - ma) / sp, "n_a": na, "n_b": nb}


K = {
    "x_kg": "Decomp ① X25519 keygen",
    "x_dh": "Decomp ① X25519 DH exchange",
    "m_kg": "Decomp ② ML-KEM-768 keygen",
    "m_en": "Decomp ② ML-KEM-768 encapsulate",
    "m_de": "Decomp ② ML-KEM-768 decapsulate",
    "h_kg": "Decomp ③ HybridKEM keygen      (full)",
    "h_en": "Decomp ③ HybridKEM encapsulate (full)",
    "h_de": "Decomp ③ HybridKEM decapsulate (full)",
}


def per_run(runs, name: str, key: str = "median_us") -> list[float]:
    return [r[name][key] for r in runs]


def decomposition(kem) -> dict[str, Any]:
    out: dict[str, Any] = {k: row_stats(kem, name) for k, name in K.items()}
    # combiner overhead, computed per run then summarised (not from rounded medians)
    for op, h, x, m in (
        ("keygen", "h_kg", "x_kg", "m_kg"),
        ("encapsulate", "h_en", "x_dh", "m_en"),
        ("decapsulate", "h_de", "x_dh", "m_de"),
    ):
        vals = [
            a - b - c for a, b, c in zip(per_run(kem, K[h]), per_run(kem, K[x]), per_run(kem, K[m]))
        ]
        out[f"overhead_{op}"] = summarise(vals)
    hs = [
        sum(v)
        for v in zip(per_run(kem, K["h_kg"]), per_run(kem, K["h_en"]), per_run(kem, K["h_de"]))
    ]
    cl = [a + b for a, b in zip(per_run(kem, K["x_kg"]), per_run(kem, K["x_dh"]))]
    out["handshake_hybrid"] = summarise(hs)
    out["handshake_classical"] = summarise(cl)
    out["handshake_overhead"] = summarise([h - c for h, c in zip(hs, cl)])
    out["handshake_ratio"] = summarise([h / c for h, c in zip(hs, cl)])
    out["welch_run_level"] = welch(cl, hs)
    out["overhead_share_of_handshake"] = summarise(
        [
            (o_k + o_e + o_d) / h
            for o_k, o_e, o_d, h in zip(
                [
                    a - b - c
                    for a, b, c in zip(
                        per_run(kem, K["h_kg"]), per_run(kem, K["x_kg"]), per_run(kem, K["m_kg"])
                    )
                ],
                [
                    a - b - c
                    for a, b, c in zip(
                        per_run(kem, K["h_en"]), per_run(kem, K["x_dh"]), per_run(kem, K["m_en"])
                    )
                ],
                [
                    a - b - c
                    for a, b, c in zip(
                        per_run(kem, K["h_de"]), per_run(kem, K["x_dh"]), per_run(kem, K["m_de"])
                    )
                ],
                hs,
            )
        ]
    )
    # the independent benchmark of the same operation ("Real ML-KEM-768" rows), as a cross-check
    real = [
        sum(v)
        for v in zip(
            per_run(kem, "HybridKEM keygen (Real ML-KEM-768)"),
            per_run(kem, "HybridKEM encapsulate (Real ML-KEM-768)"),
            per_run(kem, "HybridKEM decapsulate (Real ML-KEM-768)"),
        )
    ]
    out["handshake_hybrid_crosscheck_real_rows"] = summarise(real)
    return out


SIG_NAMES = [
    "Ed25519 sign (32B)",
    "Ed25519 verify (32B)",
    "ML-DSA-65 keygen",
    "ML-DSA-65 sign (32B)",
    "ML-DSA-65 verify (32B)",
    "HybridSign keygen (Ed25519+ML-DSA-65)",
    "HybridSign sign (32B)",
    "HybridSign verify (32B)",
    "X.509 HybridCert build (Ed25519+ML-DSA-65)",
    "X.509 HybridCert verify_cosig",
]


def throughput(kem) -> dict[str, Any]:
    out = {}
    for users in (100, 500, 1000, 5000):
        s = row_stats(kem, f"Concurrent Handshakes ({users} users)")
        out[str(users)] = {
            "median_ms": s["median"] / 1000.0,
            "p95_ms": s["p95"] / 1000.0,
            "ops_per_s": users / (s["median"] / 1e6),
            "run_min_ops_per_s": users / (s["run_max"] / 1e6),
            "run_max_ops_per_s": users / (s["run_min"] / 1e6),
        }
    base = out["100"]["ops_per_s"]
    out["degradation_5000_vs_100_pct"] = (1 - out["5000"]["ops_per_s"] / base) * 100.0
    return out


def build(env2: str, env1: str | None) -> dict[str, Any]:
    kem, sig = load_runs(env2, "kem"), load_runs(env2, "sigs")
    result: dict[str, Any] = {
        "source": {"env2": env2, "env1": env1, "runs_used": len(kem), "first_run_discarded": True},
        "decomposition": decomposition(kem),
        "signatures": {n: row_stats(sig, n) for n in SIG_NAMES},
        "throughput": throughput(kem),
        "noise_reference": {
            "aes_gcm_encrypt_1kb": row_stats(kem, "AES-256-GCM encrypt 1 KB"),
            "aes_gcm_decrypt_1kb": row_stats(kem, "AES-256-GCM decrypt 1 KB"),
            "hkdf": row_stats(kem, "HKDF-SHA256 (32B → 32B)"),
        },
        "hybrid_real_rows": {
            op: row_stats(kem, f"HybridKEM {op} (Real ML-KEM-768)")
            for op in ("keygen", "encapsulate", "decapsulate")
        },
        "x25519_mock_rows": {
            op: row_stats(kem, f"HybridKEM {op} (X25519+mock{' PQC' if op == 'keygen' else ''})")
            for op in ("keygen", "encapsulate", "decapsulate")
        },
        "ed25519_standalone": {
            "sign": row_stats(kem, "Ed25519 sign"),
            "verify": row_stats(kem, "Ed25519 verify"),
        },
        "hkdf_and_envelope": {
            n: row_stats(kem, n)
            for n in (
                "Envelope.seal() 1KB (X25519+mock KEM)",
                "Envelope.open() 1KB (X25519+mock KEM)",
            )
        },
    }
    tls = result["decomposition"]["handshake_overhead"]["median"]
    result["tls_budget"] = {
        "hybrid_overhead_us": tls,
        "share_of_8ms_pct": tls / 8000.0 * 100,
        "share_of_40ms_pct": tls / 40000.0 * 100,
        "share_of_100ms_pct": tls / 100000.0 * 100,
    }
    if env1:
        k1, s1 = load_runs(env1, "kem"), load_runs(env1, "sigs")
        pairs = {
            "ML-KEM keygen": (K["m_kg"], kem, k1),
            "ML-KEM encap": (K["m_en"], kem, k1),
            "ML-KEM decap": (K["m_de"], kem, k1),
            "HybridKEM keygen": (K["h_kg"], kem, k1),
            "HybridKEM encap": (K["h_en"], kem, k1),
            "HybridKEM decap": (K["h_de"], kem, k1),
            "ML-DSA keygen": ("ML-DSA-65 keygen", sig, s1),
            "ML-DSA sign": ("ML-DSA-65 sign (32B)", sig, s1),
            "ML-DSA verify": ("ML-DSA-65 verify (32B)", sig, s1),
        }
        cross = {}
        for label, (name, r2, r1) in pairs.items():
            cross[label] = {"env2": row_stats(r2, name), "env1": row_stats(r1, name)}
            cross[label]["ratio_env1_over_env2"] = (
                cross[label]["env1"]["median"] / cross[label]["env2"]["median"]
            )
        hs1 = [
            sum(v)
            for v in zip(per_run(k1, K["h_kg"]), per_run(k1, K["h_en"]), per_run(k1, K["h_de"]))
        ]
        hs2 = [
            sum(v)
            for v in zip(per_run(kem, K["h_kg"]), per_run(kem, K["h_en"]), per_run(kem, K["h_de"]))
        ]
        cross["Full KEM handshake"] = {
            "env2": summarise(hs2),
            "env1": summarise(hs1),
            "ratio_env1_over_env2": st.median(hs1) / st.median(hs2),
        }
        result["cross_env"] = cross
        result["env1_throughput"] = throughput(k1)
    return result


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("env2")
    ap.add_argument("--env1")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    numbers = build(args.env2, args.env1)
    Path(args.out).write_text(json.dumps(numbers, indent=2), encoding="utf-8")
    d = numbers["decomposition"]
    sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
    print(f"runs used: {numbers['source']['runs_used']}  ->  {args.out}")
    print(
        f"handshake: {d['handshake_hybrid']['median']:.1f} us  [{d['handshake_hybrid']['ci95_lo']:.1f}, {d['handshake_hybrid']['ci95_hi']:.1f}]"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
