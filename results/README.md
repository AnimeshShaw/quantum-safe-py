# Benchmark data

Raw output of the benchmark runs the papers are computed from. Everything here is written by the scripts
in `tests/bench/`; nothing is edited by hand.

| Directory | What it is |
|---|---|
| `env2/2026-10-06_16runs/` | ENV-2 (Docker, Linux): one discarded warm-up run plus 15 timed runs, 3,000 iterations each, with every timed sample (`kem_run*.json`, `sigs_run*.json`); the two-class leakage screen (`leakage.json`); the GIL scaling test (`gil.json`, `gil_replicate.json`); `ENVIRONMENT.txt` (machine, kernel, Docker, power plan); `paper_numbers.json` (every number the papers print, computed from the files above) |
| `env1/2026-10-06/` | ENV-1 (Windows 11, native Python): the same protocol, plus `leakage.json` |

Reproduce: `bash tests/bench/run_env2.sh`, `bash tests/bench/run_env1.sh`, then
`python tests/bench/paper_numbers.py results/env2/<dir> --env1 results/env1/<dir> --out paper_numbers.json`.

The run files record the commit, the machine and the liboqs version in `metadata`. Results are specific to that
machine and session: the same host gave different absolute figures in an earlier session, which is why the papers
report medians over runs with their spread, and why a figure here should not be quoted without its interval.

Logs (`*.log`) are not kept: they carry local paths and nothing the JSON does not.
