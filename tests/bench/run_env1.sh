#!/usr/bin/env bash
# ENV-1 (native Windows, no container): same protocol as run_env2.sh, using the local Python.
#   PY=/path/to/python bash tests/bench/run_env1.sh      (default: python on PATH)
# Results: results/env1/<date>/ . Run with the machine idle and on AC power.
set -euo pipefail
PY="${PY:-python}"
RUNS="${RUNS:-6}"; ITER="${ITER:-3000}"
OUT="${OUT_DIR:-results/env1/$(date +%Y-%m-%d)}"
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then echo "ERROR: uncommitted changes" >&2; exit 1; fi
mkdir -p "$OUT"; git rev-parse HEAD > "$OUT/COMMIT.txt"
for i in $(seq 1 "$RUNS"); do
  echo "== run $i of $RUNS =="
  "$PY" -X utf8 tests/bench/bench_kem.py --with-pqc --iterations "$ITER" --raw-samples --save "$OUT/kem_run${i}.json" > "$OUT/kem_run${i}.log" 2>&1
  "$PY" -X utf8 tests/bench/bench_signatures.py --with-pqc --iterations "$ITER" --raw-samples --save "$OUT/sigs_run${i}.json" > "$OUT/sigs_run${i}.log" 2>&1
done
"$PY" -X utf8 tests/bench/aggregate_runs.py "$OUT/kem_run*.json" --discard-first --out "$OUT/kem_aggregate.json" > "$OUT/aggregate_kem.log"
"$PY" -X utf8 tests/bench/aggregate_runs.py "$OUT/sigs_run*.json" --discard-first --out "$OUT/sigs_aggregate.json" > "$OUT/aggregate_sigs.log"
echo "Done: $OUT"
