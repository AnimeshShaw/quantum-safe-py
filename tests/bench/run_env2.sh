#!/usr/bin/env bash
# ENV-2 benchmark protocol: build from the current commit, run N timed runs plus a discarded
# warm-up, run the leakage screen, aggregate from the saved files, record the environment.
#
#   bash tests/bench/run_env2.sh                 # defaults: 6 runs (the first is discarded), 3000 iterations
#   RUNS=4 ITER=1000 LEAK_ITER=5000 bash tests/bench/run_env2.sh   # quick rehearsal
#
# Run from the repository root, in Git Bash, with Docker Desktop running and nothing else heavy open.
# Everything lands in results/env2/<date>/ . No number is typed by hand: the aggregate and every
# table in the papers are computed from these files.
set -euo pipefail

RUNS="${RUNS:-6}"            # run 1 is the warm-up and is discarded by the aggregator
ITER="${ITER:-3000}"
LEAK_ITER="${LEAK_ITER:-20000}"
CPUS="${CPUS:-0,1}"
IMAGE="quantum-safe-bench"
OUT="${OUT_DIR:-results/env2/$(date +%Y-%m-%d)}"   # OUT_DIR=results/env2/rehearsal for a trial run
export MSYS_NO_PATHCONV=1   # stop Git Bash rewriting /out and /app paths

if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  echo "ERROR: uncommitted changes. Commit first so the recorded commit is the code that ran." >&2
  exit 1
fi
COMMIT="$(git rev-parse HEAD)"
mkdir -p "$OUT"

echo "== environment =="
{
  echo "commit: $COMMIT"
  echo "date: $(date -u +%FT%TZ)"
  echo "runs: $RUNS (first discarded)  iterations: $ITER  leakage iterations: $LEAK_ITER  cpuset: $CPUS"
  echo "--- docker version"; docker version
  echo "--- docker info"; docker info
  echo "--- running containers"; docker ps
  echo "--- power plan"; (powercfg.exe /getactivescheme 2>/dev/null || echo "powercfg not available")
  echo "--- battery/AC"; (powershell.exe -NoProfile -Command "(Get-CimInstance Win32_Battery | Select-Object BatteryStatus | Out-String)" 2>/dev/null || true)
  echo "--- host uptime"; (powershell.exe -NoProfile -Command "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime" 2>/dev/null || true)
} > "$OUT/ENVIRONMENT.txt" 2>&1
cat "$OUT/ENVIRONMENT.txt" | head -12

echo "== build image from $COMMIT =="
docker build --build-arg QS_GIT_COMMIT="$COMMIT" -t "$IMAGE" .

run() {  # run <name> <command...> : one container, pinned CPUs, output mounted
  local name="$1"; shift
  docker run --rm --cpuset-cpus="$CPUS" -v "$(pwd)/$OUT:/out" "$IMAGE" sh -c "$*" \
    > "$OUT/${name}.log" 2>&1
}

for i in $(seq 1 "$RUNS"); do
  echo "== run $i of $RUNS: KEM =="
  run "kem_run${i}" "python -X utf8 tests/bench/bench_kem.py --with-pqc --iterations $ITER --raw-samples --save /out/kem_run${i}.json"
  echo "== run $i of $RUNS: signatures =="
  run "sigs_run${i}" "python -X utf8 tests/bench/bench_signatures.py --with-pqc --iterations $ITER --raw-samples --save /out/sigs_run${i}.json"
done

echo "== leakage screen (controls included) =="
run "leakage" "python -X utf8 tests/bench/bench_leakage.py --iterations $LEAK_ITER --save /out/leakage.json"

echo "== aggregate (median across runs; first run discarded) =="
run "aggregate_kem"  "python -X utf8 tests/bench/aggregate_runs.py '/out/kem_run*.json'  --discard-first --out /out/kem_aggregate.json"
run "aggregate_sigs" "python -X utf8 tests/bench/aggregate_runs.py '/out/sigs_run*.json' --discard-first --out /out/sigs_aggregate.json"

echo
echo "Done. Files in $OUT :"
ls -la "$OUT"
echo "Do not edit the paper yet: send these files' summary to the assistant first."
