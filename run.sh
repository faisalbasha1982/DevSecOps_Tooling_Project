#!/usr/bin/env bash
# One command for the whole take-home (Linux/macOS).
# Needs: python3 (standard library only) and Docker. Scanners run in pinned
# images from config/images.env - nothing is installed on the host.
#
#   ./run.sh                    all tasks: secrets -> sast -> triage
#   ./run.sh secrets            Task 1   exit 0 none new | 1 new secrets       | 2 error
#   ./run.sh sast               Task 2   exit 0 below    | 1 >= MIN_SEVERITY   | 2 error
#   ./run.sh triage             Task 3   exit 0 written  |                     | 2 no input
#   ./run.sh <task> -- <flags>  pass flags to the task's script,
#                               e.g. ./run.sh secrets -- --update-baseline
#
# `all` exits 2 if any task errored, else 1 if secrets or sast failed, else 0.
# Env: MIN_SEVERITY (default HIGH), SCAN_TARGET (default: this folder),
#      DOCKER (default "docker"; e.g. DOCKER="sudo docker"),
#      GITLEAKS_BIN / SEMGREP_BIN (use a local binary instead of Docker; unpinned).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON="${PYTHON:-python3}"
TASK="${1:-all}"
[[ $# -gt 0 ]] && shift
[[ "${1:-}" == "--" ]] && shift

command -v "$PYTHON" >/dev/null 2>&1 || { echo "run.sh: $PYTHON not found" >&2; exit 2; }

run_task() {  # run_task <task> [flags...] -> the task's exit code
  local task="$1"; shift
  case "$task" in
    secrets) "$PYTHON" "$ROOT/scripts/scan_secrets.py"  ${@+"$@"} ;;
    sast)    "$PYTHON" "$ROOT/scripts/scan_sast.py"     ${@+"$@"} ;;
    triage)  "$PYTHON" "$ROOT/scripts/triage_report.py" ${@+"$@"} ;;
    *) echo "run.sh: unknown task '$task' (use: all, secrets, sast, triage)" >&2; return 2 ;;
  esac
}

if [[ "$TASK" != "all" ]]; then
  set +e; run_task "$TASK" ${@+"$@"}; rc=$?; set -e
  exit "$rc"
fi

set +e
echo "== Task 1: secrets" >&2;        run_task secrets; s=$?
echo "== Task 2: sast" >&2;           run_task sast;    a=$?
echo "== Task 3: triage report" >&2;  run_task triage;  t=$?   # always runs
set -e

if   [[ $s -eq 2 || $a -eq 2 || $t -eq 2 ]]; then rc=2
elif [[ $s -eq 1 || $a -eq 1 ]];               then rc=1
else rc=0; fi
echo "== summary: secrets=$s sast=$a triage=$t -> exit $rc  (report: artifacts/triage.md)" >&2
exit "$rc"

