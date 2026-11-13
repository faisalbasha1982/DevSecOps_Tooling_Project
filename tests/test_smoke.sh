#!/usr/bin/env bash
# Smoke tests: one block per task, each check maps to an acceptance criterion.
# Every scenario runs on a throwaway copy of the repo; the real files are never touched.
#   ./tests/test_smoke.sh    (or: make test)
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
unset MIN_SEVERITY SCAN_TARGET
PASS=0; FAIL=0; WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

check() { if eval "$2"; then echo "  PASS  $1"; PASS=$((PASS+1)); else echo "  FAIL  $1"; FAIL=$((FAIL+1)); fi; }
copy()  { python3 -c 'import shutil,sys; shutil.copytree(sys.argv[1], sys.argv[2], ignore=shutil.ignore_patterns("artifacts",".git","__pycache__"))' "$ROOT" "$WORK/$1"; mkdir -p "$WORK/$1/artifacts"; echo "$WORK/$1"; }
run()   { local r="$1"; shift; (cd "$r" && ./run.sh "$@" >"$WORK/log" 2>&1); echo $?; }
py()    { python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print($2)" "$1"; }
A()     { echo "$R/artifacts/$1"; }

echo "== Task 1: secrets"
R="$(copy t1)"; rc="$(run "$R" secrets)"
check "exit 0 when only baselined secrets exist"         '[[ $rc == 0 ]]'
check "secrets.raw.json + secrets.filtered.json written"  '[[ -f $(A secrets.raw.json) && -f $(A secrets.filtered.json) ]]'
check "raw has 2 findings, filtered has 0"                '[[ $(py $(A secrets.raw.json) "len(d)") == 2 && $(py $(A secrets.filtered.json) "len(d)") == 0 ]]'
check "tuning works: .env.example (fixture) not reported" '! grep -q env.example $(A secrets.raw.json)'
check "baseline is inspectable: rule, file, reason each"  '[[ $(py $R/baseline.json "all(e[\"rule_id\"] and e[\"file\"] and e[\"reason\"] for e in d[\"entries\"])") == True ]]'
cp "$(A secrets.raw.json)" "$(A secrets.filtered.json)" "$WORK/"; run "$R" secrets >/dev/null
check "deterministic: rerun is byte-identical"            'cmp -s $WORK/secrets.raw.json $(A secrets.raw.json) && cmp -s $WORK/secrets.filtered.json $(A secrets.filtered.json)'
TOKEN="$(python3 -c 'import secrets; print("acme_tok_" + secrets.token_hex(16))')"
printf 'T = "%s"\n' "$TOKEN" > "$R/demo/app/leak.py"; rc="$(run "$R" secrets)"
check "exit 1 on a new (non-baseline) secret"             '[[ $rc == 1 && $(py $(A secrets.filtered.json) "len(d)") == 1 ]]'
check "secret value never written to artifacts"           '! grep -rq "$TOKEN" $R/artifacts/'
R="$(copy t1b)"; echo "{bad" > "$R/baseline.json"; rc="$(run "$R" secrets)"
check "exit 2 on a malformed baseline"                    '[[ $rc == 2 ]]'

echo "== Task 2: SAST"
R="$(copy t2)"; rc="$(run "$R" sast)"
check "sast.json + sast.sarif written"                    '[[ -f $(A sast.json) && -f $(A sast.sarif) ]]'
check "default MIN_SEVERITY=HIGH: exit 0, 0 blocking"     '[[ $rc == 0 && $(py $(A sast.json) "d[\"summary\"][\"blocking\"]") == 0 ]]'
rc="$(MIN_SEVERITY=MEDIUM run "$R" sast)"
check "MIN_SEVERITY=MEDIUM: exit 1, 1 blocking"           '[[ $rc == 1 && $(py $(A sast.json) "d[\"summary\"][\"blocking\"]") == 1 ]]'
rc="$(MIN_SEVERITY=INFO run "$R" sast)"
check "MIN_SEVERITY=INFO: exit 1, 4 blocking (> HIGH)"    '[[ $rc == 1 && $(py $(A sast.json) "d[\"summary\"][\"blocking\"]") == 4 ]]'
rc="$(MIN_SEVERITY=SEVERE run "$R" sast)"
check "invalid MIN_SEVERITY: exit 2"                      '[[ $rc == 2 ]]'
run "$R" sast >/dev/null; cp "$(A sast.json)" "$(A sast.sarif)" "$WORK/"; run "$R" sast >/dev/null
check "deterministic: rerun is byte-identical"            'cmp -s $WORK/sast.json $(A sast.json) && cmp -s $WORK/sast.sarif $(A sast.sarif)'
R="$(copy t2b)"
python3 - "$R/config/semgrep.yml" <<'PY'
import re, sys
p = sys.argv[1]; s = open(p).read()
s = re.sub(r"\n\s+paths:\n\s+exclude:.*", "", s)      # drop (N1)
s = re.sub(r"\n\s+- pattern-not:.*", "", s)           # drop (N2)
open(p, "w").write(s)
PY
rc="$(run "$R" sast)"
check "noise reduction in semgrep.yml changes output (4 -> $(py $(A sast.json) "d[\"summary\"][\"total\"]"), HIGH appear)" \
      '[[ $rc == 1 && $(py $(A sast.json) "d[\"summary\"][\"by_severity\"][\"HIGH\"]") -gt 0 ]]'

echo "== Task 3: triage"
R="$(copy t3)"; rc="$(run "$R" all)"
check "./run.sh produces artifacts/triage.md in one command" '[[ $rc == 0 && -f $(A triage.md) ]]'
for h in "## Counts by severity" "## Counts by category" "## Top 5 to review" "## Secrets: suppressed vs new"; do
  check "section present: $h" 'grep -qF "$h" $(A triage.md)'
done
cp "$(A triage.md)" "$WORK/"; run "$R" all >/dev/null
check "deterministic: rescan + regenerate is byte-identical" 'cmp -s $WORK/triage.md $(A triage.md)'
printf 'K = "%s"\n' "$TOKEN" > "$R/demo/zz_secret.py"
printf 'def q(c, x):\n    c.execute(f"SELECT {x}")\n' > "$R/demo/app/b_sql.py"
printf 'def q(c, x):\n    c.execute("SELECT " + x)\n' > "$R/demo/app/a_sql.py"
run "$R" all >/dev/null
TOP="$(python3 - "$(A triage.md)" <<'PY'
import sys
sec = open(sys.argv[1]).read().split("## Top 5 to review")[1].split("\n## ")[0]
rows = [[c.strip() for c in l.split("|")] for l in sec.splitlines() if l.startswith("| ") and l.split("|")[1].strip().isdigit()]
print(";".join(f"{r[2]} {r[3].strip('`').rsplit(':', 1)[0]}" for r in rows[:3]))
PY
)"
check "stable order: severity desc, then path asc"        '[[ "$TOP" == "CRITICAL demo/zz_secret.py;HIGH demo/app/a_sql.py;HIGH demo/app/b_sql.py" ]]'
R="$(copy t3b)"; rc="$(run "$R" triage)"
check "no scan output: exit 2"                            '[[ $rc == 2 ]]'

echo "== Tooling"
R="$(copy t4)"; rc="$(DOCKER=/nonexistent/docker run "$R" secrets)"
check "Docker unavailable: exit 2, never a false green"   '[[ $rc == 2 ]]'

echo; echo "passed: $PASS  failed: $FAIL"
[[ $FAIL == 0 ]]
