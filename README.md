# appsec-takehome

Three AppSec checks behind one command:

1. **Secrets scan** (gitleaks) with an explicit baseline
2. **SAST** (semgrep) with noise reduction and a severity threshold
3. **Triage report** that ranks the findings from both

The scanners run in pinned Docker images. Nothing is installed on the host.

## Requirements

- **Docker.** The first run pulls `zricethezav/gitleaks:v8.30.1` and `semgrep/semgrep:1.185.0`, pinned in `config/images.env`.
- **`python3` 3.8 or newer.** Standard library only.
- **Linux or macOS.** If Docker needs root, add your user to the `docker` group or run with `DOCKER="sudo docker" ./run.sh`.

## Run (one command)

```bash
cd appsec-takehome
./run.sh            # or: make
echo $?             # 0
```

Expected output:

```
== Task 1: secrets
[scan_secrets] running gitleaks (zricethezav/gitleaks:v8.30.1)
[scan_secrets] raw=2 suppressed_by_baseline=2 new=0
[scan_secrets] OK: no new secrets
== Task 2: sast
[scan_sast] running semgrep (semgrep/semgrep:1.185.0)
[scan_sast] findings=4 (CRITICAL=0 HIGH=0 MEDIUM=1 LOW=1 INFO=2) MIN_SEVERITY=HIGH blocking=0
[scan_sast] OK: nothing at/above HIGH
== Task 3: triage report
[triage] wrote .../artifacts/triage.md from sast.json, secrets.filtered.json, secrets.summary.json
== summary: secrets=0 sast=0 triage=0 -> exit 0  (report: artifacts/triage.md)
```

Files written to `artifacts/`:

- `secrets.raw.json`
- `secrets.filtered.json`
- `secrets.summary.json`
- `sast.json`
- `sast.sarif`
- `triage.md`

## Exit codes

| Command | 0 | 1 | 2 |
|---|---|---|---|
| `./run.sh` | all clean | a new secret, or a SAST finding at or above `MIN_SEVERITY` | any task errored |
| `./run.sh secrets` | no new secrets (baselined ones are allowed) | at least one secret not in `baseline.json` | tool or config error |
| `./run.sh sast` | nothing at or above `MIN_SEVERITY` | at least one finding at or above it | tool error or invalid `MIN_SEVERITY` |
| `./run.sh triage` | report written | n/a | no scan output to read |
| `make test` | all 25 checks pass | n/a | at least one check failed |

Exit code 2 means the tool itself failed, for example Docker is missing or the baseline is malformed. A broken setup never looks like a clean scan.

`make` and `make <task>` run the same commands. GNU make exits **2** on any failure, so it cannot distinguish findings from errors; it prints the underlying exit code instead. Use `./run.sh` when the exact code matters.

## Automated tests (`make test`)

```bash
make test            # or: ./tests/test_smoke.sh
```

Every scenario runs on a throwaway copy of the repo in a temporary folder, so `baseline.json`, the configs and `artifacts/` are never modified. Requires Docker and `python3`. With root-only Docker: `DOCKER="sudo docker" make test`. Runtime is about one minute.

Expected result:

```text
== Task 1: secrets
  PASS  exit 0 when only baselined secrets exist
  ...
== Tooling
  PASS  Docker unavailable: exit 2, never a false green

passed: 25  failed: 0
```

| Block | Checks | Coverage |
|---|---|---|
| Task 1: secrets | 9 | Exit 0 with only baselined secrets, 1 on a new secret, 2 on a malformed baseline. Raw and filtered artifacts written. `fixture` tuning suppresses `.env.example`. Every baseline entry has a rule, file and reason. Secret values never appear in `artifacts/`. Reruns are byte-identical. |
| Task 2: SAST | 7 | `sast.json` and `sast.sarif` written. `HIGH` (default): exit 0. `MEDIUM`: exit 1, 1 blocking. `INFO`: exit 1, 4 blocking. Invalid `MIN_SEVERITY`: exit 2. Reruns are byte-identical. Removing the noise reduction from `config/semgrep.yml` adds findings, including HIGH. |
| Task 3: triage | 8 | `./run.sh` produces `triage.md` with all four required sections. Regeneration is byte-identical. Top 5 ordered by severity desc, then path asc. No scan output: exit 2. |
| Tooling | 1 | Docker unavailable: exit 2. |

`./tests/test_smoke.sh` exits 0 when every check passes and 1 otherwise. A `FAIL` line names the criterion that failed. Typical causes are leftover test files in `demo/` (for example `leak.py`, `zz_secret.py`, `calc.py`) or an edited `baseline.json` or config.

## Task 1: Secrets scan

```bash
./run.sh secrets; echo $?   # 0: 2 demo secrets found, both accepted in baseline.json
python3 -c 'import secrets; print("T = \"agapi_tok_" + secrets.token_hex(16) + "\"")' > demo/app/leak.py
./run.sh secrets; echo $?   # 1: "NEW secrets detected ... demo/app/leak.py:1"
rm demo/app/leak.py
```

To accept a finding:

1. Run `make baseline`. This adds every current finding to `baseline.json` with the reason "UNREVIEWED".
2. Replace it with a real `reason`. Optionally add `"expires": "YYYY-MM-DD"`.

Each entry shows its rule, file and reason. Entries match on `sha256(rule \0 file \0 secret)[:16]`, so they still match after a secret moves to another line, and the secret itself is never stored. Secret values appear as `REDACTED` in every artifact.

## Task 2: SAST with a severity threshold

```bash
./run.sh sast;                         echo $?   # 0  (default HIGH: 0 blocking)
MIN_SEVERITY=CRITICAL ./run.sh sast;   echo $?   # 0  (0 blocking)
MIN_SEVERITY=MEDIUM   ./run.sh sast;   echo $?   # 1  (1 blocking)
MIN_SEVERITY=LOW      ./run.sh sast;   echo $?   # 1  (2 blocking)
MIN_SEVERITY=INFO     ./run.sh sast;   echo $?   # 1  (4 blocking: the most sensitive)
```

The scale is `INFO < LOW < MEDIUM < HIGH < CRITICAL`, case-insensitive. Every finding left after noise reduction is written to `sast.json` and `sast.sarif`, marked `blocking: true/false`.

## Task 3: Triage report

```bash
./run.sh triage     # reads artifacts/*.json / *.sarif and writes artifacts/triage.md
```

`./run.sh` (all) also generates this report, including when a scan fails. It contains:

- counts by severity and by category
- the **top 5** findings, ordered by severity (highest first), then by file path (A to Z)
- **suppressed vs new** secrets, with the reason for each suppression

It works with Task 1 output, Task 2 output, or both.

## Tuning choices and why

- **Secrets:** the full upstream ruleset plus a custom `agapi-internal-token` rule; `artifacts/`, `.git/` and lockfiles are excluded, and values marked `fixture` (the convention for deliberately fake values) are ignored.
- **SAST:** a bounded set of 7 Python security rules. `config/semgrep.yml` reduces noise in three ways, marked N1–N3: test paths are skipped, the safe form of each API is allowlisted (`pattern-not`), and hygiene issues are LOW or INFO. Without these, the demo yields 11 findings (5 HIGH) instead of 4 (none HIGH).
- **No hidden suppressions:** `.gitleaksignore`, inline `gitleaks:allow`, `# nosemgrep` and semgrep's built-in default ignore list (which would silently skip `tests/`) are all disabled. Every suppression lives in `config/` or `baseline.json`.
- **Same repo state, same results:** scanner images are pinned and run with `--network none` against a read-only mount; output is sorted, paths are relative, and there are no timestamps.

## Assumptions

- **Languages:** secret scanning is language-agnostic. The SAST rules target Python. Adding rules for another language to `config/semgrep.yml` extends coverage.
- **Scope:** the working tree only, not git history. Secrets in history require `gitleaks git` and rotation.
- **Network:** needed only to pull the two images on the first run. Scans run with networking disabled.
- **Without Docker:** set `GITLEAKS_BIN` / `SEMGREP_BIN` to local binaries. These versions are unpinned, so results may differ.

## Layout

```
run.sh  Makefile  baseline.json
config/   gitleaks.toml  semgrep.yml  images.env
scripts/  scan_secrets.py  scan_sast.py  triage_report.py  scanner.py (docker/local runner)
demo/     fake secrets + deliberately unsafe code to scan
tests/    test_smoke.sh  (25 checks: make test)
artifacts/  generated output
```
