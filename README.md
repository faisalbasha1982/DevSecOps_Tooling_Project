# appsec-takehome

Three AppSec checks behind one command:

1. **Secrets scan** (gitleaks) with an explicit baseline
2. **SAST** (semgrep) with noise reduction and a severity threshold
3. **Triage report** that ranks the findings from both

The scanners run in pinned Docker images. Nothing is installed on your machine.

## Requirements

- **Docker.** The first run pulls `zricethezav/gitleaks:v8.30.1` and `semgrep/semgrep:1.185.0`. These versions are pinned in `config/images.env`.
- **`python3` 3.8 or newer.** Only the standard library is used. Tested on 3.13 and 3.14.
- **Linux or macOS.** If Docker needs root on your machine, add yourself to the `docker` group, or run with `DOCKER="sudo docker" ./run.sh`.

## Run (one command)

```bash
cd appsec-takehome
./run.sh            # or: make
echo $?             # 0
```

Expected output:

```
== Task 1: secrets
[scan_secrets] raw=2 suppressed_by_baseline=2 new=0
[scan_secrets] OK: no new secrets
== Task 2: sast
[scan_sast] findings=4 (CRITICAL=0 HIGH=0 MEDIUM=1 LOW=1 INFO=2) MIN_SEVERITY=HIGH blocking=0
[scan_sast] OK: nothing at/above HIGH
== Task 3: triage report
[triage] wrote .../artifacts/triage.md from sast.json, secrets.filtered.json, secrets.summary.json
== summary: secrets=0 sast=0 triage=0 -> exit 0  (report: artifacts/triage.md)
```

This writes these files to `artifacts/`:

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

Exit code 2 means the tool itself failed, for example Docker is missing or the baseline is malformed. A broken setup never looks like a clean scan.

`make` and `make <task>` run the same commands. However, GNU make always exits **2** on any failure, so it can't tell findings apart from errors. It prints the real code instead. Use `./run.sh` when you need the exact code.

## Task 1: Secrets scan

```bash
./run.sh secrets; echo $?   # 0: 2 demo secrets found, both accepted in baseline.json
python3 -c 'import secrets; print("T = \"agapi_tok_" + secrets.token_hex(16) + "\"")' > demo/app/leak.py
./run.sh secrets; echo $?   # 1: "NEW secrets detected ... demo/app/leak.py:1"
rm demo/app/leak.py
```

To accept a finding:

1. Run `make baseline`. This adds it to `baseline.json` with the reason "UNREVIEWED".
2. Write a real `reason`. You can also add `"expires": "YYYY-MM-DD"`.

Each entry shows its rule, file and reason. Entries match on `sha256(rule \0 file \0 secret)[:16]`, so they still match after a secret moves to another line, and the secret itself is never stored. Secret values appear as `REDACTED` in every artifact.

## Task 2: SAST with a severity threshold

```bash
./run.sh sast;                       echo $?   # 0  (default HIGH: 0 blocking)
MIN_SEVERITY=MEDIUM ./run.sh sast;   echo $?   # 1  (1 blocking)
MIN_SEVERITY=INFO   ./run.sh sast;   echo $?   # 1  (4 blocking: the most sensitive)
```

The scale is `INFO < LOW < MEDIUM < HIGH < CRITICAL`, case-insensitive. Every finding left after noise reduction is written to `sast.json` and `sast.sarif`, marked `blocking: true/false`.

## Task 3: Triage report

```bash
./run.sh triage     # reads artifacts/*.json / *.sarif and writes artifacts/triage.md
```

`./run.sh` (all) generates this report too, even when a scan fails. It contains:

- counts by severity and by category
- the **top 5** findings, ordered by severity (highest first), then by file path (A to Z)
- **suppressed vs new** secrets, with the reason for each suppression

It works with Task 1 output, Task 2 output, or both.

## Tuning choices and why

- **Secrets:** the full upstream ruleset, plus a custom `agapi-internal-token` rule. It excludes `artifacts/`, `.git/` and lockfiles, and ignores values marked `fixture` (the convention for deliberately fake values).
- **SAST:** a bounded set of 7 Python security rules. `config/semgrep.yml` reduces noise in three ways, marked N1–N3: it skips test paths, ignores the safe form of each API (`pattern-not`), and gives hygiene issues a LOW or INFO severity. Without these, the demo produces 11 findings (5 HIGH) instead of 4 (none HIGH).
- **No hidden suppressions:** `.gitleaksignore`, inline `gitleaks:allow`, `# nosemgrep` and semgrep's built-in default ignore list are all switched off. That last one silently skipped `tests/`. Every suppression is in `config/` or `baseline.json`.
- **Same repo state, same results:** the scanner images are pinned and run with `--network none` against a read-only mount. Output is sorted, paths are relative, and there are no timestamps.

## Assumptions

- **Languages:** secret scanning is language-agnostic. The SAST rules target Python, the demo language. Adding rules for another language to `config/semgrep.yml` extends coverage.
- **Scope:** the working tree only, not git history. Secrets in history would need `gitleaks git` and rotation.
- **Network:** needed only to pull the two images on the first run. Scans then run with networking disabled.
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

