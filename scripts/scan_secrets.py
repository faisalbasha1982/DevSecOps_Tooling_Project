#!/usr/bin/env python3
"""
scan_secrets.py - gitleaks wrapper with explicit baselining.

Pipeline
  1. Run gitleaks (filesystem mode) in its pinned Docker image (config/images.env,
     see scanner.py) with our config; no implicit suppressions.
  2. Redact secret values, sort deterministically, add a stable fingerprint
     -> artifacts/secrets.raw.json
  3. Remove findings whose fingerprint is in baseline.json (and not expired)
     -> artifacts/secrets.filtered.json   (subset of raw: NEW findings only)
     -> artifacts/secrets.summary.json    (counts, what was suppressed and why)
  4. Exit 0 if no new findings, 1 if any new finding, 2 on tool/config error.

Stable fingerprint
  gitleaks' own fingerprint in `dir` mode is "<file>:<rule>:<line>", so it
  breaks whenever a line is inserted above the secret. This wrapper uses
      sha256("<rule_id>\\0<file relative to target>\\0<secret>")[:16]
  which survives line moves but changes if the secret, the file, or the rule
  changes - exactly the cases where a human should re-review it. Secret
  values never reach artifacts/; only this one-way hash does.

Standard library only. Python 3.8+.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scanner import Scanner, ScannerError  # noqa: E402

EXIT_CLEAN = 0
EXIT_NEW_FINDINGS = 1
EXIT_ERROR = 2

BASELINE_VERSION = 1
UNREVIEWED_REASON = "UNREVIEWED - add a justification before merging"
REDACTED = "REDACTED"


class WrapperError(Exception):
    """Raised for anything that should end the run with EXIT_ERROR."""


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def log(msg: str) -> None:
    print(f"[scan_secrets] {msg}", file=sys.stderr)


def write_json(path: Path, data: Any) -> None:
    """Write JSON byte-for-byte reproducibly: sorted keys, fixed indent, trailing newline."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8", newline="\n") as fh:
        json.dump(data, fh, indent=2, sort_keys=True, ensure_ascii=False)
        fh.write("\n")
    tmp.replace(path)  # atomic: never leave a half-written artifact


def stable_fingerprint(rule_id: str, rel_file: str, secret: str) -> str:
    material = f"{rule_id}\0{rel_file}\0{secret}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()[:16]


def normalise_path(file_path: str, target: Path) -> str:
    """Report paths relative to the scan target, POSIX style, so fingerprints
    do not depend on where the repo is checked out or how the target was given."""
    p = Path(file_path)
    if not p.is_absolute():
        p = target / p
    try:
        rel = p.resolve().relative_to(target.resolve())
    except ValueError:
        rel = Path(file_path)
    return rel.as_posix()


def sort_key(f: Dict[str, Any]) -> Tuple:
    return (f["File"], f["StartLine"], f["StartColumn"], f["RuleID"], f["StableFingerprint"])


# --------------------------------------------------------------------------- #
# Scanner
# --------------------------------------------------------------------------- #
def run_gitleaks(scanner: Scanner, honor_inline_allow: bool) -> List[Dict[str, Any]]:
    """Run gitleaks (pinned Docker image by default) and return its raw findings.

    The unredacted report is written to scanner.outdir - a private 0700 temp dir
    created by main() - parsed, and deleted with that dir. It never reaches artifacts/.
    """
    args = [
        "dir", ".",                              # run from inside the target: relative paths
        "--config", scanner.config_path,
        "--report-format", "json",
        "--report-path", f"{scanner.out_path}/report.json",
        "--exit-code", "0",                      # the wrapper owns pass/fail, not gitleaks
        "--no-banner",
        "--log-level", "warn",
        # .gitleaksignore lookup points at the empty temp dir: baseline.json is
        # the ONLY per-finding suppression mechanism.
        "--gitleaks-ignore-path", scanner.out_path,
    ]
    if not honor_inline_allow:
        args.append("--ignore-gitleaks-allow")

    log(f"running gitleaks ({scanner.ref})")
    try:
        proc = scanner.run(args)
    except ScannerError as exc:
        raise WrapperError(str(exc)) from exc
    if proc.returncode != 0:
        raise WrapperError(f"gitleaks failed (exit {proc.returncode}):\n{proc.stderr.strip()[-2000:]}")
    report = scanner.outdir / "report.json"
    if not report.is_file():
        raise WrapperError("gitleaks exited 0 but wrote no report")
    try:
        data = json.loads(report.read_text(encoding="utf-8") or "[]")
    except json.JSONDecodeError as exc:
        raise WrapperError(f"could not parse gitleaks report: {exc}") from exc
    if not isinstance(data, list):
        raise WrapperError("unexpected gitleaks report shape (expected a JSON array)")
    return data


def normalise_findings(findings: List[Dict[str, Any]], target: Path) -> List[Dict[str, Any]]:
    out = []
    for f in findings:
        f = dict(f)
        secret = f.get("Secret", "")
        rel = normalise_path(f.get("File", ""), target)
        f["File"] = rel
        if f.get("Fingerprint"):  # gitleaks' own "<file>:<rule>:<line>"
            f["Fingerprint"] = f"{rel}:{f.get('RuleID', '')}:{f.get('StartLine', '')}"
        f["StableFingerprint"] = stable_fingerprint(f.get("RuleID", ""), rel, secret)
        # Redact: secret values never reach artifacts/ (which CI may upload).
        if secret:
            f["Match"] = f.get("Match", "").replace(secret, REDACTED)
        f["Secret"] = REDACTED
        out.append(f)
    out.sort(key=sort_key)
    return out


# --------------------------------------------------------------------------- #
# Baseline
# --------------------------------------------------------------------------- #
def load_baseline(path: Path) -> Dict[str, Any]:
    if not path.exists():
        log(f"baseline {path} not found - treating as empty")
        return {"version": BASELINE_VERSION, "entries": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise WrapperError(f"baseline {path} is not valid JSON: {exc}") from exc

    if data.get("version") != BASELINE_VERSION:
        raise WrapperError(f"baseline version must be {BASELINE_VERSION}")
    entries = data.get("entries")
    if not isinstance(entries, list):
        raise WrapperError("baseline must contain an 'entries' array")

    seen = set()
    for i, e in enumerate(entries):
        where = f"baseline entry #{i}"
        fp = e.get("fingerprint")
        if not isinstance(fp, str) or len(fp) != 16:
            raise WrapperError(f"{where}: 'fingerprint' must be a 16-char string")
        if fp in seen:
            raise WrapperError(f"{where}: duplicate fingerprint {fp}")
        seen.add(fp)
        if not str(e.get("reason", "")).strip():
            raise WrapperError(f"{where} ({fp}): 'reason' is required")
        exp = e.get("expires")
        if exp is not None:
            try:
                dt.date.fromisoformat(exp)
            except (TypeError, ValueError):
                raise WrapperError(f"{where} ({fp}): 'expires' must be YYYY-MM-DD or null")
    return data


def apply_baseline(
    findings: List[Dict[str, Any]], baseline: Dict[str, Any], today: dt.date
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    entries = {e["fingerprint"]: e for e in baseline["entries"]}
    active = {
        fp: e for fp, e in entries.items()
        if e.get("expires") is None or dt.date.fromisoformat(e["expires"]) >= today
    }
    expired = sorted(set(entries) - set(active))

    new, suppressed = [], []
    for f in findings:
        entry = active.get(f["StableFingerprint"])
        if entry is None:
            new.append(f)
        else:
            suppressed.append({
                "fingerprint": f["StableFingerprint"],
                "rule_id": f["RuleID"],
                "file": f["File"],
                "start_line": f["StartLine"],
                "reason": entry["reason"],
            })

    found = {f["StableFingerprint"] for f in findings}
    stale = sorted(fp for fp in entries if fp not in found)
    unreviewed = sorted(
        fp for fp, e in entries.items() if e.get("reason", "").startswith("UNREVIEWED")
    )

    summary = {
        "counts": {
            "raw": len(findings),
            "suppressed_by_baseline": len(suppressed),
            "new": len(new),
        },
        "suppressed": sorted(suppressed, key=lambda s: (s["file"], s["start_line"], s["fingerprint"])),
        "baseline_health": {
            "expired_entries": expired,        # no longer suppress anything
            "stale_entries": stale,            # secret no longer present -> remove
            "unreviewed_entries": unreviewed,  # added by --update-baseline, need a reason
        },
    }
    return new, summary


def update_baseline(path: Path, baseline: Dict[str, Any], findings: List[Dict[str, Any]]) -> int:
    """Add every current finding not yet in the baseline. Existing entries
    (and their human-written reasons) are never modified or removed."""
    known = {e["fingerprint"] for e in baseline["entries"]}
    added = 0
    today = dt.date.today().isoformat()
    for f in findings:
        if f["StableFingerprint"] in known:
            continue
        baseline["entries"].append({
            "fingerprint": f["StableFingerprint"],
            "rule_id": f["RuleID"],
            "file": f["File"],
            "line_hint": f["StartLine"],
            "reason": UNREVIEWED_REASON,
            "added_by": os.environ.get("USER", "unknown"),
            "added_on": today,
            "expires": None,
        })
        known.add(f["StableFingerprint"])
        added += 1
    baseline["entries"].sort(key=lambda e: (e.get("file", ""), e.get("rule_id", ""), e["fingerprint"]))
    baseline.setdefault("version", BASELINE_VERSION)
    write_json(path, baseline)
    return added


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    repo_root = Path(__file__).resolve().parent.parent
    p = argparse.ArgumentParser(
        description="Run gitleaks, apply baseline, fail on new secrets.",
        epilog="Exit codes: 0 = no new findings, 1 = new findings, 2 = error.",
    )
    p.add_argument("--target", default=os.environ.get("SCAN_TARGET", str(repo_root)),
                   help="directory to scan (default: repo root)")
    p.add_argument("--config", default=str(repo_root / "config" / "gitleaks.toml"))
    p.add_argument("--baseline", default=str(repo_root / "baseline.json"))
    p.add_argument("--artifacts", default=str(repo_root / "artifacts"))
    p.add_argument("--update-baseline", action="store_true",
                   help="append all current findings to the baseline as UNREVIEWED, then exit 0")
    p.add_argument("--honor-inline-allow", action="store_true",
                   help="respect `gitleaks:allow` comments (off by default: keep suppressions in baseline.json)")
    p.add_argument("--today", default=None, help=argparse.SUPPRESS)  # test hook for expiry
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    target = Path(args.target)
    artifacts = Path(args.artifacts)
    baseline_path = Path(args.baseline)
    today = dt.date.fromisoformat(args.today) if args.today else dt.date.today()

    try:
        baseline = load_baseline(baseline_path)
        config = Path(args.config)
        if not config.is_file():
            raise WrapperError(f"config not found: {config}")
        if not target.is_dir():
            raise WrapperError(f"scan target is not a directory: {target}")
        with tempfile.TemporaryDirectory(prefix="scan_secrets_") as tmp:
            os.chmod(tmp, 0o700)
            try:
                scanner = Scanner("gitleaks", target, config, Path(tmp))
                version = scanner.version()
            except ScannerError as exc:
                raise WrapperError(str(exc)) from exc
            raw = run_gitleaks(scanner, args.honor_inline_allow)
        findings = normalise_findings(raw, target)
        write_json(artifacts / "secrets.raw.json", findings)

        if args.update_baseline:
            added = update_baseline(baseline_path, baseline, findings)
            log(f"baseline updated: {added} entr{'y' if added == 1 else 'ies'} added to {baseline_path}")
            log("edit each UNREVIEWED reason before committing")
            return EXIT_CLEAN

        new, summary = apply_baseline(findings, baseline, today)
        summary["scanner"] = {"name": "gitleaks", "version": version, "ref": scanner.ref}
        write_json(artifacts / "secrets.filtered.json", new)
        write_json(artifacts / "secrets.summary.json", summary)
    except WrapperError as exc:
        log(f"ERROR: {exc}")
        return EXIT_ERROR

    c = summary["counts"]
    log(f"raw={c['raw']} suppressed_by_baseline={c['suppressed_by_baseline']} new={c['new']}")
    health = summary["baseline_health"]
    for key, label in (("expired_entries", "expired"), ("stale_entries", "stale"),
                       ("unreviewed_entries", "unreviewed")):
        if health[key]:
            log(f"WARNING: {len(health[key])} {label} baseline entr"
                f"{'y' if len(health[key]) == 1 else 'ies'}: {', '.join(health[key])}")

    if new:
        log("NEW secrets detected (not in baseline):")
        for f in new:
            log(f"  {f['StableFingerprint']}  {f['RuleID']:<24} {f['File']}:{f['StartLine']}")
        log("rotate the secret and remove it, or - if it is a known false positive - "
            "run `make baseline` and justify the entry in baseline.json")
        return EXIT_NEW_FINDINGS

    log("OK: no new secrets")
    return EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())

