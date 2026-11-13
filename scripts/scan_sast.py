#!/usr/bin/env python3
"""
scan_sast.py - Task 2: semgrep SAST with scope control, noise reduction and a
severity threshold.

Pipeline
  1. Run semgrep (pinned Docker image, --network none) with ONLY
     config/semgrep.yml (local rules, no registry, no metrics). Scope is defined here, explicitly:
       - semgrep's implicit ignore lists are switched off (its built-in default
         .semgrepignore silently skips folders such as tests/), git state is
         ignored (--no-git-ignore), inline `# nosemgrep` is ignored;
       - only tool/output folders are excluded (SCOPE_EXCLUDES below).
     Every remaining suppression (noise reduction) lives in config/semgrep.yml.
  2. Normalise and sort findings deterministically.
  3. Mark each finding blocking if severity >= MIN_SEVERITY.
     -> artifacts/sast.json   (all post-noise-reduction findings + summary)
     -> artifacts/sast.sarif  (SARIF 2.1.0 for GitHub/GitLab code scanning)
  4. Exit 0 if no blocking finding, 1 if any, 2 on tool/config error.

Severity scale: INFO < LOW < MEDIUM < HIGH < CRITICAL   (MIN_SEVERITY default: HIGH)
Standard library only; semgrep runs in its pinned Docker image (scanner.py).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))
from scanner import Scanner, ScannerError  # noqa: E402

EXIT_CLEAN, EXIT_BLOCKING, EXIT_ERROR = 0, 1, 2

SEVERITIES = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
RANK = {s: i for i, s in enumerate(SEVERITIES)}
LEGACY = {"WARNING": "MEDIUM", "ERROR": "HIGH"}        # older semgrep severity names
SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
SECURITY_SEVERITY = {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.5", "LOW": "3.0", "INFO": "0.0"}

# Out of scope because they are tooling or our own outputs - not noise reduction.
SCOPE_EXCLUDES = [".git", ".venv", "artifacts", "node_modules"]

ROOT = Path(__file__).resolve().parent.parent

# semgrep phones home (update check, metrics) unless told not to. Inside Docker
# it also runs with --network none (scanner.py), so it cannot reach anything.
SEMGREP_ENV = {"SEMGREP_ENABLE_VERSION_CHECK": "0", "SEMGREP_SEND_METRICS": "off"}
SCAN_TIMEOUT_S = int(os.environ.get("SAST_TIMEOUT", "600"))


class WrapperError(Exception):
    pass


def log(msg: str) -> None:
    print(f"[scan_sast] {msg}", file=sys.stderr)


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8", newline="\n") as fh:
        json.dump(data, fh, indent=2, sort_keys=True, ensure_ascii=False)
        fh.write("\n")
    tmp.replace(path)


def parse_min_severity(raw: str) -> str:
    value = raw.strip().upper()
    value = LEGACY.get(value, value)
    if value not in RANK:
        raise WrapperError(f"MIN_SEVERITY='{raw}' is invalid; use one of {', '.join(SEVERITIES)}")
    return value


# --------------------------------------------------------------------------- #
# Scanner
# --------------------------------------------------------------------------- #
def run_semgrep(scanner: Scanner) -> Dict[str, Any]:
    args = ["scan", ".",
            "--config", scanner.config_path,
            "--json", "--output", f"{scanner.out_path}/semgrep.json",
            "--metrics=off", "--disable-version-check",
            "--disable-nosem",                     # no hidden inline suppressions
            "--no-git-ignore",                     # results must not depend on git state
            "--x-ignore-semgrepignore-files",      # no implicit default ignore list
            "--quiet"]
    for d in SCOPE_EXCLUDES:
        args += ["--exclude", d]
    log(f"running semgrep ({scanner.ref})")
    try:
        proc = scanner.run(args, env=SEMGREP_ENV, timeout=SCAN_TIMEOUT_S)
    except ScannerError as exc:
        raise WrapperError(str(exc)) from exc
    report = scanner.outdir / "semgrep.json"
    # semgrep: 0 = ran OK (with or without findings); anything else = failure
    if proc.returncode != 0 or not report.is_file():
        raise WrapperError(f"semgrep failed (exit {proc.returncode}):\n{proc.stderr.strip()[-2000:]}")
    data = json.loads(report.read_text(encoding="utf-8"))

    fatal = [e for e in data.get("errors", []) if e.get("level", "error") == "error"
             and e.get("type") not in ("Syntax error", "Lexical error", "PartialParsing")]
    if fatal:
        raise WrapperError("semgrep reported errors: " + "; ".join(
            str(e.get("message", e))[:300] for e in fatal))
    for e in data.get("errors", []):
        if e not in fatal:
            log(f"WARNING: {e.get('type')}: {str(e.get('message', ''))[:200]}")
    return data


# --------------------------------------------------------------------------- #
# Normalisation
# --------------------------------------------------------------------------- #
def normalise(data: Dict[str, Any], min_sev: str) -> List[Dict[str, Any]]:
    findings = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {}) or {}
        # semgrep prefixes rule ids with the config file's directory
        # ("config.python-eval-dynamic"); keep the bare id so it is location-independent.
        rule_id = r["check_id"].rsplit(".", 1)[-1]
        sev = extra.get("severity", "INFO").upper()
        sev = LEGACY.get(sev, sev)
        if sev not in RANK:
            raise WrapperError(f"rule {rule_id} has unknown severity {sev}")
        path = Path(r["path"]).as_posix()           # Path("./a/b") -> "a/b"
        start, end = r["start"], r["end"]
        fp = hashlib.sha256(f"{rule_id}\0{path}\0{start['line']}\0{start['col']}".encode()).hexdigest()[:16]
        findings.append({
            "fingerprint": fp,
            "rule_id": rule_id,
            "severity": sev,
            "blocking": RANK[sev] >= RANK[min_sev],
            "category": meta.get("category", "uncategorized"),
            "cwe": meta.get("cwe", ""),
            "fix": meta.get("fix", ""),
            "message": " ".join(extra.get("message", "").split()),
            "path": path,
            "start_line": start["line"],
            "start_col": start["col"],
            "end_line": end["line"],
        })
    # Stable order: severity desc, then path, line, column, rule
    findings.sort(key=lambda f: (-RANK[f["severity"]], f["path"], f["start_line"],
                                 f["start_col"], f["rule_id"]))
    return findings


def to_sarif(findings: List[Dict[str, Any]], version: str) -> Dict[str, Any]:
    rules: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        rules.setdefault(f["rule_id"], {
            "id": f["rule_id"],
            "name": f["rule_id"],
            "shortDescription": {"text": f["message"][:120]},
            "fullDescription": {"text": f["message"]},
            "help": {"text": f"Fix: {f['fix']}" if f["fix"] else f["message"]},
            "defaultConfiguration": {"level": SARIF_LEVEL[f["severity"]]},
            "properties": {
                "security-severity": SECURITY_SEVERITY[f["severity"]],
                "tags": sorted(t for t in ["security", f["category"], f["cwe"]] if t),
            },
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "semgrep", "version": version,
                                "informationUri": "https://semgrep.dev",
                                "rules": [rules[k] for k in sorted(rules)]}},
            "results": [{
                "ruleId": f["rule_id"],
                "level": SARIF_LEVEL[f["severity"]],
                "message": {"text": f["message"]},
                "partialFingerprints": {"primaryLocationLineHash": f["fingerprint"]},
                "properties": {"severity": f["severity"], "blocking": f["blocking"]},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": f["path"]},
                    "region": {"startLine": f["start_line"], "startColumn": f["start_col"],
                               "endLine": f["end_line"]}}}],
            } for f in findings],
        }],
    }


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Run semgrep SAST, apply MIN_SEVERITY, fail on blocking findings.",
        epilog="Exit codes: 0 = nothing at/above threshold, 1 = blocking findings, 2 = error.")
    ap.add_argument("--target", default=os.environ.get("SCAN_TARGET", str(ROOT)))
    ap.add_argument("--config", default=str(ROOT / "config" / "semgrep.yml"))
    ap.add_argument("--artifacts", default=str(ROOT / "artifacts"))
    ap.add_argument("--min-severity", default=os.environ.get("MIN_SEVERITY") or "HIGH",
                    help="block on findings at/above this (env MIN_SEVERITY, default HIGH)")
    args = ap.parse_args(argv)

    try:
        min_sev = parse_min_severity(args.min_severity)
        target, config = Path(args.target), Path(args.config)
        if not config.is_file():
            raise WrapperError(f"config not found: {config}")
        if not target.is_dir():
            raise WrapperError(f"scan target is not a directory: {target}")
        with tempfile.TemporaryDirectory(prefix="scan_sast_") as tmp:
            try:
                scanner = Scanner("semgrep", target, config, Path(tmp))
                version = scanner.version()
            except ScannerError as exc:
                raise WrapperError(str(exc)) from exc
            data = run_semgrep(scanner)
        findings = normalise(data, min_sev)
    except WrapperError as exc:
        log(f"ERROR: {exc}")
        return EXIT_ERROR

    blocking = [f for f in findings if f["blocking"]]
    by_sev = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
    out = {
        "schema_version": 1,
        "scanner": {"name": "semgrep", "version": version, "ref": scanner.ref,
                    "config": "config/semgrep.yml"},
        "min_severity": min_sev,
        "summary": {"total": len(findings), "blocking": len(blocking), "by_severity": by_sev},
        "findings": findings,
    }
    artifacts = Path(args.artifacts)
    write_json(artifacts / "sast.json", out)
    write_json(artifacts / "sast.sarif", to_sarif(findings, version))

    counts = " ".join(f"{s}={by_sev[s]}" for s in reversed(SEVERITIES))
    log(f"findings={len(findings)} ({counts}) MIN_SEVERITY={min_sev} blocking={len(blocking)}")
    if blocking:
        log(f"findings at/above {min_sev}:")
        for f in blocking:
            log(f"  {f['severity']:<8} {f['rule_id']:<38} {f['path']}:{f['start_line']}")
        return EXIT_BLOCKING
    log(f"OK: nothing at/above {min_sev}")
    return EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())

