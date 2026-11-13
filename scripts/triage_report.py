#!/usr/bin/env python3
"""
triage_report.py - Task 3: one prioritised Markdown report from the scan outputs.

Reads whatever is present in artifacts/ (Task 1, Task 2, or both):
  Task 1  secrets.filtered.json   new secrets (not in baseline)
          secrets.summary.json    suppressed findings + reasons, baseline health
  Task 2  sast.json               preferred (rich: category, CWE, fix, blocking)
          sast.sarif              fallback, any SARIF 2.1.0 producer
Writes artifacts/triage.md.

Determinism: the report is a pure function of the input files. No timestamps,
no environment data; every list has a total ordering; inputs are identified by
content hash. Same artifacts in -> byte-identical triage.md out.

Ordering rule (top 5 and the full list):
  severity desc  ->  file path asc  ->  line asc  ->  rule id asc  ->  source asc

Severity for secrets: a NEW secret is CRITICAL (a credential in the tree is
directly usable, unlike most SAST findings, which need a reachable path).

Exit codes: 0 report written, 2 no usable input / malformed input.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]          # display order
RANK = {s: i for i, s in enumerate(reversed(SEVERITIES))}           # INFO=0 .. CRITICAL=4
SARIF_LEVEL_TO_SEV = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "INFO"}
TOP_N = 5
ROOT = Path(__file__).resolve().parent.parent


class TriageError(Exception):
    pass


def log(msg: str) -> None:
    print(f"[triage] {msg}", file=sys.stderr)


def load(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TriageError(f"cannot read {path.name}: {exc}") from exc


def sha12(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:12]


def md(text: Any) -> str:
    """Make a value safe inside a Markdown table cell."""
    return str(text).replace("|", "\\|").replace("\n", " ").strip()


# --------------------------------------------------------------------------- #
# Loaders -> one common item shape
# --------------------------------------------------------------------------- #
def item(source, severity, category, rule, path, line, blocking, message, fix="", ref="") -> Dict[str, Any]:
    return {"source": source, "severity": severity, "category": category, "rule": rule,
            "path": path, "line": int(line or 0), "blocking": bool(blocking),
            "message": message, "fix": fix, "ref": ref}


def load_secrets(art: Path) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]], List[Path]]:
    filtered, summary = art / "secrets.filtered.json", art / "secrets.summary.json"
    used, items, summ = [], [], None
    if filtered.is_file():
        data = load(filtered)
        if not isinstance(data, list):
            raise TriageError("secrets.filtered.json: expected a JSON array")
        for f in data:
            items.append(item(
                "secrets", "CRITICAL", "secret", f.get("RuleID", "?"), f.get("File", "?"),
                f.get("StartLine", 0), True,
                f"New secret not in baseline ({f.get('Description', '').strip() or f.get('RuleID')})",
                "Rotate the credential, then remove it. If it is a known false positive: "
                "`make baseline` and justify the entry.",
                f.get("StableFingerprint", "")))
        used.append(filtered)
    if summary.is_file():
        summ = load(summary)
        used.append(summary)
    return items, summ, used


def load_sast(art: Path) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, Any]], List[Path]]:
    sjson, sarif = art / "sast.json", art / "sast.sarif"
    if sjson.is_file():
        data = load(sjson)
        try:
            items = [item("sast", f["severity"], f.get("category", "uncategorized"), f["rule_id"],
                          f["path"], f["start_line"], f.get("blocking", False), f["message"],
                          f.get("fix", ""), f.get("cwe", ""))
                     for f in data["findings"]]
        except (KeyError, TypeError) as exc:
            raise TriageError(f"sast.json: unexpected shape ({exc})") from exc
        meta = {"min_severity": data.get("min_severity"), "scanner": data.get("scanner", {})}
        return items, meta, [sjson]
    if sarif.is_file():
        data = load(sarif)
        items = []
        for run in data.get("runs", []):
            for r in run.get("results", []):
                props = r.get("properties", {}) or {}
                sev = str(props.get("severity") or SARIF_LEVEL_TO_SEV.get(r.get("level", "warning"), "MEDIUM")).upper()
                loc = (r.get("locations") or [{}])[0].get("physicalLocation", {})
                items.append(item("sast", sev if sev in RANK else "MEDIUM", "sarif",
                                  r.get("ruleId", "?"), loc.get("artifactLocation", {}).get("uri", "?"),
                                  loc.get("region", {}).get("startLine", 0), props.get("blocking", False),
                                  r.get("message", {}).get("text", "")))
        return items, {"min_severity": None, "scanner": {}}, [sarif]
    return [], None, []


def sort_key(i: Dict[str, Any]):
    return (-RANK[i["severity"]], i["path"], i["line"], i["rule"], i["source"])


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #
def render(items, secrets_summary, sast_meta, inputs: List[Path], art: Path) -> str:
    items = sorted(items, key=sort_key)
    blocking = [i for i in items if i["blocking"]]
    L: List[str] = []
    add = L.append

    add("# Security triage report")
    add("")
    if not items:
        add("**Verdict: nothing to review.** No new secrets and no SAST findings after noise reduction.")
    else:
        worst = items[0]["severity"]
        add(f"**Verdict: {len(blocking)} blocking of {len(items)} findings. Highest severity: {worst}.** "
            "Start with the top 5 below; they are already in review order.")
    add("")
    add("Inputs (content hash, so this report can be matched to the exact scan):")
    add("")
    for p in inputs:
        add(f"- `{p.relative_to(art.parent).as_posix() if art.parent in p.parents else p.name}` sha256:{sha12(p)}")
    if sast_meta and sast_meta.get("min_severity"):
        sc = sast_meta.get("scanner", {})
        add(f"- SAST threshold `MIN_SEVERITY={sast_meta['min_severity']}`"
            + (f", {sc.get('name')} {sc.get('version')}" if sc.get("name") else ""))
    add("")

    # ---- counts ---------------------------------------------------------------
    add("## Counts by severity")
    add("")
    sources = [s for s in ("secrets", "sast") if any(i["source"] == s for i in items)
               or (s == "secrets" and secrets_summary is not None) or (s == "sast" and sast_meta is not None)]
    add("| Severity | " + " | ".join(sources) + " | Total | Blocking |")
    add("|---|" + "---:|" * (len(sources) + 2))
    for sev in SEVERITIES:
        row = [sum(1 for i in items if i["severity"] == sev and i["source"] == s) for s in sources]
        tot = sum(row)
        blk = sum(1 for i in items if i["severity"] == sev and i["blocking"])
        add(f"| {sev} | " + " | ".join(str(n) for n in row) + f" | {tot} | {blk} |")
    add(f"| **Total** | " + " | ".join(str(sum(1 for i in items if i['source'] == s)) for s in sources)
        + f" | **{len(items)}** | **{len(blocking)}** |")
    add("")

    add("## Counts by category")
    add("")
    if items:
        cats: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
        for i in items:
            cats.setdefault((i["source"], i["category"]), []).append(i)
        add("| Category | Source | Findings | Highest severity | Rules |")
        add("|---|---|---:|---|---|")
        for (src, cat), its in sorted(cats.items(), key=lambda kv: (-max(RANK[i["severity"]] for i in kv[1]),
                                                                    -len(kv[1]), kv[0])):
            top = max(its, key=lambda i: RANK[i["severity"]])["severity"]
            rules = ", ".join(sorted({f"`{i['rule']}`" for i in its}))
            add(f"| {md(cat)} | {src} | {len(its)} | {top} | {rules} |")
    else:
        add("_No findings._")
    add("")

    # ---- top 5 ----------------------------------------------------------------
    add(f"## Top {TOP_N} to review")
    add("")
    add("Ordering: severity desc, then file path asc (ties: line, rule).")
    add("")
    if items:
        add("| # | Severity | Location | Rule | Blocking | Why it matters | Suggested fix |")
        add("|---:|---|---|---|---|---|---|")
        for n, i in enumerate(items[:TOP_N], 1):
            rule = f"`{md(i['rule'])}`" + (f"<br>{md(i['ref'])}" if i["ref"] and i["source"] == "sast" else "")
            add(f"| {n} | {i['severity']} | `{md(i['path'])}:{i['line']}` | {rule} | "
                f"{'yes' if i['blocking'] else 'no'} | {md(i['message'])} | {md(i['fix']) or '-'} |")
        if len(items) > TOP_N:
            add("")
            add(f"{len(items) - TOP_N} more finding(s) in the full list below.")
    else:
        add("_Nothing to review._")
    add("")

    # ---- suppressed vs new (Task 1) -------------------------------------------
    add("## Secrets: suppressed vs new")
    add("")
    if secrets_summary is None:
        add("_Not applicable: no Task 1 output (`artifacts/secrets.summary.json`) found._")
    else:
        c = secrets_summary.get("counts", {})
        add("| Status | Count | Meaning |")
        add("|---|---:|---|")
        add(f"| New | {c.get('new', 0)} | Not in `baseline.json`: fails the secrets scan |")
        add(f"| Suppressed | {c.get('suppressed_by_baseline', 0)} | Accepted in `baseline.json`, with a reason |")
        add(f"| Total found | {c.get('raw', 0)} | Everything gitleaks reported after config tuning |")
        add("")
        sup = secrets_summary.get("suppressed", [])
        if sup:
            add("Suppressed findings and why:")
            add("")
            add("| Location | Rule | Fingerprint | Reason |")
            add("|---|---|---|---|")
            for s in sorted(sup, key=lambda s: (s.get("file", ""), s.get("start_line", 0), s.get("fingerprint", ""))):
                add(f"| `{md(s.get('file'))}:{s.get('start_line')}` | `{md(s.get('rule_id'))}` | "
                    f"`{md(s.get('fingerprint'))}` | {md(s.get('reason'))} |")
            add("")
        health = secrets_summary.get("baseline_health", {})
        notes = [(k, health.get(k, [])) for k in ("expired_entries", "stale_entries", "unreviewed_entries")]
        if any(v for _, v in notes):
            add("Baseline health:")
            add("")
            labels = {"expired_entries": "Expired (no longer suppress; renew or fix)",
                      "stale_entries": "Stale (secret gone; delete the entry)",
                      "unreviewed_entries": "Unreviewed (write a reason before merging)"}
            for k, v in notes:
                if v:
                    add(f"- {labels[k]}: " + ", ".join(f"`{x}`" for x in sorted(v)))
        else:
            add("Baseline health: no expired, stale or unreviewed entries.")
    add("")

    # ---- full list ------------------------------------------------------------
    if len(items) > TOP_N:
        add("## All findings")
        add("")
        add("| # | Severity | Source | Location | Rule | Blocking |")
        add("|---:|---|---|---|---|---|")
        for n, i in enumerate(items, 1):
            add(f"| {n} | {i['severity']} | {i['source']} | `{md(i['path'])}:{i['line']}` | "
                f"`{md(i['rule'])}` | {'yes' if i['blocking'] else 'no'} |")
        add("")
    return "\n".join(L)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Build artifacts/triage.md from scan outputs.",
                                 epilog="Exit codes: 0 report written, 2 no usable input.")
    ap.add_argument("--artifacts", default=str(ROOT / "artifacts"))
    ap.add_argument("--output", default=None, help="default: <artifacts>/triage.md")
    args = ap.parse_args(argv)
    art = Path(args.artifacts)
    out = Path(args.output) if args.output else art / "triage.md"

    try:
        s_items, s_summary, s_used = load_secrets(art)
        a_items, a_meta, a_used = load_sast(art)
    except TriageError as exc:
        log(f"ERROR: {exc}")
        return 2
    inputs = sorted(s_used + a_used, key=lambda p: p.name)
    if not inputs:
        log(f"ERROR: no scan output in {art}/ - run `./run.sh secrets` and/or `./run.sh sast` first")
        return 2

    text = render(s_items + a_items, s_summary, a_meta, inputs, art)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(".md.tmp")
    tmp.write_text(text, encoding="utf-8", newline="\n")
    tmp.replace(out)
    log(f"wrote {out} from {', '.join(p.name for p in inputs)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

