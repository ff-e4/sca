
import argparse
import json
import csv
import re
import sys
from pathlib import Path
from typing import Dict, List, Iterable
import report_writer
import rules

run_rules = rules.ruleset("grails")

GRAILS_EXTS = {".groovy", ".gsp", ".gradle", ".gs", ".java", ".jsp"}


def compile_rules() -> None:
    for rule in run_rules:
        for pat in rule["patterns"]:
            pat["_compiled"] = re.compile(pat["regex"], re.M)


def find_files(root: Path) -> Iterable[Path]:
    for p in root.rglob("*"):
        if p.suffix.lower() in GRAILS_EXTS and p.is_file():
            yield p


def context_snippet(lines: List[str], idx: int) -> str:
    snip = []
    for rel in (-1, 0, 1):
        j = idx + rel
        if 0 <= j < len(lines):
            snip.append(f"{j+1:>4}| {lines[j].rstrip()[:160]}")
    return "\n".join(snip)


def analyse_file(path: Path) -> List[Dict]:
    findings: List[Dict] = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception as exc:
        return [{
            "file": str(path),
            "line": 0,
            "rule": "I/O‑ERROR",
            "severity": "high",
            "match": "",
            "reason": f"Cannot read file: {exc}",
            "recommendation": "Fix file encoding/permissions and re‑run.",
            "context": ""
        }]

    lines = text.splitlines()

    for i, line in enumerate(lines):
        for rule in run_rules:
            for pat in rule["patterns"]:
                m = pat["_compiled"].search(line)
                if m:
                    findings.append({
                        "file": str(path.relative_to(Path.cwd())),
                        "line": i + 1,
                        "rule": f"{rule['id']}: {rule['name']}",
                        "severity": pat["severity"],
                        "match": m.group(0).strip()[:120],
                        "reason": pat["reason"],
                        "recommendation": pat["recommendation"],
                        "context": context_snippet(lines, i),
                    })
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Static analyzer for Grails/Groovy code (OWASP Top 10)"
    )
    parser.add_argument(
        "directory",
        nargs="?",
        default=".",
        help="Project root to scan (default: current directory)",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="findings.csv",
        help="CSV file to write (default: findings.csv)",
    )
    parser.add_argument(
        "--html-report",
        metavar="FILE",
        help="Write results as HTML report to this file",
    )

    args = parser.parse_args()
    root = Path(args.directory).expanduser().resolve()

    if not root.exists():
        sys.exit(f"[!] Directory not found: {root}")

    compile_rules()

    all_findings: List[Dict] = []
    grails_files = list(find_files(root))
    for fp in grails_files:
        all_findings.extend(analyse_file(fp))

    # JSON report to stdout
    print(json.dumps(all_findings, indent=2))

    # --------- write CSV ----------
    fieldnames = [
        "file",
        "line",
        "rule",
        "severity",
        "match",
        "reason",
        "recommendation",
        "context",
    ]
    try:
        with open(args.output, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(all_findings)
    except Exception as e:
        sys.exit(f"[!] Failed to write CSV: {e}")

    # Summary to stderr
    summary: Dict[str, int] = {}
    for f in all_findings:
        summary[f["rule"]] = summary.get(f["rule"], 0) + 1

    sys.stderr.write("\n=== Summary ===\n")
    for rule, count in sorted(summary.items(), key=lambda x: (-x[1], x[0])):
        sys.stderr.write(f"{rule:<40} {count}\n")
    sys.stderr.write(
        f"Scanned {len(grails_files)} file(s) — total findings: {len(all_findings)}\n"
    )
    if args.html_report:
        report_writer.write_html_report(all_findings, args.html_report, "grails")
        sys.stderr.write(f"HTML report written to {args.html_report}\n")


if __name__ == "__main__":
    main()
