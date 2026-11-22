import argparse
import json
from scanner import find_tf_files
from parser import parse_file
from checks import run_checks

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

def scan_folder(folder):
    findings = []
    for path in find_tf_files(folder):
        for resource in parse_file(path):
            findings += run_checks(resource)
    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["file"], f["line"]))
    return findings

def format_report(findings):
    lines = ["IaCScan Report", "=" * 60]
    for f in findings:
        lines.append("[%s] %s:%d  %s" % (f["severity"], f["file"], f["line"], f["resource"]))
        lines.append("    Issue: " + f["issue"])
        lines.append("    Fix:   " + f["fix"])
        lines.append("")
    lines.append("=" * 60)
    lines.append("Total findings: %d" % len(findings))
    for sev in SEVERITY_ORDER:
        count = sum(1 for f in findings if f["severity"] == sev)
        if count:
            lines.append("  %s: %d" % (sev, count))
    return "\n".join(lines)

def format_json(findings):
    summary = {}
    for sev in SEVERITY_ORDER:
        count = sum(1 for f in findings if f["severity"] == sev)
        if count:
            summary[sev] = count
    return json.dumps({"total": len(findings), "summary": summary,
                       "findings": findings}, indent=2)

def main():
    ap = argparse.ArgumentParser(description="IaCScan - IaC security scanner")
    ap.add_argument("folder", help="Folder to scan")
    ap.add_argument("-o", "--output", default="report.txt", help="Report file")
    ap.add_argument("--format", choices=["text", "json"], default="text",
                    help="Report format (default: text)")
    args = ap.parse_args()

    findings = scan_folder(args.folder)
    if args.format == "json":
        report = format_json(findings)
    else:
        report = format_report(findings)
    print(report)
    with open(args.output, "w") as f:
        f.write(report + "\n")
    print("\nReport saved to " + args.output)

if __name__ == "__main__":
    main()
