# Jeeva J P, 727823TUCY018
# student_name   : Jeeva J P
# roll_number    : 727823TUCY018
# project_name   : SSH Brute-Force Detector
# date           : 2026-03-28

"""
analyze_results.py  —  Pipeline Stage 3
=========================================
Reads the combined JSON output from Stage 2, produces a
statistical summary, and generates an HTML report.
Prints roll number + timestamp to stdout on every run.
"""

import os
import sys
import json
import datetime
from collections import Counter

ROLL_NUMBER  = "727823TUCY018"
STUDENT_NAME = "Jeeva J P"

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "helper_modules"))
from alerting import build_html_report, format_alert, print_summary_table


def analyse(results: list) -> dict:
    all_alerts      = []
    total_events    = 0
    legit_logins    = 0

    for r in results:
        all_alerts  += r.get("alerts", [])
        s            = r.get("summary", {})
        total_events += s.get("total_events", 0)
        legit_logins += s.get("legitimate_logins", 0)

    severity_counts = Counter(a.get("severity", "MEDIUM") for a in all_alerts)
    type_counts     = Counter(a.get("alert_type", "UNKNOWN") for a in all_alerts)
    attacker_ips    = list({a.get("ip") for a in all_alerts if a.get("ip")})

    return {
        "roll_number"      : ROLL_NUMBER,
        "timestamp"        : datetime.datetime.now().isoformat(),
        "test_cases_run"   : len(results),
        "total_log_events" : total_events,
        "total_alerts"     : len(all_alerts),
        "legitimate_logins": legit_logins,
        "severity_counts"  : dict(severity_counts),
        "type_counts"      : dict(type_counts),
        "unique_attacker_ips": attacker_ips,
        "all_alerts"       : all_alerts,
    }


def print_analysis(analysis: dict) -> None:
    print(f"\n{'═'*60}")
    print(f"  ANALYSIS REPORT")
    print(f"  Roll No  : {analysis['roll_number']}")
    print(f"  Time     : {analysis['timestamp']}")
    print(f"{'═'*60}")
    print(f"  Test cases run      : {analysis['test_cases_run']}")
    print(f"  Total log events    : {analysis['total_log_events']}")
    print(f"  Total alerts raised : {analysis['total_alerts']}")
    print(f"  Legitimate logins   : {analysis['legitimate_logins']}")
    print(f"\n  Severity Breakdown:")
    for sev, count in analysis["severity_counts"].items():
        bar = "█" * count
        print(f"    {sev:<8} {bar} ({count})")
    print(f"\n  Alert Type Breakdown:")
    for atype, count in analysis["type_counts"].items():
        print(f"    {atype:<35} : {count}")
    print(f"\n  Attacker IPs identified:")
    for ip in analysis["unique_attacker_ips"]:
        print(f"    • {ip}")
    print(f"{'═'*60}\n")


def main():
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("=" * 60)
    print(f"  PIPELINE STAGE 3 — Analyse Results")
    print(f"  Roll No  : {ROLL_NUMBER}")
    print(f"  Student  : {STUDENT_NAME}")
    print(f"  Timestamp: {ts}")
    print("=" * 60)

    combined_path = "outputs/exports/all_results.json"
    if not os.path.isfile(combined_path):
        print(f"[!] Results file not found: {combined_path}")
        print("[!] Run run_tool.py first (Stage 2).")
        sys.exit(1)

    with open(combined_path) as f:
        data = json.load(f)

    results  = data.get("results", [])
    analysis = analyse(results)

    print_analysis(analysis)

    # Save analysis JSON
    analysis_out = "outputs/reports/analysis.json"
    os.makedirs("outputs/reports", exist_ok=True)
    with open(analysis_out, "w") as f:
        json.dump(analysis, f, indent=2)
    print(f"[+] Analysis JSON saved: {analysis_out}")

    # Build HTML report
    summary_for_html = {
        "total_events"       : analysis["total_log_events"],
        "alerts_raised"      : analysis["total_alerts"],
        "unique_attacker_ips": len(analysis["unique_attacker_ips"]),
        "legitimate_logins"  : analysis["legitimate_logins"],
    }
    html_path = "outputs/reports/report.html"
    build_html_report(summary_for_html, analysis["all_alerts"], html_path)
    print(f"[+] HTML report saved : {html_path}")

    print(f"\n[✓] Roll No: {ROLL_NUMBER} | Stage 3 completed @ {datetime.datetime.now()}")

if __name__ == "__main__":
    main()
