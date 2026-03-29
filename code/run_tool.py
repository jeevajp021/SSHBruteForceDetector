# Jeeva J P, 727823TUCY018
# student_name   : Jeeva J P
# roll_number    : 727823TUCY018
# project_name   : SSH Brute-Force Detector
# date           : 2026-03-28

"""
run_tool.py  —  Pipeline Stage 2
==================================
Executes the SSH Brute-Force Detector against all 4 synthetic
test-case log files and saves JSON + CSV results per test case.
Prints roll number + timestamp to stdout on every run.
"""

import os
import sys
import json
import datetime

ROLL_NUMBER  = "727823TUCY018"
STUDENT_NAME = "Jeeva J P"

sys.path.insert(0, os.path.dirname(__file__))
from tool_main import SSHBruteForceDetector, print_banner

TEST_CASES = [
    {
        "name"      : "TC1 — Classic Brute Force",
        "log"       : "outputs/logs/tc1_brute_force.log",
        "threshold" : 5,
        "window"    : 60,
        "expected"  : "BRUTE_FORCE_FAILED_PASSWORD alert for 192.168.1.100",
    },
    {
        "name"      : "TC2 — User Enumeration",
        "log"       : "outputs/logs/tc2_user_enum.log",
        "threshold" : 5,
        "window"    : 120,
        "expected"  : "USER_ENUMERATION alert for 10.0.0.55",
    },
    {
        "name"      : "TC3 — Benign Mistype (No Alert)",
        "log"       : "outputs/logs/tc3_benign.log",
        "threshold" : 5,
        "window"    : 60,
        "expected"  : "No alerts (below threshold)",
    },
    {
        "name"      : "TC4 — Distributed Attack",
        "log"       : "outputs/logs/tc4_distributed.log",
        "threshold" : 5,
        "window"    : 60,
        "expected"  : "Multiple MEDIUM alerts across 4 IPs",
    },
]

def run_test_case(tc: dict, tc_index: int) -> dict:
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n{'━'*60}")
    print(f"  [{tc_index}] {tc['name']}")
    print(f"  Roll No  : {ROLL_NUMBER}  |  {ts}")
    print(f"  Expected : {tc['expected']}")
    print(f"{'━'*60}")

    detector = SSHBruteForceDetector(
        threshold      = tc["threshold"],
        window_seconds = tc["window"],
    )
    detector.parse_log(tc["log"])
    detector.detect()
    detector.print_report()

    # Save per-test-case JSON
    out_json = f"outputs/exports/tc{tc_index}_results.json"
    detector.export_json(out_json)
    out_csv  = f"outputs/exports/tc{tc_index}_alerts.csv"
    detector.export_csv(out_csv)

    return {
        "test_case"   : tc["name"],
        "log_file"    : tc["log"],
        "expected"    : tc["expected"],
        "alerts_found": len(detector.alerts),
        "alerts"      : detector.alerts,
        "summary"     : detector.summary(),
    }

def main():
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("=" * 60)
    print(f"  PIPELINE STAGE 2 — Run Tool")
    print(f"  Roll No  : {ROLL_NUMBER}")
    print(f"  Student  : {STUDENT_NAME}")
    print(f"  Timestamp: {ts}")
    print("=" * 60)

    os.makedirs("outputs/exports", exist_ok=True)

    all_results = []
    for i, tc in enumerate(TEST_CASES, 1):
        result = run_test_case(tc, i)
        all_results.append(result)

    # Save combined results
    combined_path = "outputs/exports/all_results.json"
    with open(combined_path, "w") as f:
        json.dump(
            {"roll_number": ROLL_NUMBER, "generated": ts, "results": all_results},
            f, indent=2
        )
    print(f"\n[✓] All results saved: {combined_path}")
    print(f"[✓] Roll No: {ROLL_NUMBER} | Stage 2 completed @ {datetime.datetime.now()}")

if __name__ == "__main__":
    main()
