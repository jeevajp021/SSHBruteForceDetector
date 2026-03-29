# Jeeva J P, 727823TUCY018
# student_name   : Jeeva J P
# roll_number    : 727823TUCY018
# project_name   : SSH Brute-Force Detector
# date           : 2026-03-28

"""
setup_lab.py  —  Pipeline Stage 1
===================================
Prepares the lab environment:
  • Checks Python version
  • Installs required packages
  • Creates output directories
  • Generates all 4 synthetic test-case log files
  • Prints roll number + timestamp to stdout
"""

import os
import sys
import subprocess
import datetime

ROLL_NUMBER  = "727823TUCY018"
STUDENT_NAME = "Jeeva J P"

def log(msg: str) -> None:
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}")

def main():
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("=" * 60)
    print(f"  PIPELINE STAGE 1 — Lab Setup")
    print(f"  Roll No  : {ROLL_NUMBER}")
    print(f"  Student  : {STUDENT_NAME}")
    print(f"  Timestamp: {ts}")
    print("=" * 60)

    # ── Python version check ──────────────────────────────────────
    log(f"Python version: {sys.version}")
    if sys.version_info < (3, 7):
        log("[ERROR] Python 3.7+ required.")
        sys.exit(1)

    # ── Install dependencies ──────────────────────────────────────
    packages = ["reportlab", "fpdf2"]
    for pkg in packages:
        log(f"Checking / installing: {pkg}")
        subprocess.run(
            [sys.executable, "-m", "pip", "install", pkg, "-q"],
            check=False
        )

    # ── Output directory setup ────────────────────────────────────
    dirs = [
        "outputs/logs",
        "outputs/reports",
        "outputs/exports",
    ]
    for d in dirs:
        os.makedirs(d, exist_ok=True)
        log(f"Directory ready: {d}")

    # ── Generate synthetic test logs ──────────────────────────────
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "helper_modules"))
    from log_parser import (
        generate_test_case_1, generate_test_case_2,
        generate_test_case_3, generate_test_case_4,
    )

    cases = {
        "outputs/logs/tc1_brute_force.log"    : generate_test_case_1,
        "outputs/logs/tc2_user_enum.log"       : generate_test_case_2,
        "outputs/logs/tc3_benign.log"          : generate_test_case_3,
        "outputs/logs/tc4_distributed.log"     : generate_test_case_4,
    }
    for path, gen_fn in cases.items():
        gen_fn(path)
        log(f"Generated: {path}")

    log(f"[✓] Setup complete — Roll No: {ROLL_NUMBER} @ {datetime.datetime.now()}")

if __name__ == "__main__":
    main()
