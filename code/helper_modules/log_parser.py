# student_name   : Jeeva J P
# roll_number    : 727823TUCY018
# project_name   : SSH Brute-Force Detector
# date           : 2026-03-28

"""
helper_modules/log_parser.py
─────────────────────────────
Utility functions for generating synthetic test logs and
reading real auth.log files for the SSH Brute-Force Detector.
"""

import os
import datetime
import random

ROLL_NUMBER = "727823TUCY018"

# ── Synthetic log templates ────────────────────────────────────────────────────
def generate_test_case_1(path: str) -> str:
    """
    Test Case 1: Classic brute-force — one IP hammers root with many rapid failures.
    Expected: HIGH severity BRUTE_FORCE_FAILED_PASSWORD alert for 192.168.1.100
    """
    base = datetime.datetime(2026, 3, 28, 10, 0, 0)
    lines = []
    for i in range(12):
        ts = (base + datetime.timedelta(seconds=i * 2)).strftime("%b %d %H:%M:%S")
        lines.append(
            f"{ts} metasploitable sshd[{1000+i}]: Failed password for root "
            f"from 192.168.1.100 port {50000+i} ssh2"
        )
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    return path


def generate_test_case_2(path: str) -> str:
    """
    Test Case 2: User-enumeration scan — attacker tries many different usernames.
    Expected: USER_ENUMERATION alert for 10.0.0.55
    """
    users = ["admin", "root", "test", "oracle", "postgres", "ftp", "guest",
             "ubuntu", "pi", "nagios", "hadoop"]
    base  = datetime.datetime(2026, 3, 28, 11, 0, 0)
    lines = []
    for i, user in enumerate(users):
        ts = (base + datetime.timedelta(seconds=i * 3)).strftime("%b %d %H:%M:%S")
        lines.append(
            f"{ts} metasploitable sshd[{2000+i}]: Invalid user {user} "
            f"from 10.0.0.55 port {60000+i}"
        )
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    return path


def generate_test_case_3(path: str) -> str:
    """
    Test Case 3: Low-frequency failures (benign mistype) — should NOT trigger alert.
    Expected: No alerts (failures spread over >60s window, below threshold).
    """
    base  = datetime.datetime(2026, 3, 28, 14, 0, 0)
    lines = [
        (base + datetime.timedelta(minutes=0)).strftime("%b %d %H:%M:%S")
        + " metasploitable sshd[3001]: Failed password for alice from 172.16.0.20 port 4444 ssh2",

        (base + datetime.timedelta(minutes=5)).strftime("%b %d %H:%M:%S")
        + " metasploitable sshd[3002]: Failed password for alice from 172.16.0.20 port 4445 ssh2",

        (base + datetime.timedelta(minutes=11)).strftime("%b %d %H:%M:%S")
        + " metasploitable sshd[3003]: Accepted password for alice from 172.16.0.20 port 4446 ssh2",
    ]
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    return path


def generate_test_case_4(path: str) -> str:
    """
    Test Case 4: Distributed attack — several IPs each individually just below threshold
    but collectively targeting the same service window.
    Expected: Individual alerts may be MEDIUM; total event count high.
    """
    ips   = ["203.0.113.10", "203.0.113.11", "203.0.113.12", "203.0.113.13"]
    base  = datetime.datetime(2026, 3, 28, 15, 0, 0)
    lines = []
    pid   = 5000
    for cycle in range(8):
        for ip in ips:
            ts = (base + datetime.timedelta(seconds=cycle * 5 + ips.index(ip))).strftime("%b %d %H:%M:%S")
            lines.append(
                f"{ts} metasploitable sshd[{pid}]: Failed password for root "
                f"from {ip} port {40000+pid} ssh2"
            )
            pid += 1
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    return path


ALL_GENERATORS = {
    "tc1_brute_force":       generate_test_case_1,
    "tc2_user_enum":         generate_test_case_2,
    "tc3_benign_failures":   generate_test_case_3,
    "tc4_distributed":       generate_test_case_4,
}


def load_real_auth_log(path: str = "/var/log/auth.log") -> str:
    """Return path to auth.log if readable, else raise."""
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Auth log not found: {path}")
    if not os.access(path, os.R_OK):
        raise PermissionError(f"Cannot read: {path} — try sudo")
    return path
