# student_name   : Jeeva J P
# roll_number    : 727823TUCY018
# project_name   : SSH Brute-Force Detector
# date           : 2026-03-28

"""
SSH Brute-Force Detector
========================
Detects SSH brute-force attacks by analysing authentication log files.
Supports live /var/log/auth.log parsing, synthetic log generation for
testing, threshold-based alerting, and JSON/CSV report export.

Usage (standalone):
    python tool_main.py --log auth.log --threshold 5 --window 60
    python tool_main.py --demo                  # generates synthetic logs
    python tool_main.py --export results.json   # JSON export
"""

import re
import os
import sys
import json
import csv
import argparse
import datetime
from collections import defaultdict

# ── Roll-number / timestamp banner ────────────────────────────────────────────
ROLL_NUMBER = "727823TUCY018"
STUDENT_NAME = "Jeeva J P"
PROJECT_NAME = "SSH Brute-Force Detector"

def print_banner():
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("=" * 60)
    print(f"  Project  : {PROJECT_NAME}")
    print(f"  Student  : {STUDENT_NAME}")
    print(f"  Roll No  : {ROLL_NUMBER}")
    print(f"  Run Time : {ts}")
    print("=" * 60)

# ── Regex patterns ─────────────────────────────────────────────────────────────
FAILED_AUTH_PATTERN = re.compile(
    r"(\w{3}\s+\d+\s[\d:]+).*?Failed password for (?:invalid user )?(\S+) from ([\d.]+)"
)
INVALID_USER_PATTERN = re.compile(
    r"(\w{3}\s+\d+\s[\d:]+).*?Invalid user (\S+) from ([\d.]+)"
)
ACCEPTED_PATTERN = re.compile(
    r"(\w{3}\s+\d+\s[\d:]+).*?Accepted password for (\S+) from ([\d.]+)"
)
DISCONNECTED_PATTERN = re.compile(
    r"(\w{3}\s+\d+\s[\d:]+).*?Disconnected from ([\d.]+)"
)

# ── Synthetic log generator ────────────────────────────────────────────────────
DEMO_LOGS = [
    # Test Case 1: Single attacker, multiple rapid failures → brute-force
    "Mar 28 10:00:01 server sshd[1001]: Failed password for root from 192.168.1.100 port 22 ssh2",
    "Mar 28 10:00:03 server sshd[1002]: Failed password for root from 192.168.1.100 port 22 ssh2",
    "Mar 28 10:00:05 server sshd[1003]: Failed password for root from 192.168.1.100 port 22 ssh2",
    "Mar 28 10:00:07 server sshd[1004]: Failed password for root from 192.168.1.100 port 22 ssh2",
    "Mar 28 10:00:09 server sshd[1005]: Failed password for root from 192.168.1.100 port 22 ssh2",
    "Mar 28 10:00:11 server sshd[1006]: Failed password for root from 192.168.1.100 port 22 ssh2",
    # Test Case 2: Invalid user enumeration from different IP
    "Mar 28 10:01:00 server sshd[1010]: Invalid user admin from 10.0.0.55 port 50001",
    "Mar 28 10:01:02 server sshd[1011]: Invalid user test from 10.0.0.55 port 50002",
    "Mar 28 10:01:04 server sshd[1012]: Invalid user oracle from 10.0.0.55 port 50003",
    "Mar 28 10:01:06 server sshd[1013]: Invalid user postgres from 10.0.0.55 port 50004",
    "Mar 28 10:01:08 server sshd[1014]: Invalid user guest from 10.0.0.55 port 50005",
    "Mar 28 10:01:10 server sshd[1015]: Invalid user ftp from 10.0.0.55 port 50006",
    "Mar 28 10:01:12 server sshd[1016]: Invalid user ubuntu from 10.0.0.55 port 50007",
    # Test Case 3: Low-frequency failures (NOT a brute-force — below threshold)
    "Mar 28 11:00:00 server sshd[2000]: Failed password for alice from 172.16.0.5 port 4444 ssh2",
    "Mar 28 11:05:00 server sshd[2001]: Failed password for alice from 172.16.0.5 port 4444 ssh2",
    # Legitimate login
    "Mar 28 11:10:00 server sshd[3000]: Accepted password for alice from 172.16.0.5 port 4444 ssh2",
    # Distributed attack — 3 IPs each below individual threshold but combined suspicious
    "Mar 28 12:00:00 server sshd[4001]: Failed password for root from 203.0.113.10 port 60001 ssh2",
    "Mar 28 12:00:02 server sshd[4002]: Failed password for root from 203.0.113.11 port 60002 ssh2",
    "Mar 28 12:00:04 server sshd[4003]: Failed password for root from 203.0.113.12 port 60003 ssh2",
    "Mar 28 12:00:06 server sshd[4004]: Failed password for root from 203.0.113.10 port 60004 ssh2",
    "Mar 28 12:00:08 server sshd[4005]: Failed password for root from 203.0.113.11 port 60005 ssh2",
    "Mar 28 12:00:10 server sshd[4006]: Failed password for root from 203.0.113.12 port 60006 ssh2",
]

def generate_demo_log(path: str) -> str:
    with open(path, "w") as f:
        f.write("\n".join(DEMO_LOGS) + "\n")
    print(f"[+] Demo log written to: {path}")
    return path

# ── Core analyser ──────────────────────────────────────────────────────────────
class SSHBruteForceDetector:
    def __init__(self, threshold: int = 5, window_seconds: int = 60):
        self.threshold = threshold
        self.window = window_seconds
        self.failed_attempts: dict = defaultdict(list)     # ip → [timestamps]
        self.invalid_users: dict  = defaultdict(list)
        self.accepted: list       = []
        self.alerts: list         = []
        self.raw_events: list     = []

    def _parse_timestamp(self, ts_str: str) -> datetime.datetime:
        """Parse syslog-style timestamp (current year assumed)."""
        year = datetime.datetime.now().year
        try:
            return datetime.datetime.strptime(f"{year} {ts_str.strip()}", "%Y %b %d %H:%M:%S")
        except ValueError:
            return datetime.datetime.now()

    def parse_log(self, log_path: str) -> None:
        if not os.path.isfile(log_path):
            print(f"[!] Log file not found: {log_path}")
            sys.exit(1)
        with open(log_path, "r", errors="replace") as fh:
            for line in fh:
                line = line.rstrip()
                m = FAILED_AUTH_PATTERN.search(line)
                if m:
                    ts = self._parse_timestamp(m.group(1))
                    user, ip = m.group(2), m.group(3)
                    self.failed_attempts[ip].append(ts)
                    self.raw_events.append({"type": "FAILED", "ip": ip, "user": user, "ts": str(ts)})
                    continue
                m = INVALID_USER_PATTERN.search(line)
                if m:
                    ts = self._parse_timestamp(m.group(1))
                    user, ip = m.group(2), m.group(3)
                    self.invalid_users[ip].append((ts, user))
                    self.raw_events.append({"type": "INVALID_USER", "ip": ip, "user": user, "ts": str(ts)})
                    continue
                m = ACCEPTED_PATTERN.search(line)
                if m:
                    ts = self._parse_timestamp(m.group(1))
                    user, ip = m.group(2), m.group(3)
                    self.accepted.append({"ip": ip, "user": user, "ts": str(ts)})

    def detect(self) -> list:
        """Apply sliding-window brute-force detection."""
        self.alerts = []

        # --- Failed-password brute-force ---
        for ip, timestamps in self.failed_attempts.items():
            timestamps.sort()
            for i in range(len(timestamps)):
                window_start = timestamps[i]
                window_end   = window_start + datetime.timedelta(seconds=self.window)
                count = sum(1 for t in timestamps if window_start <= t <= window_end)
                if count >= self.threshold:
                    self.alerts.append({
                        "alert_type"  : "BRUTE_FORCE_FAILED_PASSWORD",
                        "ip"          : ip,
                        "count"       : count,
                        "window_secs" : self.window,
                        "first_seen"  : str(timestamps[i]),
                        "severity"    : "HIGH" if count >= self.threshold * 2 else "MEDIUM",
                    })
                    break  # one alert per IP

        # --- Invalid-user enumeration ---
        for ip, entries in self.invalid_users.items():
            unique_users = set(u for _, u in entries)
            if len(entries) >= self.threshold:
                self.alerts.append({
                    "alert_type"    : "USER_ENUMERATION",
                    "ip"            : ip,
                    "attempt_count" : len(entries),
                    "unique_users"  : list(unique_users),
                    "first_seen"    : str(min(ts for ts, _ in entries)),
                    "severity"      : "HIGH",
                })

        return self.alerts

    def summary(self) -> dict:
        return {
            "roll_number"         : ROLL_NUMBER,
            "timestamp"           : datetime.datetime.now().isoformat(),
            "total_events"        : len(self.raw_events),
            "unique_attacker_ips" : len(self.failed_attempts) + len(self.invalid_users),
            "alerts_raised"       : len(self.alerts),
            "legitimate_logins"   : len(self.accepted),
        }

    def export_json(self, path: str) -> None:
        data = {"summary": self.summary(), "alerts": self.alerts, "events": self.raw_events}
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"[+] JSON report saved: {path}")

    def export_csv(self, path: str) -> None:
        if not self.alerts:
            print("[!] No alerts to export.")
            return
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=self.alerts[0].keys())
            writer.writeheader()
            writer.writerows(self.alerts)
        print(f"[+] CSV report saved: {path}")

    def print_report(self) -> None:
        s = self.summary()
        print(f"\n{'─'*60}")
        print(f"  DETECTION SUMMARY")
        print(f"{'─'*60}")
        print(f"  Total log events parsed  : {s['total_events']}")
        print(f"  Unique attacker IPs      : {s['unique_attacker_ips']}")
        print(f"  Legitimate logins seen   : {s['legitimate_logins']}")
        print(f"  Alerts raised            : {s['alerts_raised']}")
        print(f"{'─'*60}")
        if not self.alerts:
            print("  [✓] No brute-force activity detected.")
        else:
            print(f"  [!] {len(self.alerts)} ALERT(S) DETECTED:\n")
            for i, a in enumerate(self.alerts, 1):
                print(f"  Alert #{i}")
                for k, v in a.items():
                    print(f"    {k:<18}: {v}")
                print()
        print(f"{'─'*60}\n")


# ── CLI entry-point ─────────────────────────────────────────────────────────────
def main():
    print_banner()

    parser = argparse.ArgumentParser(description="SSH Brute-Force Detector")
    parser.add_argument("--log",       default=None,          help="Path to auth.log (or custom log file)")
    parser.add_argument("--threshold", type=int, default=5,   help="Failed attempts threshold (default: 5)")
    parser.add_argument("--window",    type=int, default=60,  help="Detection window in seconds (default: 60)")
    parser.add_argument("--demo",      action="store_true",   help="Run with synthetic demo log")
    parser.add_argument("--export",    default=None,          help="Export JSON results to this path")
    parser.add_argument("--csv",       default=None,          help="Export CSV alerts to this path")
    args = parser.parse_args()

    log_path = args.log

    if args.demo or log_path is None:
        log_path = "/tmp/ssh_demo_auth.log"
        generate_demo_log(log_path)

    detector = SSHBruteForceDetector(threshold=args.threshold, window_seconds=args.window)
    print(f"[+] Parsing log file : {log_path}")
    print(f"[+] Threshold        : {args.threshold} attempts / {args.window}s window")
    detector.parse_log(log_path)

    print(f"[+] Running detection engine ...")
    detector.detect()
    detector.print_report()

    if args.export:
        detector.export_json(args.export)
    if args.csv:
        detector.export_csv(args.csv)

    print(f"[✓] Roll No: {ROLL_NUMBER} | Completed: {datetime.datetime.now()}")


if __name__ == "__main__":
    main()
