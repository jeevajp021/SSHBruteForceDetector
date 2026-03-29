# student_name   : Jeeva J P
# roll_number    : 727823TUCY018
# project_name   : SSH Brute-Force Detector
# date           : 2026-03-28

"""
helper_modules/alerting.py
───────────────────────────
Alert formatting, severity classification, and reporting utilities
for the SSH Brute-Force Detector pipeline.
"""

import datetime
import json

ROLL_NUMBER = "727823TUCY018"


SEVERITY_COLORS = {
    "HIGH":   "\033[91m",   # red
    "MEDIUM": "\033[93m",   # yellow
    "LOW":    "\033[92m",   # green
    "RESET":  "\033[0m",
}


def colorise(text: str, severity: str) -> str:
    c = SEVERITY_COLORS.get(severity.upper(), "")
    r = SEVERITY_COLORS["RESET"]
    return f"{c}{text}{r}"


def format_alert(alert: dict, index: int = 1) -> str:
    sev = alert.get("severity", "MEDIUM")
    lines = [
        colorise(f"  ┌─ Alert #{index}  [{sev}]  ─────────────────────────────", sev),
    ]
    for k, v in alert.items():
        if isinstance(v, list):
            v = ", ".join(str(x) for x in v)
        lines.append(f"  │  {k:<22}: {v}")
    lines.append("  └" + "─" * 52)
    return "\n".join(lines)


def build_html_report(summary: dict, alerts: list, output_path: str) -> str:
    """Generate a minimal standalone HTML report."""
    rows = ""
    for a in alerts:
        sev   = a.get("severity", "MEDIUM")
        color = "#d32f2f" if sev == "HIGH" else "#f57c00"
        rows += (
            f"<tr>"
            f"<td>{a.get('alert_type','')}</td>"
            f"<td>{a.get('ip','')}</td>"
            f"<td style='color:{color};font-weight:bold'>{sev}</td>"
            f"<td>{a.get('count', a.get('attempt_count','N/A'))}</td>"
            f"<td>{a.get('first_seen','')}</td>"
            f"</tr>\n"
        )

    html = f"""<!DOCTYPE html>
<html lang='en'>
<head><meta charset='utf-8'>
<title>SSH Brute-Force Detector Report</title>
<style>
  body{{font-family:Arial,sans-serif;margin:40px;background:#f5f5f5}}
  h1{{color:#1565c0}} h2{{color:#333}}
  table{{border-collapse:collapse;width:100%;background:#fff;box-shadow:0 1px 4px #ccc}}
  th{{background:#1565c0;color:#fff;padding:10px;text-align:left}}
  td{{padding:9px;border-bottom:1px solid #eee}}
  tr:hover{{background:#f0f4ff}}
  .badge{{display:inline-block;padding:3px 10px;border-radius:12px;font-size:12px}}
  .kv{{display:flex;gap:30px;flex-wrap:wrap;margin-bottom:20px}}
  .kv div{{background:#fff;padding:14px 20px;border-radius:8px;
            box-shadow:0 1px 3px #ccc;min-width:150px}}
  .kv .val{{font-size:24px;font-weight:bold;color:#1565c0}}
</style>
</head>
<body>
<h1>🔐 SSH Brute-Force Detector</h1>
<p><b>Student:</b> Jeeva J P &nbsp;|&nbsp; <b>Roll No:</b> {ROLL_NUMBER} &nbsp;|&nbsp;
   <b>Generated:</b> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<div class='kv'>
  <div><div>Total Events</div><div class='val'>{summary.get('total_events',0)}</div></div>
  <div><div>Alerts Raised</div><div class='val'>{summary.get('alerts_raised',0)}</div></div>
  <div><div>Attacker IPs</div><div class='val'>{summary.get('unique_attacker_ips',0)}</div></div>
  <div><div>Legit Logins</div><div class='val'>{summary.get('legitimate_logins',0)}</div></div>
</div>
<h2>Alerts</h2>
<table>
<tr><th>Type</th><th>Attacker IP</th><th>Severity</th><th>Count</th><th>First Seen</th></tr>
{rows if rows else "<tr><td colspan='5'>No alerts detected.</td></tr>"}
</table>
</body></html>"""

    with open(output_path, "w") as f:
        f.write(html)
    return output_path


def print_summary_table(summary: dict) -> None:
    print(f"\n  Roll No  : {summary.get('roll_number','')}")
    print(f"  Time     : {summary.get('timestamp','')}")
    print(f"  Events   : {summary.get('total_events',0)}")
    print(f"  Alerts   : {summary.get('alerts_raised',0)}")
    print(f"  Legit    : {summary.get('legitimate_logins',0)}")
