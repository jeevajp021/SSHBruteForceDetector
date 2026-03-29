# 🔐 SSH Brute-Force Detector

| Field        | Value                          |
|--------------|-------------------------------|
| **Student**  | Jeeva J P                     |
| **Roll No**  | 727823TUCY018                 |
| **Category** | Network Security / Log Analysis |
| **Date**     | 2026-03-28                    |

---

## Project Overview

The **SSH Brute-Force Detector** analyses Linux authentication log files (`/var/log/auth.log`) to identify brute-force login attacks and user-enumeration scans in real time.  
It uses a **sliding-window algorithm** — if an IP generates ≥ N failed login attempts within a configurable time window (default 60 seconds), it raises a `BRUTE_FORCE_FAILED_PASSWORD` or `USER_ENUMERATION` alert with a severity rating.

---

## Lab Environment

| Component       | Details                        |
|-----------------|-------------------------------|
| Host OS         | Windows 11 / macOS             |
| Hypervisor      | VirtualBox 7.x                 |
| Attacker VM     | Kali Linux 2024.x              |
| Target VM       | Metasploitable2                |
| Network Mode    | Host-only Adapter              |
| Python Version  | 3.10+                          |

---

## Tool Architecture

```
tool_main.py                    ← Core detector (CLI)
code/
  setup_lab.py                  ← Pipeline Stage 1: env setup + log generation
  run_tool.py                   ← Pipeline Stage 2: run detector on all test cases
  analyze_results.py            ← Pipeline Stage 3: aggregate analysis + HTML report
  helper_modules/
    log_parser.py               ← Synthetic log generators (4 test cases)
    alerting.py                 ← Alert formatting + HTML report builder
pipeline_727823TUCY018.yml      ← Pipeline definition
notebooks/demo.ipynb            ← Jupyter demo notebook
requirements.txt
```

---

## Setup

```bash
# 1. Clone the repo
git clone https://github.com/<your-username>/hacker-skct-727823TUCY018
cd hacker-skct-727823TUCY018

# 2. Install dependencies
pip install -r requirements.txt

# 3. (Optional) Set up VirtualBox with Kali + Metasploitable2
#    - Ensure both VMs are on a Host-only network
#    - All testing MUST be done on systems you own or have written permission to test
```

---

## Usage

### Quick demo (synthetic logs, no VM needed)

```bash
python code/tool_main.py --demo
```

### Real auth.log (requires sudo on Linux)

```bash
sudo python code/tool_main.py --log /var/log/auth.log --threshold 5 --window 60
```

### Export results

```bash
python code/tool_main.py --demo --export results.json --csv alerts.csv
```

### Run full pipeline

```bash
cd code/
python setup_lab.py        # Stage 1 — setup + generate logs
python run_tool.py         # Stage 2 — run detector on all test cases
python analyze_results.py  # Stage 3 — analysis + HTML report
```

---

## Test Cases

| # | Description                | Input Log               | Expected Result                          |
|---|----------------------------|-------------------------|------------------------------------------|
| 1 | Classic brute-force        | tc1_brute_force.log     | HIGH alert — 192.168.1.100               |
| 2 | User enumeration scan      | tc2_user_enum.log       | HIGH alert — 10.0.0.55                   |
| 3 | Benign mistype (no alert)  | tc3_benign.log          | No alert — below threshold               |
| 4 | Distributed attack         | tc4_distributed.log     | MEDIUM alerts — 203.0.113.10–.13        |

---

## Ethical Notice

> All testing is performed exclusively on **VMs you own or have explicit written permission to test**.  
> Never run this tool against production systems or external networks without proper authorisation.  
> This project is for educational purposes only.

---

## Files in This Repository

| File / Folder                  | Purpose                                  |
|-------------------------------|------------------------------------------|
| `code/tool_main.py`           | Primary Python script                    |
| `code/helper_modules/`        | Supporting modules                       |
| `code/setup_lab.py`           | Pipeline Stage 1                         |
| `code/run_tool.py`            | Pipeline Stage 2                         |
| `code/analyze_results.py`     | Pipeline Stage 3                         |
| `pipeline_727823TUCY018.yml`  | Pipeline YAML definition                 |
| `notebooks/demo.ipynb`        | Jupyter notebook demo                    |
| `requirements.txt`            | Python dependencies                      |
| `report/report.pdf`           | 2-page project report                    |

---

*Roll No: 727823TUCY018 | GitHub: hacker-skct-727823TUCY018*
