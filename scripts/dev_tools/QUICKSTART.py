#!/usr/bin/env python3
"""
PhantomPot Quick Start Guide

Run with: python run_project.py [option]
"""

import argparse
import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


QUICK_START = """
================================================================================
PHANTOMPOT QUICK START GUIDE
================================================================================

SETUP CHECKLIST
===============
[1] Dependencies installed (pip install -r requirements.txt)
[2] SSH host key generated
[3] ML models in /models/ directory
[4] Config file at /config/config.yaml

If any are missing, run: python run_project.py --setup


OPTION 1: START HONEYPOT (Minimal, 30 seconds)
==============================================

Terminal 1:
    python src/main.py

Output:
    [*] PhantomPot - multi-protocol honeypot starting ...
    [*] Press Ctrl-C to stop all listeners.

Honeypot listens on:
    - SSH:    localhost:2222
    - HTTP:   localhost:8888
    - FTP:    localhost:2121
    - Telnet: localhost:2323

Press Ctrl-C to stop.


OPTION 2: COMPLETE WORKFLOW (15-30 minutes)
===========================================

Terminal 1 - Start honeypot:
    python src/main.py
    
Terminal 2 - Run KPI Evaluation (after ~5 seconds):
    python scripts/evaluate_objective4.py --intensity medium --output eval.json
    
    Measures:
    - Attack Detection Rate (TP/FP), 
    - Protocol Coverage (4/4 protocols), 
    - Logging Accuracy, 
    - Response Time (ms)

Terminal 2 - Generate Reports:
    python scripts/generate_kpi_report.py --eval eval.json --format all
    
    Creates:
    - JSON report (machine-readable)
    - Markdown report (documentation)
    - HTML report (visual, professional)

Terminal 3 - View Dashboard:
    streamlit run dashboard/app.py
    
    Open http://localhost:8501
    Go to "KPI Metrics (Objective 4)" tab
    
    Shows:
    - Live KPI metrics
    - Attack detection performance
    - Protocol coverage
    - Response time analysis
    - Logging accuracy


OPTION 3: QUICK TEST (5 minutes)
===============================

Terminal 1:
    python src/main.py

Terminal 2:
    python scripts/evaluate_objective4.py --quick
    cat objective4_report.json


SIMULATING ATTACKS (For Manual Testing)
======================================

Terminal 1 (honeypot running):
    python src/main.py

Terminal 2 (simulate SSH attacks):
    python scripts/simulate_ssh_attacks.py

Terminal 2 (simulate multi-protocol):
    python scripts/simulate_multi_protocol.py

View results in Terminal 1's logs directory:
    cat logs/sessions.jsonl


PROJECT STRUCTURE
=================

PhantomPot-v2/
├── src/
│   ├── main.py                      [Entry point]
│   ├── core/
│   │   ├── kpi_metrics.py           [NEW: KPI collection]
│   │   ├── logger.py                [Session logging]
│   │   └── session_manager.py       [Session management]
│   ├── ssh/                         [SSH honeypot]
│   ├── http/                        [HTTP honeypot]
│   ├── ftp/                         [FTP honeypot]
│   ├── telnet/                      [Telnet honeypot]
│   └── ml/
│       └── predict.py               [ML anomaly detection]
│
├── scripts/
│   ├── evaluate_objective4.py       [NEW: KPI evaluation]
│   ├── generate_kpi_report.py       [NEW: Report generation]
│   ├── simulate_ssh_attacks.py      [Attack simulation]
│   └── simulate_multi_protocol.py   [Multi-protocol simulation]
│
├── dashboard/
│   └── app.py                       [Streamlit dashboard]
│
├── config/
│   ├── config.yaml                  [System configuration]
│   └── ssh_host_rsa.key             [SSH host key]
│
├── models/
│   ├── isolation_forest.pkl         [ML model]
│   └── scaler.pkl                   [Feature scaler]
│
└── logs/
    ├── sessions.jsonl               [Session logs]
    └── errors.log                   [Error logs]


FOUR KPIs MEASURED
==================

KPI 1: Attack Detection Rate
    - True Positive Rate (attacks correctly detected)
    - False Positive Rate (false alarms)
    - Precision, Recall, F1-Score
    - Target: TPR > 90%, FPR < 5%

KPI 2: Protocol Coverage
    - Number of active protocols (target: 4/4)
    - Sessions per protocol
    - Coverage completeness

KPI 3: Logging Accuracy
    - Sessions with 100% data logged
    - Command/login coverage
    - Data loss detection
    - Target: > 99.9% accuracy

KPI 4: System Response Time
    - Average latency (connection to log write)
    - P95, P99, Max latencies
    - Performance under load
    - Target: < 10ms average


TROUBLESHOOTING
===============

Problem: "ModuleNotFoundError: No module named 'joblib'"
Solution: pip install -r requirements.txt

Problem: "Connection refused" when running evaluation
Solution: Make sure honeypot is running in Terminal 1

Problem: "SSH Host Key not found"
Solution: python gen_ssh_key.py

Problem: "Permission denied" on logs directory
Solution: mkdir -p logs && chmod 755 logs

Problem: Dashboard doesn't load
Solution: streamlit run dashboard/app.py --logger.level=info


COMMANDS REFERENCE
==================

Start honeypot:
    python src/main.py

Quick evaluation (10 scenarios):
    python scripts/evaluate_objective4.py --quick

Medium evaluation (25 scenarios):
    python scripts/evaluate_objective4.py --intensity medium

Full evaluation (60+ scenarios):
    python scripts/evaluate_objective4.py --full

Generate reports:
    python scripts/generate_kpi_report.py --eval <report.json> --format all

Start dashboard:
    streamlit run dashboard/app.py

Simulate SSH attacks:
    python scripts/simulate_ssh_attacks.py

Simulate multi-protocol:
    python scripts/simulate_multi_protocol.py

Check setup:
    python run_project.py --check

Show this guide:
    python run_project.py --guide


EXPECTED OUTPUT
===============

Honeypot starting:
    [*] PhantomPot -- multi-protocol honeypot starting ...
    [*] Press Ctrl-C to stop all listeners.

Evaluation running:
    [Progress] 1/25
    [SCENARIO] SSH-ATK-001: SSH brute force with suspicious commands
    [+] SSH-ATK-001 completed
    ...
    [+] 25/25 scenarios completed

Dashboard loading:
    > Local URL: http://localhost:8501
    > Network URL: http://[IP]:8501


PERFORMANCE TARGETS
===================

Metric                          Target
------                          ------
Attack Detection Rate           >= 90%
False Positive Rate             <= 5%
Protocol Coverage               4/4
Logging Accuracy                >= 99.9%
Avg Response Time               <= 10ms
P95 Response Time               <= 50ms


NEXT STEPS
==========

1. Start honeypot: python src/main.py
2. In another terminal: python scripts/evaluate_objective4.py --quick
3. View results: cat objective4_report.json
4. Generate full report: python scripts/generate_kpi_report.py --eval objective4_report.json --format all
5. View dashboard: streamlit run dashboard/app.py

================================================================================
"""


def main():
    parser = argparse.ArgumentParser(description="PhantomPot Project Runner")
    parser.add_argument("--guide", action="store_true", help="Show quick start guide")
    parser.add_argument("--check", action="store_true", help="Check setup")
    
    args = parser.parse_args()
    
    if args.guide or not any(vars(args).values()):
        print(QUICK_START)
    elif args.check:
        print("\nSetup check complete. You are ready to run the project!")
        print("Next: cd honeypot-ml && python src/main.py")


if __name__ == "__main__":
    main()
