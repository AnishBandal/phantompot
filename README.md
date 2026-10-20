# PhantomPot-v2

PhantomPot-v2 is a multi-protocol honeypot platform for security experimentation, attack-behavior capture, and anomaly-based analysis. It combines protocol emulation, structured session logging, and machine learning assisted scoring with a Streamlit dashboard for investigation.

## Core Capabilities

- Concurrent honeypot listeners for SSH, HTTP, FTP, and Telnet.
- Thread-safe session lifecycle and logging pipeline shared across protocols.
- Per-session anomaly scoring with severity and confidence metadata.
- HTTP payload analysis with signature-based attack reasons.
- Interactive dashboard for filtering, drill-down, protocol analytics, and KPI views.

## Architecture Summary

The system follows a unified data flow:

1. Protocol handler captures connection activity.
2. Session manager aggregates login attempts and commands.
3. Session finalizer builds features, runs prediction, and enriches metadata.
4. Logger writes one JSON object per session to logs/sessions.jsonl.
5. Dashboard reads and visualizes logged session records.

## Repository Layout

```text
PhantomPot-v2/
  config/                 Runtime configuration (ports, paths)
  dashboard/              Streamlit analytics dashboard
  data/                   Raw and processed datasets
  docs/                   Reports and project documentation
  logs/                   Runtime logs (sessions.jsonl, errors.log)
  models/                 Trained ML artifacts and metadata
  scripts/                Simulation, evaluation, and utility scripts
  src/
    core/                 Shared session/logging/finalization services
    ftp/                  FTP honeypot implementation
    http_honeypot/        HTTP honeypot and payload analyzer
    ml/                   Inference pipeline
    ssh/                  SSH honeypot implementation
    telnet/               Telnet honeypot implementation
    main.py               Multi-protocol server entrypoint
```

## Requirements

- Python 3.8+
- Pip and virtual environment support
- Windows PowerShell, Linux shell, or macOS terminal

Install dependencies:

```bash
pip install -r requirements.txt
```

## Configuration

Primary runtime settings are in config/config.yaml.

Default listener ports:

- SSH: 2222
- HTTP: 8888
- FTP: 2121
- Telnet: 2323

## Quick Start

### Windows (PowerShell)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python src/main.py
```

### Linux or macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python src/main.py
```

When started, the server listens on all configured protocols concurrently.

## Dashboard

Run the dashboard in a separate terminal:

```bash
streamlit run dashboard/app.py
```

Dashboard includes:

- Global filters (protocol, IP, severity, anomaly class, attack type, attack tags, time range)
- Session analytics and protocol distributions
- HTTP-specific method/path analysis
- Session drill-down view
- KPI metrics tab
- Threshold tuning view

Note: New activity appears once a session is finalized and written to logs/sessions.jsonl. For short HTTP requests this is typically immediate; interactive sessions appear when disconnected or exited.

## Testing Protocols

Start the honeypot first, then run one or more simulation scripts:

```bash
python scripts/simulate_ssh_attacks.py
python scripts/simulate_multi_protocol.py
python scripts/simulate_single_high_intensity.py
```

Manual examples:

- SSH: ssh user@127.0.0.1 -p 2222
- HTTP: curl http://127.0.0.1:8888/
- FTP: ftp 127.0.0.1 2121
- Telnet: telnet 127.0.0.1 2323

## Data and ML Artifacts

Primary runtime log:

- logs/sessions.jsonl

Key enriched fields include:

- session metadata: session_id, ip, protocol, start_time, end_time, duration
- behavior counts: total_login_attempts, commands_count, suspicious_commands_count
- model output: anomaly, anomaly_score, severity, confidence_label, confidence_score, decision_band
- attack typing: attack_type, attack_tags

Model files are stored in:

- models/isolation_forest.pkl
- models/scaler.pkl
- models/model_metadata.json

## Evaluation Utilities

Common scripts:

- scripts/evaluate_objective4.py
- scripts/evaluate_ml_scenarios.py
- scripts/generate_kpi_report.py
- scripts/json_to_csv.py

## Deception Events, Investigation, and Reports

The existing `logs/sessions.jsonl` remains the finalized session-summary log. New
protocol observations are also written as versioned event records to
`logs/events.jsonl`. Event records include an ID, schema version, UTC timestamp,
session reference, source, protocol, event type, outcome, evidence, tags, and a
simulation marker. Historical summaries remain readable; when their event log
is unavailable, the dashboard reconstructs limited events and labels them as
legacy evidence. Missing historical authentication outcomes remain `unknown`.

### Decoy authentication

SSH, FTP, and Telnet preserve their accept-any decoy behavior by default. You
can switch a protocol to configured fake accounts in `config/config.yaml` by
setting `accept_any: false` and adding decoy-only username/password pairs under
`accounts`. The default HTTP fake account is `demo` / `decoy-demo`; change it
before demonstrations if desired. These values are used only by the isolated
simulation policy and never authenticate operating-system accounts. Submitted
passwords are not written to new session summaries or event records. Existing
historical logs may contain credentials captured before this change, so the
dashboard redacts them in detail views and exports; protect those original log
files accordingly.

### Dashboard investigations

Start the dashboard with:

```bash
streamlit run dashboard/app.py
```

The sidebar provides light/dark appearance selection, filters, refresh controls,
and session/event log paths. New navigation sections include **Attack Flow**,
**Security Recommendations**, and **Reports**. Attack-flow links between
different sessions are labeled potentially related when source IP and time
window match; they are not actor attribution. Recommendations are human-review
guidance based on observed honeypot evidence and do not run remediation.
Reports can be previewed and exported as PDF, HTML, JSON, and filtered-session
CSV. Secrets are redacted from reports and exports.

### Isolated synthetic demonstration data

Generate reproducible, clearly marked test records without adding them to
production logs:

```bash
python scripts/generate_demo_scenarios.py
```

In the dashboard, set the session log to
`data/demo_scenarios/sessions.jsonl` and event log to
`data/demo_scenarios/events.jsonl`. The fixtures cover rejected and accepted
decoy authentication, SSH/Telnet command discovery, HTTP signatures, FTP
decoy-file access, benign traffic, and same-source cross-protocol sessions.
All fixture rows have `simulation: true` and are stored separately from `logs/`.

## Security Notice and Disclaimer

This project is provided for authorized security research, defensive testing, and educational use only.

By using this software, you agree to the following:

- You are solely responsible for where and how it is deployed.
- You must use it only in environments you own or are explicitly permitted to test.
- You must comply with all applicable laws, regulations, and institutional policies.

The authors and contributors are not responsible for:

- Any misuse, illegal activity, or unauthorized deployment.
- Any direct, indirect, incidental, or consequential damages resulting from use of this project.
- Data loss, service disruption, legal claims, or third-party impacts arising from operation of this software.

No warranty is provided, express or implied, including but not limited to fitness for a particular purpose and non-infringement.
