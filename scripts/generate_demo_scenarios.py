"""Write reproducible, explicitly synthetic records outside production logs.

Run from the project root:
    python scripts/generate_demo_scenarios.py
Then set the dashboard session/event paths to data/demo_scenarios/*.jsonl.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from core.event_schema import build_event

OUT = ROOT / "data" / "demo_scenarios"
BASE = datetime(2026, 10, 16, 10, 0, tzinfo=timezone.utc)

SCENARIOS = [
    ("failed-auth", "ssh", "192.0.2.10", [("authentication_attempt", "login", "rejected", {"username": "admin"}, ["authentication_failure"]), ("authentication_attempt", "login", "rejected", {"username": "root"}, ["authentication_failure"]), ("authentication_attempt", "login", "rejected", {"username": "service"}, ["authentication_failure"])]),
    ("decoy-enumeration", "ssh", "192.0.2.11", [("authentication_attempt", "login", "accepted_simulated", {"username": "demo"}, []), ("command_observed", "whoami", "recorded", {"command": "whoami", "response_simulated": True}, []), ("command_observed", "uname -a", "recorded", {"command": "uname -a", "response_simulated": True}, [])]),
    ("http-signature", "http", "192.0.2.12", [("http_request_observed", "POST /login", "signature_match", {"method": "POST", "path": "/login", "response_status": 401}, ["login_probe"]), ("http_request_observed", "GET /../../etc/passwd", "signature_match", {"method": "GET", "path": "/../../etc/passwd", "response_status": 200}, ["path_traversal"])]),
    ("ftp-exploration", "ftp", "192.0.2.13", [("authentication_attempt", "login", "accepted_simulated", {"username": "ftp-user"}, []), ("command_observed", "LIST", "recorded", {"command": "LIST", "response_simulated": True}, []), ("command_observed", "RETR readme.txt", "simulated_decoy_file_returned", {"command": "RETR readme.txt", "response_simulated": True}, [])]),
    ("telnet-discovery", "telnet", "192.0.2.14", [("authentication_attempt", "login", "accepted_simulated", {"username": "guest"}, []), ("command_observed", "id", "recorded", {"command": "id", "response_simulated": True}, [])]),
    ("benign-http", "http", "192.0.2.15", [("http_request_observed", "GET /", "request_recorded", {"method": "GET", "path": "/", "response_status": 200}, [])]),
    ("cross-protocol-ssh", "ssh", "192.0.2.16", [("command_observed", "help", "recorded", {"command": "help", "response_simulated": True}, [])]),
    ("cross-protocol-http", "http", "192.0.2.16", [("http_request_observed", "GET /admin", "signature_match", {"method": "GET", "path": "/admin", "response_status": 200}, ["admin_panel_probe"])]),
]


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    sessions = []
    events = []
    for index, (name, protocol, ip, actions) in enumerate(SCENARIOS):
        session_id = f"demo-{index + 1:02d}-{name}"
        start = BASE + timedelta(minutes=index * 3)
        session_events = [build_event(session_id=session_id, source_ip=ip, protocol=protocol, event_type="connection_opened", event_category="connection", action="connection_open", outcome="observed", evidence={"scenario": name}, simulation=True, timestamp=start.isoformat())]
        for offset, (event_type, action, outcome, evidence, tags) in enumerate(actions, 1):
            session_events.append(build_event(session_id=session_id, source_ip=ip, protocol=protocol, event_type=event_type, event_category="authentication" if event_type == "authentication_attempt" else "request" if protocol == "http" else "command", action=action, outcome=outcome, severity="medium" if tags or outcome == "rejected" else "informational", evidence=evidence, attack_tags=tags, simulation=True, metadata={"scenario_id": name, "response_simulated": True}, timestamp=(start + timedelta(seconds=offset * 20)).isoformat()))
        end = start + timedelta(seconds=(len(actions) + 1) * 20)
        session_events.append(build_event(session_id=session_id, source_ip=ip, protocol=protocol, event_type="session_ended", event_category="lifecycle", action="session_end", outcome="disconnected", simulation=True, metadata={"scenario_id": name}, timestamp=end.isoformat()))
        for event_index, event in enumerate(session_events, 1):
            event["event_id"] = f"{session_id}:event:{event_index:02d}"
        events.extend(session_events)
        logins = [event for event in session_events if event["event_type"] == "authentication_attempt"]
        commands = [event for event in session_events if event["event_type"] in {"command_observed", "http_request_observed"}]
        sessions.append({"schema_version": 1, "session_id": session_id, "ip": ip, "protocol": protocol, "start_time": start.isoformat(), "end_time": end.isoformat(), "duration": (end-start).total_seconds(), "simulation": True, "simulation_scenario": name, "event_ids": [event["event_id"] for event in session_events], "login_attempts": [{"username": event["evidence"].get("username", ""), "timestamp": event["timestamp"], "outcome": event["outcome"]} for event in logins], "commands": [{"command": event["action"], "timestamp": event["timestamp"], "is_suspicious": bool(event["attack_tags"])} for event in commands], "total_login_attempts": len(logins), "commands_count": len(commands), "suspicious_commands_count": sum(bool(event["attack_tags"]) for event in commands), "anomaly": "attack" if any(event["attack_tags"] for event in session_events) else "normal", "anomaly_score": -0.6 if any(event["attack_tags"] for event in session_events) else 0.1, "severity": "high" if any(event["attack_tags"] for event in session_events) else "low", "attack_type": next((tag for event in session_events for tag in event["attack_tags"]), "none"), "attack_tags": sorted({tag for event in session_events for tag in event["attack_tags"]})})
    (OUT / "sessions.jsonl").write_text("".join(json.dumps(row, separators=(",", ":")) + "\n" for row in sessions), encoding="utf-8")
    (OUT / "events.jsonl").write_text("".join(json.dumps(row, separators=(",", ":")) + "\n" for row in events), encoding="utf-8")
    print(f"Wrote {len(sessions)} synthetic sessions and {len(events)} events to {OUT}")


if __name__ == "__main__":
    main()
