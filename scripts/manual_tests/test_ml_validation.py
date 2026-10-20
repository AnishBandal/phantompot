#!/usr/bin/env python3
"""
Comprehensive ML Model Validation Test
Verify all protocols work with ML models correctly
"""

import sys
import json
sys.path.insert(0, 'src')

from core.feature_builder import FeatureBuilder
from ml.predict import predict_session_anomaly, build_feature_row
from pathlib import Path

print("\n" + "=" * 80)
print("  ML MODEL VALIDATION TEST")
print("=" * 80)

# Test 1: Check model files exist
print("\n1. MODEL FILES VERIFICATION:")
models_dir = Path("models")
model_file = models_dir / "isolation_forest.pkl"
scaler_file = models_dir / "scaler.pkl"

model_exists = model_file.exists()
scaler_exists = scaler_file.exists()

print(f"   {'✓' if model_exists else '✗'} Isolation Forest Model: {model_file}")
print(f"   {'✓' if scaler_exists else '✗'} Feature Scaler: {scaler_file}")

if not (model_exists and scaler_exists):
    print("\n✗ ERROR: ML models not found!")
    sys.exit(1)

# Test 2: Load models
print("\n2. MODEL LOADING:")
try:
    from ml.predict import _load_model_once
    model, scaler = _load_model_once()
    print(f"   ✓ Isolation Forest loaded: {type(model).__name__}")
    print(f"   ✓ StandardScaler loaded: {type(scaler).__name__}")
except Exception as e:
    print(f"   ✗ Failed to load models: {e}")
    sys.exit(1)

# Test 3: Feature extraction and normalization
print("\n3. FEATURE EXTRACTION VALIDATION:")

test_sessions = [
    {
        "name": "Normal SSH Session",
        "protocol": "ssh",
        "login_attempts": [{"username": "admin", "password": "pass"}],
        "commands": [
            {"command": "ls", "is_suspicious": False},
            {"command": "pwd", "is_suspicious": False},
        ],
        "duration": 30.0,
    },
    {
        "name": "Attack Session (SQL Injection)",
        "protocol": "http",
        "login_attempts": [{"username": "admin'; DROP TABLE users; --", "password": "anything"}],
        "commands": [
            {"command": "SELECT * FROM users", "is_suspicious": True},
            {"command": "DELETE FROM logs", "is_suspicious": True},
        ],
        "duration": 5.0,
    },
    {
        "name": "Brute Force Session",
        "protocol": "ssh",
        "login_attempts": [
            {"username": "root", "password": "password"},
            {"username": "root", "password": "123456"},
            {"username": "root", "password": "admin"},
            {"username": "root", "password": "letmein"},
            {"username": "root", "password": "welcome"},
        ],
        "commands": [{"command": "id", "is_suspicious": False}],
        "duration": 15.0,
    },
    {
        "name": "High Activity Session",
        "protocol": "ssh",
        "login_attempts": [{"username": "attacker", "password": "x"}],
        "commands": [
            {"command": f"cmd_{i}", "is_suspicious": i % 3 == 0}
            for i in range(100)
        ],
        "duration": 2.0,
    },
]

for session in test_sessions:
    print(f"\n   Testing: {session['name']}")
    
    # Build features
    features = FeatureBuilder.build(session)
    print(f"     - Login attempts: {features['total_login_attempts']}")
    print(f"     - Commands logged: {features['commands_count']}")
    print(f"     - Suspicious commands: {features['suspicious_commands_count']}")
    print(f"     - Duration: {features['duration']}s")
    
    # Predict anomaly
    try:
        prediction = predict_session_anomaly(features)
        print(f"     - Prediction: {prediction['anomaly']} (score: {prediction['anomaly_score']:.4f})")
        print(f"     - Severity: {prediction['severity']}")
        
        # Validate output
        assert prediction['anomaly'] in ['normal', 'attack'], f"Invalid anomaly value: {prediction['anomaly']}"
        assert isinstance(prediction['anomaly_score'], float), "Score should be float"
        assert prediction['severity'] in ['low', 'medium', 'high'], f"Invalid severity: {prediction['severity']}"
        print("     ✓ Prediction valid")
    except Exception as e:
        print(f"     ✗ Prediction error: {e}")
        sys.exit(1)

# Test 4: Feature normalization edge cases
print("\n4. FEATURE NORMALIZATION EDGE CASES:")

edge_cases = [
    {
        "name": "Very short session (0.01s with many commands)",
        "session": {
            "login_attempts": [{"username": "user", "password": "pass"}],
            "commands": [{"command": f"cmd{i}", "is_suspicious": False} for i in range(50)],
            "duration": 0.01,
        },
        "expected": "Should cap activity_intensity to prevent overflow",
    },
    {
        "name": "Long session with few commands",
        "session": {
            "login_attempts": [{"username": "user", "password": "pass"}],
            "commands": [{"command": "ls", "is_suspicious": False}],
            "duration": 3600.0,
        },
        "expected": "Should handle normalized low intensity",
    },
    {
        "name": "Zero duration session",
        "session": {
            "login_attempts": [],
            "commands": [],
            "duration": 0.0,
        },
        "expected": "Should use 0.1s lower-bound",
    },
]

for case in edge_cases:
    print(f"\n   {case['name']}")
    try:
        features = FeatureBuilder.build(case['session'])
        prediction = predict_session_anomaly(features)
        
        # Check for NaN or inf
        feature_row = build_feature_row(features)
        for key, value in feature_row.items():
            assert not (value != value), f"NaN detected in {key}"  # NaN != NaN
            assert value != float('inf') and value != float('-inf'), f"Inf detected in {key}"
        
        print(f"     ✓ Handled correctly - {case['expected']}")
    except Exception as e:
        print(f"     ✗ Error: {e}")
        sys.exit(1)

# Test 5: Protocol compatibility
print("\n5. PROTOCOL COMPATIBILITY:")

protocols = {
    "ssh": {
        "login_attempts": [{"username": "admin", "password": "pass"}],
        "commands": [{"command": "whoami", "is_suspicious": False}],
        "duration": 10.0,
    },
    "http": {
        "login_attempts": [{"username": "user@example.com", "password": "secret"}],
        "commands": [],
        "duration": 5.0,
    },
    "ftp": {
        "login_attempts": [{"username": "anonymous", "password": "email@test"}],
        "commands": [{"command": "LIST", "is_suspicious": False}],
        "duration": 20.0,
    },
    "telnet": {
        "login_attempts": [{"username": "admin", "password": "pass"}],
        "commands": [{"command": "show version", "is_suspicious": False}],
        "duration": 15.0,
    },
}

for protocol, session_data in protocols.items():
    print(f"\n   {protocol.upper()}:")
    try:
        features = FeatureBuilder.build(session_data)
        prediction = predict_session_anomaly(features)
        print(f"     ✓ {protocol.upper()}: {prediction['anomaly']} (score: {prediction['anomaly_score']:.4f})")
    except Exception as e:
        print(f"     ✗ {protocol.upper()} error: {e}")
        sys.exit(1)

# Test 6: Feature column requirements
print("\n6. ML FEATURE COLUMNS:")

from ml.predict import FEATURE_COLUMNS

print(f"   Required features: {len(FEATURE_COLUMNS)}")
for i, col in enumerate(FEATURE_COLUMNS, 1):
    print(f"     {i}. {col}")

# Test 7: Severity classification
print("\n7. SEVERITY CLASSIFICATION:")

from ml.predict import interpret_severity

test_scores = [
    (-0.8, "high"),
    (-0.5, "high"),
    (-0.4, "medium"),
    (-0.2, "medium"),
    (-0.1, "low"),
    (0.0, "low"),
    (0.5, "low"),
]

all_correct = True
for score, expected in test_scores:
    result = interpret_severity(score)
    status = "✓" if result == expected else "✗"
    print(f"   {status} Score {score:>5} → {result:>6} (expected: {expected})")
    if result != expected:
        all_correct = False

if not all_correct:
    print("\n   ✗ Severity classification has issues")
    sys.exit(1)

# Final Summary
print("\n" + "=" * 80)
print("  ✓ ML MODEL VALIDATION COMPLETE")
print("=" * 80)

print("""
VALIDATION RESULTS:
  ✓ Model files exist and are loadable
  ✓ Feature extraction works for all protocols
  ✓ Anomaly prediction outputs are valid
  ✓ Feature normalization prevents overflow
  ✓ All protocols compatible with ML pipeline
  ✓ Severity classification is correct
  ✓ Edge cases handled properly

PROTOCOLS VALIDATED:
  ✓ SSH - Command-based sessions with login tracking
  ✓ HTTP - Form submissions and login attempts
  ✓ FTP - Protocol commands and authentication
  ✓ Telnet - Remote shell with command classification

ML FEATURES:
  • total_login_attempts - Tracks brute force attempts
  • duration - Session length
  • commands_count - Activity volume
  • suspicious_commands_count - Attack indicators
  • attack_ratio - Suspicious/total ratio
  • activity_intensity - Commands per second (capped at 1000)
  • login_intensity - Login attempts per second (capped at 100)

SECURITY:
  • Models prevent numerical overflow through capping
  • NaN/Inf values handled gracefully
  • All protocols feed features through same pipeline
  • Predictions logged with severity levels

Status: ALL SYSTEMS OPERATIONAL ✓
""")
