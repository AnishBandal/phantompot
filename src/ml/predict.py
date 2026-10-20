"""Real-time anomaly prediction for honeypot sessions."""

from __future__ import annotations

from pathlib import Path
import json
import threading
from typing import Any, Dict, Tuple

import joblib
import pandas as pd

BASE_DIR = Path(__file__).resolve().parents[2]
MODEL_PATH = BASE_DIR / "models" / "isolation_forest.pkl"
SCALER_PATH = BASE_DIR / "models" / "scaler.pkl"
METADATA_PATH = BASE_DIR / "models" / "model_metadata.json"

FEATURE_COLUMNS = [
    "total_login_attempts",
    "duration",
    "commands_count",
    "suspicious_commands_count",
    "attack_ratio",
    "activity_intensity",
    "login_intensity",
    "protocol_risk",
    "hour_of_day",
    "is_weekend",
]

PROTOCOL_RISK = {
    "ssh": 0.9,
    "telnet": 1.0,
    "http": 0.7,
    "ftp": 0.6,
}

_model = None
_scaler = None
_metadata: Dict[str, Any] = {}
_model_lock = threading.Lock()



def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default



def _load_model_once() -> Tuple[Any, Any]:
    global _model
    global _scaler
    global _metadata

    if _model is None or _scaler is None:
        with _model_lock:
            if _model is None:
                _model = joblib.load(MODEL_PATH)
            if _scaler is None:
                _scaler = joblib.load(SCALER_PATH)
            if not _metadata and METADATA_PATH.exists():
                try:
                    _metadata = json.loads(METADATA_PATH.read_text(encoding="utf-8"))
                except Exception:
                    _metadata = {}

    return _model, _scaler



def build_feature_row(session_data: Dict[str, Any]) -> Dict[str, float]:
    attempts = max(_safe_float(session_data.get("total_login_attempts", 0)), 0.0)
    duration = max(_safe_float(session_data.get("duration", 0.0)), 0.0)
    commands = max(_safe_float(session_data.get("commands_count", 0)), 0.0)
    suspicious = max(_safe_float(session_data.get("suspicious_commands_count", 0)), 0.0)

    attack_ratio = suspicious / commands if commands > 0 else 0.0
    # Normalize intensity features with lower-bound to prevent extreme values on short sessions.
    # Cap at reasonable maximums to maintain numerical stability across the ML pipeline.
    activity_intensity = min(commands / max(duration, 0.1), 1000.0) if duration > 0 else min(commands, 1000.0)
    login_intensity = min(attempts / max(duration, 0.1), 100.0) if duration > 0 else min(attempts, 100.0)
    protocol = str(session_data.get("protocol", "unknown")).lower()
    protocol_risk = float(PROTOCOL_RISK.get(protocol, 0.5))

    start_time = session_data.get("start_time")
    parsed_start = pd.to_datetime(start_time, format="ISO8601", errors="coerce", utc=True)
    if pd.isna(parsed_start):
        hour_of_day = 0.0
        is_weekend = 0.0
    else:
        hour_of_day = float(parsed_start.hour)
        is_weekend = 1.0 if int(parsed_start.dayofweek) >= 5 else 0.0

    return {
        "total_login_attempts": attempts,
        "duration": duration,
        "commands_count": commands,
        "suspicious_commands_count": suspicious,
        "attack_ratio": attack_ratio,
        "activity_intensity": activity_intensity,
        "login_intensity": login_intensity,
        "protocol_risk": protocol_risk,
        "hour_of_day": hour_of_day,
        "is_weekend": is_weekend,
    }



def interpret_severity(anomaly_score: float) -> str:
    """Interpret anomaly severity based on score.
    
    Isolation Forest uses negative scores for anomalies.
    More negative = more anomalous.
    """
    thresholds = _metadata.get("thresholds", {}) if isinstance(_metadata, dict) else {}
    high_cutoff = _safe_float(thresholds.get("severity_high", -0.5), -0.5)
    medium_cutoff = _safe_float(thresholds.get("severity_medium", -0.2), -0.2)

    if anomaly_score <= high_cutoff:
        return "high"
    if anomaly_score <= medium_cutoff:
        return "medium"
    return "low"


def _confidence_from_score(
    anomaly_score: float,
    attack_threshold: float,
    high_cutoff: float,
    medium_cutoff: float,
) -> Dict[str, Any]:
    """Compute confidence band for model decisions.

    Confidence is based on how far the score is from the decision threshold.
    Farther distance => higher confidence.
    """
    thresholds = _metadata.get("thresholds", {}) if isinstance(_metadata, dict) else {}
    margin = _safe_float(thresholds.get("confidence_margin", 0.08), 0.08)
    margin = max(margin, 0.01)

    distance = abs(anomaly_score - attack_threshold)
    confidence_score = min(distance / (margin * 3.0), 1.0)

    if attack_threshold - margin <= anomaly_score <= attack_threshold + margin:
        return {
            "confidence_label": "uncertain",
            "confidence_score": confidence_score,
            "decision_band": "threshold_neighborhood",
        }

    if anomaly_score <= attack_threshold:
        # Attack side confidence tiers anchored to severity thresholds.
        if anomaly_score <= high_cutoff:
            label = "high_confidence_attack"
            band = "high_severity_zone"
        elif anomaly_score <= medium_cutoff:
            label = "medium_confidence_attack"
            band = "medium_severity_zone"
        else:
            label = "low_confidence_attack"
            band = "low_severity_attack_zone"
        return {
            "confidence_label": label,
            "confidence_score": confidence_score,
            "decision_band": band,
        }

    # Normal side confidence tiers by threshold distance.
    if distance >= margin * 2.5:
        label = "high_confidence_normal"
    elif distance >= margin * 1.5:
        label = "medium_confidence_normal"
    else:
        label = "low_confidence_normal"

    return {
        "confidence_label": label,
        "confidence_score": confidence_score,
        "decision_band": "normal_zone",
    }



def predict_session_anomaly(session_data: Dict[str, Any]) -> Dict[str, Any]:
    model, scaler = _load_model_once()

    row = build_feature_row(session_data)
    feature_frame = pd.DataFrame([row], columns=FEATURE_COLUMNS)
    scaled = scaler.transform(feature_frame)

    raw_prediction = int(model.predict(scaled)[0])

    if hasattr(model, "score_samples"):
        anomaly_score = float(model.score_samples(scaled)[0])
    elif hasattr(model, "decision_function"):
        anomaly_score = float(model.decision_function(scaled)[0])
    else:
        anomaly_score = 0.0

    thresholds = _metadata.get("thresholds", {}) if isinstance(_metadata, dict) else {}
    attack_threshold = _safe_float(thresholds.get("attack", -0.2), -0.2)
    high_cutoff = _safe_float(thresholds.get("severity_high", -0.5), -0.5)
    medium_cutoff = _safe_float(thresholds.get("severity_medium", -0.2), -0.2)

    label = "attack" if anomaly_score <= attack_threshold else "normal"
    severity = interpret_severity(anomaly_score)
    confidence = _confidence_from_score(
        anomaly_score=anomaly_score,
        attack_threshold=attack_threshold,
        high_cutoff=high_cutoff,
        medium_cutoff=medium_cutoff,
    )

    return {
        "anomaly": label,
        "model_prediction": "normal" if raw_prediction == 1 else "attack",
        "attack_threshold": attack_threshold,
        "anomaly_score": anomaly_score,
        "severity": severity,
        "confidence_label": confidence["confidence_label"],
        "confidence_score": confidence["confidence_score"],
        "decision_band": confidence["decision_band"],
        "features": row,
    }
