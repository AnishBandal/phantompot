from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler


ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "processed" / "sessions.csv"
MODEL_DIR = ROOT / "models"
MODEL_DIR.mkdir(exist_ok=True)

MODEL_PATH = MODEL_DIR / "isolation_forest.pkl"
SCALER_PATH = MODEL_DIR / "scaler.pkl"
METADATA_PATH = MODEL_DIR / "model_metadata.json"

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


def _pseudo_label(df: pd.DataFrame) -> np.ndarray:
    """Generate weak labels for synthetic-data validation only."""
    return (
        (df["suspicious_commands_count"] > 0)
        | (df["attack_ratio"] >= 0.30)
        | (df["total_login_attempts"] >= 5)
    ).astype(int).to_numpy()


def _engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    for col in ["duration", "total_login_attempts", "commands_count", "suspicious_commands_count"]:
        df[col] = pd.to_numeric(df.get(col, 0), errors="coerce").fillna(0.0)

    if "attack_ratio" not in df.columns:
        df["attack_ratio"] = df["suspicious_commands_count"] / df["commands_count"].replace(0, 1)
    else:
        df["attack_ratio"] = pd.to_numeric(df["attack_ratio"], errors="coerce").fillna(0.0)

    df["activity_intensity"] = df["commands_count"] / df["duration"].replace(0, 1)
    df["login_intensity"] = df["total_login_attempts"] / df["duration"].replace(0, 1)

    protocol_series = df.get("protocol", "unknown").astype(str).str.lower()
    df["protocol_risk"] = protocol_series.map(PROTOCOL_RISK).fillna(0.5)

    start_ts = pd.to_datetime(df.get("start_time"), format="ISO8601", errors="coerce", utc=True)
    df["hour_of_day"] = start_ts.dt.hour.fillna(0).astype(float)
    df["is_weekend"] = (start_ts.dt.dayofweek >= 5).fillna(False).astype(float)

    return df


def _calibrate_attack_threshold(scores: np.ndarray, y_true: np.ndarray) -> Tuple[float, Dict[str, float]]:
    candidates = np.quantile(scores, np.linspace(0.02, 0.98, 80))
    best = {
        "threshold": -0.2,
        "f1": -1.0,
        "precision": 0.0,
        "recall": 0.0,
        "accuracy": 0.0,
    }

    for threshold in candidates:
        y_pred = (scores <= threshold).astype(int)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        if f1 > best["f1"]:
            best.update(
                {
                    "threshold": float(threshold),
                    "f1": float(f1),
                    "precision": float(precision_score(y_true, y_pred, zero_division=0)),
                    "recall": float(recall_score(y_true, y_pred, zero_division=0)),
                    "accuracy": float(accuracy_score(y_true, y_pred)),
                }
            )

    return float(best["threshold"]), best


def _calibrate_severity_thresholds(scores: np.ndarray, y_true: np.ndarray) -> Tuple[float, float]:
    attack_scores = scores[y_true == 1]
    if len(attack_scores) < 10:
        return -0.5, -0.2

    high_cutoff = float(np.quantile(attack_scores, 0.25))
    medium_cutoff = float(np.quantile(attack_scores, 0.60))
    if high_cutoff >= medium_cutoff:
        return -0.5, -0.2
    return high_cutoff, medium_cutoff


def main() -> None:
    df = pd.read_csv(DATA_PATH)
    df = _engineer_features(df)

    X = df[FEATURE_COLUMNS]
    y_weak = _pseudo_label(df)

    X_train, X_val, y_train_weak, y_val_weak = train_test_split(
        X,
        y_weak,
        test_size=0.20,
        random_state=42,
        stratify=y_weak,
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_val_scaled = scaler.transform(X_val)

    model = IsolationForest(contamination=0.2, random_state=42)
    model.fit(X_train_scaled)

    val_scores = model.score_samples(X_val_scaled)
    attack_threshold, calibration_metrics = _calibrate_attack_threshold(val_scores, y_val_weak)
    high_cutoff, medium_cutoff = _calibrate_severity_thresholds(val_scores, y_val_weak)

    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)

    metadata = {
        "model_version": datetime.now(timezone.utc).isoformat(),
        "training_dataset": str(DATA_PATH),
        "training_rows": int(len(df)),
        "feature_columns": FEATURE_COLUMNS,
        "protocol_risk_mapping": PROTOCOL_RISK,
        "thresholds": {
            "attack": attack_threshold,
            "severity_high": high_cutoff,
            "severity_medium": medium_cutoff,
        },
        "validation": {
            "rows": int(len(X_val)),
            "weak_label_attack_ratio": float(y_val_weak.mean()),
            "calibration_metrics": calibration_metrics,
        },
        "notes": "Validation metrics are computed against weak synthetic labels, not real-world labels.",
    }
    METADATA_PATH.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    print("\nModel training complete")
    print(f"Model saved: {MODEL_PATH}")
    print(f"Scaler saved: {SCALER_PATH}")
    print(f"Metadata saved: {METADATA_PATH}")
    print(f"Calibrated attack threshold: {attack_threshold:.4f}")
    print(f"Calibrated severity thresholds: high<{high_cutoff:.4f}, medium<{medium_cutoff:.4f}")
    print(
        "Validation (weak labels): "
        f"F1={calibration_metrics['f1']:.3f}, "
        f"precision={calibration_metrics['precision']:.3f}, "
        f"recall={calibration_metrics['recall']:.3f}, "
        f"accuracy={calibration_metrics['accuracy']:.3f}"
    )


if __name__ == "__main__":
    main()