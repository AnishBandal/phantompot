"""Per-scenario ML evaluation harness with confidence analytics.

Evaluates model performance by synthetic scenario families and protocols.
Ground truth is weak-label based (synthetic heuristic), not real-world labels.

Usage:
    python scripts/evaluate_ml_scenarios.py
    python scripts/evaluate_ml_scenarios.py --input data/processed/sessions.csv --output ml_scenario_report.json
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pandas as pd

SCRIPT_DIR = Path(__file__).resolve().parent
BASE_DIR = SCRIPT_DIR.parent
SRC_DIR = BASE_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from ml.predict import predict_session_anomaly


@dataclass
class SessionEval:
    session_id: str
    protocol: str
    scenario_family: str
    y_true: str
    y_pred: str
    anomaly_score: float
    confidence_label: str
    confidence_score: float


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _scenario_family(row: pd.Series) -> str:
    protocol = str(row.get("protocol", "unknown")).lower()
    attempts = _safe_float(row.get("total_login_attempts", 0))
    commands = _safe_float(row.get("commands_count", 0))
    suspicious = _safe_float(row.get("suspicious_commands_count", 0))
    attack_ratio = _safe_float(row.get("attack_ratio", 0))
    duration = _safe_float(row.get("duration", 0))

    if protocol in {"ssh", "telnet"} and attempts >= 6:
        return "brute_force"
    if protocol == "http" and suspicious > 0:
        return "payload_injection"
    if protocol == "ftp" and (suspicious > 0 or commands >= 8):
        return "enumeration"
    if suspicious >= 2 and attack_ratio >= 0.40:
        return "command_execution"
    if attempts <= 2 and suspicious == 0 and commands <= 3 and duration >= 30:
        return "normal_baseline"
    if suspicious == 0 and attempts <= 3:
        return "normal_interactive"
    return "reconnaissance"


def _weak_ground_truth(row: pd.Series, family: str) -> str:
    if family in {"normal_baseline", "normal_interactive"}:
        return "normal"

    suspicious = _safe_float(row.get("suspicious_commands_count", 0))
    attack_ratio = _safe_float(row.get("attack_ratio", 0))
    attempts = _safe_float(row.get("total_login_attempts", 0))

    if suspicious > 0 or attack_ratio >= 0.30 or attempts >= 5:
        return "attack"
    return "normal"


def _confusion(y_true: List[str], y_pred: List[str]) -> Dict[str, int]:
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == "attack" and p == "attack")
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == "normal" and p == "normal")
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == "normal" and p == "attack")
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == "attack" and p == "normal")
    return {"tp": tp, "tn": tn, "fp": fp, "fn": fn}


def _metrics_from_confusion(c: Dict[str, int]) -> Dict[str, float]:
    tp, tn, fp, fn = c["tp"], c["tn"], c["fp"], c["fn"]
    total = tp + tn + fp + fn
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    accuracy = (tp + tn) / total if total else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {
        "total": float(total),
        "precision": precision,
        "recall": recall,
        "accuracy": accuracy,
        "f1": f1,
        "false_positive_rate": fpr,
    }


def _evaluate_rows(df: pd.DataFrame) -> List[SessionEval]:
    results: List[SessionEval] = []

    for _, row in df.iterrows():
        family = _scenario_family(row)
        y_true = _weak_ground_truth(row, family)
        session_dict = {
            "protocol": row.get("protocol", "unknown"),
            "start_time": row.get("start_time", None),
            "total_login_attempts": _safe_float(row.get("total_login_attempts", 0)),
            "duration": _safe_float(row.get("duration", 0)),
            "commands_count": _safe_float(row.get("commands_count", 0)),
            "suspicious_commands_count": _safe_float(row.get("suspicious_commands_count", 0)),
        }

        pred = predict_session_anomaly(session_dict)
        results.append(
            SessionEval(
                session_id=str(row.get("session_id", "unknown")),
                protocol=str(row.get("protocol", "unknown")).lower(),
                scenario_family=family,
                y_true=y_true,
                y_pred=str(pred.get("anomaly", "normal")),
                anomaly_score=_safe_float(pred.get("anomaly_score", 0.0)),
                confidence_label=str(pred.get("confidence_label", "uncertain")),
                confidence_score=_safe_float(pred.get("confidence_score", 0.0)),
            )
        )

    return results


def _group_report(items: List[SessionEval], key: str) -> Dict[str, Any]:
    grouped: Dict[str, List[SessionEval]] = {}
    for item in items:
        bucket = getattr(item, key)
        grouped.setdefault(bucket, []).append(item)

    report: Dict[str, Any] = {}
    for bucket, rows in sorted(grouped.items(), key=lambda kv: kv[0]):
        y_true = [r.y_true for r in rows]
        y_pred = [r.y_pred for r in rows]
        conf = _confusion(y_true, y_pred)
        metrics = _metrics_from_confusion(conf)
        confidence_counts: Dict[str, int] = {}
        for r in rows:
            confidence_counts[r.confidence_label] = confidence_counts.get(r.confidence_label, 0) + 1

        report[bucket] = {
            "count": len(rows),
            "confusion": conf,
            "metrics": metrics,
            "confidence_distribution": confidence_counts,
            "avg_confidence_score": sum(r.confidence_score for r in rows) / max(len(rows), 1),
            "avg_anomaly_score": sum(r.anomaly_score for r in rows) / max(len(rows), 1),
        }
    return report


def run(input_csv: Path, output_path: Path) -> Dict[str, Any]:
    df = pd.read_csv(input_csv)

    required_cols = {
        "session_id",
        "protocol",
        "start_time",
        "duration",
        "total_login_attempts",
        "commands_count",
        "suspicious_commands_count",
    }
    missing = sorted(required_cols - set(df.columns))
    if missing:
        raise ValueError(f"Missing required columns: {missing}")

    if "attack_ratio" not in df.columns:
        df["attack_ratio"] = (
            pd.to_numeric(df["suspicious_commands_count"], errors="coerce").fillna(0.0)
            / pd.to_numeric(df["commands_count"], errors="coerce").replace(0, 1).fillna(1.0)
        )

    evaluations = _evaluate_rows(df)
    y_true = [e.y_true for e in evaluations]
    y_pred = [e.y_pred for e in evaluations]

    overall_conf = _confusion(y_true, y_pred)
    overall_metrics = _metrics_from_confusion(overall_conf)

    confidence_distribution: Dict[str, int] = {}
    for e in evaluations:
        confidence_distribution[e.confidence_label] = confidence_distribution.get(e.confidence_label, 0) + 1

    report = {
        "metadata": {
            "input_csv": str(input_csv),
            "rows": len(evaluations),
            "note": "Ground truth is weak-label synthetic heuristic.",
        },
        "overall": {
            "confusion": overall_conf,
            "metrics": overall_metrics,
            "confidence_distribution": confidence_distribution,
            "avg_confidence_score": sum(e.confidence_score for e in evaluations) / max(len(evaluations), 1),
        },
        "by_scenario_family": _group_report(evaluations, "scenario_family"),
        "by_protocol": _group_report(evaluations, "protocol"),
    }

    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Per-scenario ML evaluation harness")
    parser.add_argument(
        "--input",
        type=Path,
        default=BASE_DIR / "data" / "processed" / "sessions.csv",
        help="Input sessions CSV",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=BASE_DIR / "ml_scenario_report.json",
        help="Output report JSON",
    )
    args = parser.parse_args()

    report = run(args.input, args.output)
    print("Per-scenario ML evaluation complete")
    print(f"Output: {args.output}")
    print(
        "Overall metrics: "
        f"F1={report['overall']['metrics']['f1']:.3f}, "
        f"precision={report['overall']['metrics']['precision']:.3f}, "
        f"recall={report['overall']['metrics']['recall']:.3f}, "
        f"accuracy={report['overall']['metrics']['accuracy']:.3f}"
    )


if __name__ == "__main__":
    main()
