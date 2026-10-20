"""Shared session finalization + ML prediction + logging flow."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from core.feature_builder import FeatureBuilder
from core.logger import HoneypotLogger
from core.session_manager import SessionManager
from ml.predict import predict_session_anomaly


def _derive_attack_typing(
    session_record: Dict[str, Any],
    prediction: Dict[str, Any],
    attack_reasons: Optional[List[str]],
) -> Dict[str, Any]:
    """Create normalized attack typing fields for downstream dashboards/reports."""
    tags: List[str] = []

    if isinstance(attack_reasons, list):
        for reason in attack_reasons:
            if reason is None:
                continue
            reason_text = str(reason).strip()
            if reason_text:
                tags.append(reason_text)

    login_attempts = float(session_record.get("total_login_attempts", 0) or 0)
    suspicious_commands = float(session_record.get("suspicious_commands_count", 0) or 0)

    if login_attempts >= 8:
        tags.append("brute_force_suspected")
    if suspicious_commands > 0:
        tags.append("suspicious_command_activity")

    # Keep stable order while removing duplicates.
    deduped_tags: List[str] = []
    seen = set()
    for tag in tags:
        if tag in seen:
            continue
        seen.add(tag)
        deduped_tags.append(tag)

    is_attack = prediction.get("anomaly") == "attack"
    if deduped_tags:
        attack_type = deduped_tags[0]
    elif is_attack:
        attack_type = "ml_anomalous_activity"
    else:
        attack_type = "none"

    return {
        "attack_type": attack_type,
        "attack_tags": deduped_tags,
    }


def finalize_and_log_session(
    session_id: str,
    client_ip: str,
    protocol_tag: str,
    session_manager: SessionManager,
    logger: HoneypotLogger,
    attack_reasons: Optional[List[str]] = None,
) -> None:
    """Finalize a session, run ML inference, and persist the enriched record."""
    payload = session_manager.finalize_session(session_id)
    session_record = FeatureBuilder.build(payload)

    try:
        prediction = predict_session_anomaly(session_record)
        session_record["anomaly"] = prediction["anomaly"]
        session_record["anomaly_score"] = prediction["anomaly_score"]
        session_record["severity"] = prediction["severity"]
        session_record["confidence_label"] = prediction.get("confidence_label")
        session_record["confidence_score"] = prediction.get("confidence_score")
        session_record["decision_band"] = prediction.get("decision_band")
        session_record.update(
            _derive_attack_typing(
                session_record=session_record,
                prediction=prediction,
                attack_reasons=attack_reasons,
            )
        )

        marker = "[!]" if prediction["anomaly"] == "attack" else "[+]"
        tag = f" {protocol_tag}" if protocol_tag else ""
        print(
            f"{marker}{tag} Session {session_id} -> {prediction['anomaly']} "
            f"(score: {prediction['anomaly_score']:.4f}, "
            f"severity: {prediction['severity']})"
        )
    except Exception as exc:
        logger.log_error(f"ml_predict session_id={session_id} ip={client_ip} error={exc}")

    logger.log_session(session_record)
