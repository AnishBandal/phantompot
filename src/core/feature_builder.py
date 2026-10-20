"""Reusable feature extraction for ML-ready session logs."""

from __future__ import annotations

from typing import Any, Dict


class FeatureBuilder:
    """Build flat numerical features from protocol session payloads."""

    @staticmethod
    def build(session_payload: Dict[str, Any]) -> Dict[str, Any]:
        login_attempts = session_payload.get("login_attempts", [])
        commands = session_payload.get("commands", [])
        suspicious_commands_count = sum(
            1 for cmd in commands if bool(cmd.get("is_suspicious", False))
        )

        return {
            **session_payload,
            "total_login_attempts": len(login_attempts),
            "commands_count": len(commands),
            "suspicious_commands_count": suspicious_commands_count,
            "duration": float(session_payload.get("duration", 0.0)),
        }
