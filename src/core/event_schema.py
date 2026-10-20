"""Versioned, protocol-neutral event records for honeypot investigations."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

SCHEMA_VERSION = 1
EVENT_TYPES = {
    "connection_opened", "authentication_attempt", "command_observed",
    "http_request_observed", "session_ended", "service_interaction",
}


def build_event(
    *, session_id: str, source_ip: str, protocol: str, event_type: str,
    event_category: str, action: str, outcome: str = "observed",
    severity: str = "informational", evidence: Any = None,
    attack_tags: list[str] | None = None, simulation: bool = False,
    metadata: dict[str, Any] | None = None, timestamp: str | None = None,
) -> dict[str, Any]:
    if event_type not in EVENT_TYPES:
        raise ValueError(f"Unsupported event_type: {event_type}")
    event_timestamp = timestamp or datetime.now(timezone.utc).isoformat()
    parsed = datetime.fromisoformat(event_timestamp.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Event timestamps must include a timezone")
    return {
        "event_id": str(uuid4()),
        "schema_version": SCHEMA_VERSION,
        "session_id": str(session_id),
        "timestamp": parsed.astimezone(timezone.utc).isoformat(),
        "source_ip": str(source_ip),
        "protocol": str(protocol).lower(),
        "event_type": event_type,
        "event_category": str(event_category),
        "action": str(action),
        "outcome": str(outcome),
        "severity": str(severity).lower(),
        "evidence": evidence,
        "attack_tags": list(attack_tags or []),
        "simulation": bool(simulation),
        "metadata": dict(metadata or {}),
    }


def validate_event(event: dict[str, Any]) -> bool:
    required = {
        "event_id", "schema_version", "session_id", "timestamp", "source_ip",
        "protocol", "event_type", "event_category", "action", "outcome",
        "severity", "evidence", "attack_tags", "simulation", "metadata",
    }
    if not required.issubset(event) or event["event_type"] not in EVENT_TYPES:
        return False
    try:
        return datetime.fromisoformat(str(event["timestamp"]).replace("Z", "+00:00")).tzinfo is not None
    except ValueError:
        return False
