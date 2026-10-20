"""Session lifecycle management for all honeypot protocols."""

from __future__ import annotations

import threading
from datetime import datetime
from typing import Any, Dict

from .utils import base_session_dict, generate_session_id, utc_now_iso
from .auth_policy import DecoyAuthPolicy
from .event_schema import build_event


class SessionManager:
    """Create, track, and finalize session objects in a thread-safe map."""

    def __init__(self, event_sink=None, auth_config=None) -> None:
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._event_sink = event_sink
        self._auth_policy = DecoyAuthPolicy(auth_config)

    def _emit(self, session_id: str, **event_fields: Any) -> Dict[str, Any] | None:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return None
            event = build_event(
                session_id=session_id,
                source_ip=session["ip"],
                protocol=session["protocol"],
                simulation=bool(session.get("simulation", False)),
                **event_fields,
            )
            session.setdefault("event_ids", []).append(event["event_id"])
        if self._event_sink is not None:
            try:
                self._event_sink(event)
            except Exception:
                # Telemetry persistence failures must not kill a decoy session.
                with self._lock:
                    current = self._sessions.get(session_id)
                    if current is not None:
                        current["event_persistence_errors"] = int(current.get("event_persistence_errors", 0)) + 1
        return event

    def create_session(self, ip: str, protocol: str) -> str:
        session_id = generate_session_id()
        with self._lock:
            self._sessions[session_id] = base_session_dict(
                session_id=session_id,
                ip=ip,
                protocol=protocol,
            )
            self._sessions[session_id]["schema_version"] = 1
            self._sessions[session_id]["simulation"] = False
            self._sessions[session_id]["event_ids"] = []
            self._sessions[session_id]["connection_state"] = "active"
        self._emit(
            session_id, event_type="connection_opened", event_category="connection",
            action="connection_open", outcome="observed", severity="informational",
            evidence={"protocol": protocol},
        )
        return session_id

    def add_login_attempt(self, session_id: str, username: str, password: str = "", *, accepted: bool = True, reason: str = "simulated") -> None:
        payload = {
            "username": username,
            "timestamp": utc_now_iso(),
            "outcome": "accepted_simulated" if accepted else "rejected",
        }
        with self._lock:
            if session_id not in self._sessions:
                return
            self._sessions[session_id]["login_attempts"].append(payload)
        self._emit(
            session_id, event_type="authentication_attempt", event_category="authentication",
            action="login", outcome=payload["outcome"], severity="medium" if not accepted else "informational",
            evidence={"username": username},
            metadata={"reason": reason, "simulated_acceptance": bool(accepted)},
            attack_tags=["authentication_failure"] if not accepted else [],
        )

    def authenticate(self, session_id: str, username: str, password: str) -> bool:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return False
            protocol = session["protocol"]
        accepted, reason = self._auth_policy.authenticate(protocol, username, password)
        self.add_login_attempt(session_id, username, password, accepted=accepted, reason=reason)
        return accepted

    def add_command(self, session_id: str, command: str, is_suspicious: bool, *, outcome: str | None = None, event_metadata: Dict[str, Any] | None = None, attack_tags: list[str] | None = None) -> None:
        payload = {
            "command": command,
            "timestamp": utc_now_iso(),
            "is_suspicious": bool(is_suspicious),
        }
        with self._lock:
            if session_id in self._sessions:
                self._sessions[session_id]["commands"].append(payload)
                protocol = self._sessions[session_id]["protocol"]
            else:
                return
        self._emit(
            session_id,
            event_type="http_request_observed" if protocol == "http" else "command_observed",
            event_category="http_request" if protocol == "http" else "command",
            action=command,
            outcome=outcome or ("flagged" if is_suspicious else "recorded"),
            severity="medium" if is_suspicious else "informational",
            evidence={"command": command},
            attack_tags=attack_tags or (["suspicious_activity"] if is_suspicious else []),
            metadata={"response_simulated": True, **(event_metadata or {})},
        )

    def set_connection_state(self, session_id: str, state: str) -> None:
        if state not in {"active", "disconnected", "incomplete"}:
            raise ValueError(f"Unsupported connection state: {state}")
        with self._lock:
            if session_id in self._sessions:
                self._sessions[session_id]["connection_state"] = state

    def finalize_session(self, session_id: str) -> Dict[str, Any]:
        with self._lock:
            existing = self._sessions.get(session_id)
            state = str(existing.get("connection_state", "active")) if existing else "incomplete"
        if state == "active":
            state = "disconnected"
            self.set_connection_state(session_id, state)
        self._emit(
            session_id, event_type="session_ended", event_category="lifecycle",
            action="session_end", outcome=state, severity="informational",
            evidence=None,
        )
        with self._lock:
            session = self._sessions.pop(session_id, None)

        if session is None:
            raise KeyError(f"Unknown session_id: {session_id}")

        start = datetime.fromisoformat(session["start_time"])
        end = datetime.now(start.tzinfo)
        session["end_time"] = end.isoformat()
        session["duration"] = max((end - start).total_seconds(), 0.0)
        session["connection_state"] = state
        return session
