"""Thread-safe session/error logging for SIEM ingestion."""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

from .utils import ensure_parent_dir, utc_now_iso
from .event_schema import validate_event


class HoneypotLogger:
    """Write JSONL session events and plain-text errors."""

    def __init__(self, sessions_log_path: str, errors_log_path: str, 
                 kpi_collector: Optional[Any] = None,
                 events_log_path: Optional[str] = None) -> None:
        self.sessions_log_path = sessions_log_path
        self.errors_log_path = errors_log_path
        self.events_log_path = events_log_path or str(Path(sessions_log_path).with_name("events.jsonl"))
        self.kpi_collector = kpi_collector  # Optional KPIMetricsCollector for tracking
        self._session_lock = threading.Lock()
        self._error_lock = threading.Lock()
        self._event_lock = threading.Lock()

        ensure_parent_dir(self.sessions_log_path)
        ensure_parent_dir(self.errors_log_path)

        Path(self.sessions_log_path).touch(exist_ok=True)
        Path(self.errors_log_path).touch(exist_ok=True)
        ensure_parent_dir(self.events_log_path)
        Path(self.events_log_path).touch(exist_ok=True)

    def log_event(self, event: Dict[str, Any]) -> None:
        """Append a validated event record to the dedicated event JSONL stream."""
        if not validate_event(event):
            raise ValueError("Refusing to persist an invalid event record")
        line = json.dumps(event, separators=(",", ":"), ensure_ascii=True)
        with self._event_lock:
            with open(self.events_log_path, "a", encoding="utf-8") as handle:
                handle.write(line + "\n")

    def log_session(self, payload: Dict[str, Any], connection_start_time: Optional[float] = None) -> None:
        """Log session with optional response time tracking.
        
        Args:
            payload: Session data to log
            connection_start_time: Unix timestamp when connection was established (for latency tracking)
        """
        log_write_time = time.time()
        line = json.dumps(payload, separators=(",", ":"), ensure_ascii=True)
        with self._session_lock:
            with open(self.sessions_log_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        
        # Track response time if KPI collector is available
        if self.kpi_collector is not None and connection_start_time is not None:
            session_id = payload.get("session_id", "unknown")
            protocol = payload.get("protocol", "unknown")
            self.kpi_collector.record_response_time(
                session_id=session_id,
                protocol=protocol,
                connection_time=connection_start_time,
                log_write_time=log_write_time
            )

    def log_error(self, message: str) -> None:
        line = f"{utc_now_iso()} {message}"
        with self._error_lock:
            with open(self.errors_log_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")


# Module-level convenient logger and helper function
_DEFAULT_LOGS_DIR = Path(__file__).resolve().parents[2] / "logs"
_DEFAULT_SESSIONS = str(_DEFAULT_LOGS_DIR / "sessions.jsonl")
_DEFAULT_ERRORS = str(_DEFAULT_LOGS_DIR / "errors.log")

_default_logger: HoneypotLogger | None = None


def get_default_logger() -> HoneypotLogger:
    global _default_logger
    if _default_logger is None:
        _default_logger = HoneypotLogger(_DEFAULT_SESSIONS, _DEFAULT_ERRORS)
    return _default_logger


def log_event(payload: Dict[str, Any]) -> None:
    """Write a single session event (JSON Lines).

    This is a thin wrapper around `HoneypotLogger.log_session` so callers
    can simply import `log_event` and not worry about logger setup.
    """
    try:
        get_default_logger().log_session(payload)
    except Exception:
        # In case logging fails, avoid crashing the honeypot; write nothing.
        # Consumers may call `log_error` separately if they need to record
        # logger failures.
        pass
