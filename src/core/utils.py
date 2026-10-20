"""Shared helper utilities for honeypot services."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict
from uuid import uuid4



def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).isoformat()



def generate_session_id() -> str:
    """Create a unique session identifier."""
    return str(uuid4())



def ensure_parent_dir(file_path: str) -> None:
    """Ensure a file's parent directory exists."""
    Path(file_path).parent.mkdir(parents=True, exist_ok=True)



def base_session_dict(session_id: str, ip: str, protocol: str) -> Dict[str, Any]:
    """Create a protocol-agnostic base session payload."""
    now = utc_now_iso()
    return {
        "session_id": session_id,
        "ip": ip,
        "protocol": protocol,
        "start_time": now,
        "end_time": now,
        "duration": 0.0,
        "login_attempts": [],
        "commands": [],
    }
