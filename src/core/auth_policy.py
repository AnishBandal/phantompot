"""Configurable fake-account policies; never consults host operating-system users."""

from __future__ import annotations

import hmac
from typing import Any


class DecoyAuthPolicy:
    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config = config or {}

    def authenticate(self, protocol: str, username: str, password: str) -> tuple[bool, str]:
        settings = self.config.get(protocol.lower(), {})
        accounts = settings.get("accounts", {}) if isinstance(settings, dict) else {}
        if not isinstance(accounts, dict):
            accounts = {}
        if username in accounts and hmac.compare_digest(str(accounts[username]), str(password)):
            return True, "fake_account_match"
        if settings.get("accept_any", True):
            return True, "accept_any_simulation"
        return False, "fake_account_mismatch"
