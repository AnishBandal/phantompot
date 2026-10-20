"""Application entrypoint for the modular multi-protocol honeypot backend.

Starts four honeypot listeners concurrently:
  - SSH    (default port 2222)
    - HTTP   (default port 8888)
  - FTP    (default port 2121)
  - Telnet (default port 2323)

Each protocol runs in its own daemon thread so a Ctrl-C from the main
thread shuts everything down cleanly.
"""

from __future__ import annotations

import threading
import sys
import sysconfig
import os

# Ensure the Python stdlib directory is earlier on sys.path than the project
# so standard library packages (e.g. `http`) are not shadowed by local
# packages named the same. This helps when running the script directly.
stdlib_dir = sysconfig.get_paths().get("stdlib")
if stdlib_dir and stdlib_dir not in sys.path:
    sys.path.insert(0, stdlib_dir)
from pathlib import Path
from typing import Any, Dict

import yaml

from core.logger import HoneypotLogger
from core.session_manager import SessionManager
from ftp.ftp_server import FTPHoneypotServer
from http_honeypot.http_server import HTTPHoneypotServer
from ssh.ssh_server import SSHHoneypotServer
from telnet.telnet_server import TelnetHoneypotServer

BASE_DIR = Path(__file__).resolve().parents[1]


def load_config(config_path: Path) -> Dict[str, Any]:
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def build_logger(cfg: Dict[str, Any]) -> HoneypotLogger:
    logs_cfg = cfg.get("logging", {})
    sessions_log = BASE_DIR / logs_cfg.get("sessions_log", "logs/sessions.jsonl")
    errors_log = BASE_DIR / logs_cfg.get("errors_log", "logs/errors.log")
    events_log = BASE_DIR / logs_cfg.get("events_log", "logs/events.jsonl")
    return HoneypotLogger(str(sessions_log), str(errors_log), events_log_path=str(events_log))


def _start_in_thread(server: Any, name: str) -> threading.Thread:
    """Spawn *server.serve_forever()* in a named daemon thread."""
    t = threading.Thread(target=server.serve_forever, name=name, daemon=True)
    t.start()
    return t


def main() -> None:
    config = load_config(BASE_DIR / "config" / "config.yaml")

    logs_cfg = config.get("logging", {})
    logger = HoneypotLogger(
        str(BASE_DIR / config.get("logging", {}).get("sessions_log", "logs/sessions.jsonl")),
        str(BASE_DIR / config.get("logging", {}).get("errors_log", "logs/errors.log")),
        events_log_path=str(BASE_DIR / logs_cfg.get("events_log", "logs/events.jsonl")),
    )
    # Shared session manager — all protocols write to the same in-memory store
    # which is thread-safe internally.
    session_manager = SessionManager(
        event_sink=logger.log_event,
        auth_config=config.get("deception", {}).get("authentication", {}),
    )

    # ------------------------------------------------------------------ SSH
    ssh_cfg = config.get("ssh", {})
    ssh_server = SSHHoneypotServer(
        host=ssh_cfg.get("host", "0.0.0.0"),
        port=int(ssh_cfg.get("port", 2222)),
        logger=logger,
        session_manager=session_manager,
        host_key_path=str(BASE_DIR / ssh_cfg.get("host_key_path", "config/ssh_host_rsa.key")),
    )

    # ----------------------------------------------------------------- HTTP
    http_cfg = config.get("http", {})
    http_server = HTTPHoneypotServer(
        host=http_cfg.get("host", "0.0.0.0"),
        port=int(http_cfg.get("port", 8888)),
        logger=logger,
        session_manager=session_manager,
    )

    # ------------------------------------------------------------------ FTP
    ftp_cfg = config.get("ftp", {})
    ftp_server = FTPHoneypotServer(
        host=ftp_cfg.get("host", "0.0.0.0"),
        port=int(ftp_cfg.get("port", 2121)),
        logger=logger,
        session_manager=session_manager,
    )

    # --------------------------------------------------------------- Telnet
    telnet_cfg = config.get("telnet", {})
    telnet_server = TelnetHoneypotServer(
        host=telnet_cfg.get("host", "0.0.0.0"),
        port=int(telnet_cfg.get("port", 2323)),
        logger=logger,
        session_manager=session_manager,
    )

    # Start HTTP, FTP, Telnet in background threads; SSH blocks main thread.
    _start_in_thread(http_server, "http-honeypot")
    _start_in_thread(ftp_server, "ftp-honeypot")
    _start_in_thread(telnet_server, "telnet-honeypot")

    # SSH runs on the main thread so KeyboardInterrupt propagates cleanly.
    print("[*] PhantomPot — multi-protocol honeypot starting …")
    print("[*] Press Ctrl-C to stop all listeners.\n")
    ssh_server.serve_forever()


if __name__ == "__main__":
    main()
