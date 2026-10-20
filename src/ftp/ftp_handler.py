"""FTP honeypot connection handler.

Simulates a ProFTPD-style FTP server. Accepts all credentials,
responds to common FTP commands with fake data, and logs every
login attempt and command to the shared session/logging pipeline.
"""

from __future__ import annotations

import socket
from typing import Optional

from core.logger import HoneypotLogger
from core.session_finalizer import finalize_and_log_session
from core.session_manager import SessionManager
from core.utils import utc_now_iso


# ---------------------------------------------------------------------------
# Fake filesystem used for LIST / NLST responses
# ---------------------------------------------------------------------------

_FAKE_FILE_LIST = (
    "-rw-r--r-- 1 admin admin  1024 Apr  7 09:00 readme.txt\r\n"
    "-rw-r--r-- 1 admin admin  2048 Apr  6 18:22 backup.tar.gz\r\n"
    "drwxr-xr-x 2 admin admin  4096 Apr  5 11:10 uploads\r\n"
)

_FAKE_SYSTEM = "215 UNIX Type: L8"
_FAKE_PWD = '257 "/home/admin" is the current directory'
_BANNER = "220 ProFTPD 1.3.7 Server (FTP Honeypot) [127.0.0.1]\r\n"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _send(sock: socket.socket, msg: str) -> None:
    """Send an FTP response line (CRLF-terminated)."""
    if not msg.endswith("\r\n"):
        msg += "\r\n"
    try:
        sock.sendall(msg.encode("utf-8", errors="ignore"))
    except OSError:
        pass


def _recv_line(sock: socket.socket, timeout: float = 120.0) -> Optional[str]:
    """Read one CRLF-terminated line from the socket."""
    sock.settimeout(timeout)
    buf = bytearray()
    try:
        while True:
            byte = sock.recv(1)
            if not byte:
                return None
            buf.extend(byte)
            if buf.endswith(b"\n"):
                return buf.decode("utf-8", errors="ignore").strip()
            if len(buf) > 4096:
                return buf.decode("utf-8", errors="ignore").strip()
    except (OSError, socket.timeout):
        return None


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def handle_ftp_client(
    client_socket: socket.socket,
    client_ip: str,
    session_manager: SessionManager,
    logger: HoneypotLogger,
) -> None:
    """Handle a single FTP client connection end-to-end."""
    session_id = session_manager.create_session(ip=client_ip, protocol="ftp")

    try:
        _send(client_socket, _BANNER)
        _run_ftp_session(client_socket, client_ip, session_id, session_manager, logger)
    except Exception as exc:
        logger.log_error(
            f"ftp_handler session_id={session_id} ip={client_ip} error={exc}"
        )
    finally:
        try:
            finalize_and_log_session(
                session_id=session_id,
                client_ip=client_ip,
                protocol_tag="[FTP]",
                session_manager=session_manager,
                logger=logger,
            )
        except Exception as exc:
            logger.log_error(
                f"session_finalize session_id={session_id} ip={client_ip} error={exc}"
            )

        try:
            client_socket.close()
        except OSError:
            pass


def _run_ftp_session(
    sock: socket.socket,
    client_ip: str,
    session_id: str,
    session_manager: SessionManager,
    logger: HoneypotLogger,
) -> None:
    """State machine that walks through a fake FTP conversation."""
    username: str = ""
    authenticated: bool = False
    current_dir = "/home/admin"

    while True:
        line = _recv_line(sock)
        if line is None:
            break

        parts = line.split(None, 1)
        if not parts:
            continue

        cmd = parts[0].upper()
        arg = parts[1] if len(parts) > 1 else ""

        # ---- pre-auth commands -----------------------------------------
        if cmd == "USER":
            username = arg
            _send(sock, f"331 Password required for {username}")

        elif cmd == "PASS":
            authenticated = session_manager.authenticate(session_id, username, arg)
            if authenticated:
                _send(sock, f"230 User {username} logged in")
            else:
                _send(sock, "530 Login incorrect")

        elif cmd == "QUIT":
            _send(sock, "221 Goodbye.")
            break

        elif cmd == "SYST":
            _send(sock, _FAKE_SYSTEM)
            session_manager.add_command(
                session_id=session_id, command="SYST", is_suspicious=False
            )

        elif cmd == "FEAT":
            _send(sock, "211-Features:\r\n PASV\r\n UTF8\r\n211 End")
            session_manager.add_command(
                session_id=session_id, command="FEAT", is_suspicious=False
            )

        elif cmd == "NOOP":
            _send(sock, "200 NOOP ok")
            session_manager.add_command(
                session_id=session_id, command="NOOP", is_suspicious=False
            )

        elif cmd in {"PWD", "CWD", "LIST", "NLST", "RETR", "STOR", "APPE", "DELE", "MKD", "RMD"} and not authenticated:
            _send(sock, "530 Please login with USER and PASS")
            session_manager.add_command(
                session_id=session_id,
                command=f"{cmd} {arg}".strip(),
                is_suspicious=cmd in {"STOR", "APPE", "DELE", "MKD", "RMD"},
                outcome="blocked_auth_required",
            )

        # ---- authenticated operations over an in-memory fake filesystem ------
        elif cmd == "PWD":
            _send(sock, f'257 "{current_dir}" is the current directory')
            session_manager.add_command(
                session_id=session_id, command="PWD", is_suspicious=False
            )

        elif cmd == "CWD":
            target = arg.replace("\\", "/").rstrip("/") or "/"
            if not target.startswith("/"):
                target = f"{current_dir.rstrip('/')}/{target}"
            allowed_dirs = {"/", "/home", "/home/admin", "/home/admin/uploads", "/tmp", "/var", "/var/log"}
            if target in allowed_dirs:
                current_dir = target
                _send(sock, f"250 Directory changed to {current_dir}")
                outcome = "simulated_directory_changed"
            else:
                _send(sock, "550 Directory not found in decoy filesystem")
                outcome = "blocked"
            session_manager.add_command(
                session_id=session_id, command=f"CWD {arg}", is_suspicious=outcome == "blocked", outcome=outcome,
                event_metadata={"simulated_filesystem": True},
            )

        elif cmd in ("LIST", "NLST"):
            # Honeypot: pretend to open a data channel but never does —
            # just send the listing inline (many scanners only check codes).
            _send(sock, "150 Here comes the directory listing.")
            # Fake data on control channel to satisfy simple scanners.
            _send(sock, _FAKE_FILE_LIST)
            _send(sock, "226 Directory send OK.")
            session_manager.add_command(
                session_id=session_id, command=cmd, is_suspicious=False, outcome="simulated_listing_returned",
                event_metadata={"simulated_filesystem": True},
            )

        elif cmd == "TYPE":
            _send(sock, f"200 Type set to {arg}")
            session_manager.add_command(
                session_id=session_id, command=f"TYPE {arg}", is_suspicious=False
            )

        elif cmd == "PASV":
            # Return a deliberately unreachable address so no real data
            # channel is established.
            _send(sock, "227 Entering Passive Mode (127,0,0,1,39,15)")
            session_manager.add_command(
                session_id=session_id, command="PASV", is_suspicious=False
            )

        elif cmd == "PORT":
            _send(sock, "200 PORT command successful")
            session_manager.add_command(
                session_id=session_id, command=f"PORT {arg}", is_suspicious=False
            )

        elif cmd in ("RETR", "STOR", "APPE"):
            fake_files = {
                "readme.txt": "Maintenance window: Sunday 02:00 UTC.\r\n",
                "backup.tar.gz": "[simulated archive contents unavailable]\r\n",
            }
            if cmd == "RETR" and authenticated and arg in fake_files:
                _send(sock, "150 Opening simulated decoy data transfer")
                _send(sock, fake_files[arg])
                _send(sock, "226 Simulated transfer complete")
                outcome = "simulated_decoy_file_returned"
            else:
                _send(sock, f"550 {arg}: Access denied")
                outcome = "blocked"
            is_sus = cmd in ("STOR", "APPE") or outcome == "blocked"
            session_manager.add_command(
                session_id=session_id,
                command=f"{cmd} {arg}",
                is_suspicious=is_sus,
                outcome=outcome,
                event_metadata={"simulated_file": cmd == "RETR" and arg in fake_files},
            )

        elif cmd == "DELE":
            _send(sock, f"550 {arg}: Permission denied")
            session_manager.add_command(
                session_id=session_id,
                command=f"DELE {arg}",
                is_suspicious=True,
            )

        elif cmd == "MKD":
            _send(sock, f"550 {arg}: Permission denied")
            session_manager.add_command(
                session_id=session_id,
                command=f"MKD {arg}",
                is_suspicious=True,
            )

        elif cmd == "RMD":
            _send(sock, f"550 {arg}: Permission denied")
            session_manager.add_command(
                session_id=session_id,
                command=f"RMD {arg}",
                is_suspicious=True,
            )

        elif cmd in ("SITE", "EXEC"):
            _send(sock, "502 Command not implemented")
            session_manager.add_command(
                session_id=session_id,
                command=f"{cmd} {arg}",
                is_suspicious=True,
            )

        else:
            _send(sock, f"502 Command '{cmd}' not implemented")
            session_manager.add_command(
                session_id=session_id,
                command=f"{cmd} {arg}".strip(),
                is_suspicious=False,
            )
