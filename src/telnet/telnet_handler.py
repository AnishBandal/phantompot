"""Telnet honeypot connection handler.

Simulates a Linux login prompt via raw TCP with minimal Telnet
option negotiation (IAC sequences are consumed but not fully
negotiated). Accepts all credentials, drops into the shared
fake shell, and logs every attempt and command.
"""

from __future__ import annotations

import socket
from typing import Optional

from core.logger import HoneypotLogger
from core.session_finalizer import finalize_and_log_session
from core.session_manager import SessionManager
from ssh.command_classifier import is_suspicious_command
from ssh.fake_shell import ShellSession, handle_fake_command


# ---------------------------------------------------------------------------
# Telnet protocol constants (RFC 854)
# ---------------------------------------------------------------------------

IAC = 0xFF   # Interpret As Command
WILL = 0xFB
WONT = 0xFC
DO = 0xFD
DONT = 0xFE
SB = 0xFA    # Subnegotiation begin
SE = 0xF0    # Subnegotiation end
ECHO = 0x01
SUPPRESS_GA = 0x03

_MOTD = (
    "\r\n"
    "Ubuntu 22.04.3 LTS\r\n"
    "Kernel 5.15.0-91-generic\r\n"
    "\r\n"
)

# ---------------------------------------------------------------------------
# Low-level socket helpers
# ---------------------------------------------------------------------------

def _send(sock: socket.socket, data: str) -> None:
    try:
        sock.sendall(data.encode("utf-8", errors="ignore"))
    except OSError:
        pass


def _send_raw(sock: socket.socket, data: bytes) -> None:
    try:
        sock.sendall(data)
    except OSError:
        pass


def _negotiate(sock: socket.socket) -> None:
    """Send minimal Telnet option negotiation so terminals behave."""
    # WILL ECHO   — server will echo characters
    # WILL SUPPRESS-GO-AHEAD — suppress go-ahead signals
    # DO   SUPPRESS-GO-AHEAD — ask client to suppress go-ahead
    _send_raw(sock, bytes([IAC, WILL, ECHO, IAC, WILL, SUPPRESS_GA, IAC, DO, SUPPRESS_GA]))


def _recv_line(
    sock: socket.socket,
    timeout: float = 60.0,
    echo: bool = False,
    mask: bool = False,
) -> Optional[str]:
    """Read one line, stripping IAC option bytes and handling backspace.

    Args:
        echo:  If True, echo printable characters back to the client.
        mask:  If True, echo '*' instead of the actual character (password fields).
    """
    sock.settimeout(timeout)
    buf = bytearray()

    try:
        while True:
            byte_data = sock.recv(1)
            if not byte_data:
                return None

            b = byte_data[0]

            # ----- Telnet IAC option: consume 3-byte sequence -----
            if b == IAC:
                option = sock.recv(2)          # verb + option code
                # SB (subnegotiation) needs to drain until IAC SE
                if option and option[0] == SB:
                    while True:
                        nb = sock.recv(1)
                        if not nb:
                            break
                        if nb[0] == IAC:
                            sock.recv(1)       # consume SE
                            break
                continue

            # ----- End of line -----
            if b in (0x0A, 0x0D):             # LF or CR
                _send(sock, "\r\n")
                break

            # ----- Ctrl-C -----
            if b == 0x03:
                return "exit"

            # ----- Backspace / DEL -----
            if b in (0x08, 0x7F):
                if buf:
                    buf.pop()
                    if echo or mask:
                        _send(sock, "\b \b")
                continue

            # ----- Printable ASCII -----
            if 0x20 <= b <= 0x7E:
                buf.append(b)
                if echo:
                    _send(sock, chr(b))
                elif mask:
                    _send(sock, "*")
                if len(buf) > 4096:
                    break
                continue

            # ignore other control bytes

    except (OSError, socket.timeout):
        return None

    return buf.decode("utf-8", errors="ignore").strip()


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def handle_telnet_client(
    client_socket: socket.socket,
    client_ip: str,
    session_manager: SessionManager,
    logger: HoneypotLogger,
) -> None:
    """Handle a single Telnet client connection end-to-end."""
    session_id = session_manager.create_session(ip=client_ip, protocol="telnet")

    try:
        _negotiate(client_socket)
        _run_telnet_session(client_socket, client_ip, session_id, session_manager, logger)
    except Exception as exc:
        session_manager.set_connection_state(session_id, "incomplete")
        logger.log_error(
            f"telnet_handler session_id={session_id} ip={client_ip} error={exc}"
        )
    finally:
        try:
            finalize_and_log_session(
                session_id=session_id,
                client_ip=client_ip,
                protocol_tag="[Telnet]",
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


def _run_telnet_session(
    sock: socket.socket,
    client_ip: str,
    session_id: str,
    session_manager: SessionManager,
    logger: HoneypotLogger,
) -> None:
    """Walk through the fake login + shell interaction."""
    _send(sock, _MOTD)

    # ---- Decoy credential policy (bounded retries; no password persistence) ----
    username = ""
    authenticated = False
    for attempt in range(3):
        _send(sock, "login: ")
        username = _recv_line(sock, timeout=30.0, echo=True) or ""
        _send(sock, "Password: ")
        password = _recv_line(sock, timeout=30.0, echo=False, mask=False) or ""
        authenticated = session_manager.authenticate(session_id, username, password)
        if authenticated:
            break
        _send(sock, "\r\nLogin incorrect\r\n")
    if not authenticated:
        session_manager.set_connection_state(session_id, "incomplete")
        return

    _send(sock, "\r\nLast login: simulated decoy environment\r\n")
    
    # Create shell session with the authenticated username
    shell = ShellSession(username)
    _send(sock, shell.get_prompt())

    # ---- Fake shell ----
    while True:
        command = _recv_line(sock, timeout=300.0, echo=True)
        if command is None:
            break

        if command.lower() in {"exit", "quit", "logout"}:
            _send(sock, "logout\r\n")
            break

        suspicious = is_suspicious_command(command)
        session_manager.add_command(
            session_id=session_id,
            command=command,
            is_suspicious=suspicious,
        )

        response = handle_fake_command(shell, command)
        if response:
            _send(sock, response + "\r\n")
        _send(sock, shell.get_prompt())
