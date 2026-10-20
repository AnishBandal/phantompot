"""SSH connection/session handling logic."""

from __future__ import annotations

import socket
import threading
from typing import Optional

import paramiko

from core.logger import HoneypotLogger
from core.session_finalizer import finalize_and_log_session
from core.session_manager import SessionManager
from ssh.command_classifier import is_suspicious_command
from ssh.fake_shell import ShellSession, handle_fake_command


class AcceptAllSSHServer(paramiko.ServerInterface):
    """Paramiko server interface that accepts all credentials."""

    def __init__(self, session_manager: SessionManager, session_id: str) -> None:
        self.session_manager = session_manager
        self.session_id = session_id
        self.event = threading.Event()
        self.username = "user"  # Store username for use in shell prompt

    def check_auth_password(self, username: str, password: str) -> int:
        self.username = username  # Store the username
        accepted = self.session_manager.authenticate(self.session_id, username, password)
        return paramiko.AUTH_SUCCESSFUL if accepted else paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        self.event.set()
        return True

    def check_channel_pty_request(
        self,
        channel: paramiko.Channel,
        term: str,
        width: int,
        height: int,
        pixelwidth: int,
        pixelheight: int,
        modes: bytes,
    ) -> bool:
        return True



def _safe_recv_line(channel: paramiko.Channel, timeout: float = 300.0) -> Optional[str]:
    channel.settimeout(timeout)
    data = bytearray()

    while True:
        chunk = channel.recv(1)
        if not chunk:
            return None

        if chunk in (b"\n", b"\r"):
            channel.send("\r\n")
            break

        if chunk == b"\x03":
            return "exit"

        # Handle backspace/delete so edited commands are recorded correctly.
        if chunk in (b"\x08", b"\x7f"):
            if data:
                data.pop()
                channel.send("\b \b")
            continue

        # Keep shell interaction realistic by echoing printable characters.
        if 32 <= chunk[0] <= 126:
            data.extend(chunk)
            channel.send(chunk.decode("utf-8", errors="ignore"))
            if len(data) > 4096:
                break
            continue

        # Ignore other control characters.
        continue

    return data.decode("utf-8", errors="ignore").strip()



def handle_ssh_client(
    client_socket: socket.socket,
    client_ip: str,
    host_key: paramiko.PKey,
    session_manager: SessionManager,
    logger: HoneypotLogger,
) -> None:
    session_id = session_manager.create_session(ip=client_ip, protocol="ssh")
    transport: Optional[paramiko.Transport] = None

    try:
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(host_key)
        server = AcceptAllSSHServer(session_manager=session_manager, session_id=session_id)

        transport.start_server(server=server)
        channel = transport.accept(20)
        if channel is None:
            session_manager.set_connection_state(session_id, "incomplete")
            return

        server.event.wait(10)
        channel.send("Welcome to Ubuntu 22.04 LTS\r\n")
        
        # Create shell session with the authenticated username
        shell = ShellSession(server.username)
        channel.send(shell.get_prompt())

        while True:
            command = _safe_recv_line(channel)
            if command is None:
                break

            if command.lower() in {"exit", "quit", "logout"}:
                channel.send("logout\r\n")
                break

            suspicious = is_suspicious_command(command)
            session_manager.add_command(
                session_id=session_id,
                command=command,
                is_suspicious=suspicious,
            )

            response = handle_fake_command(shell, command)
            if response:
                channel.send(response + "\r\n")
            channel.send(shell.get_prompt())

    except Exception as exc:
        session_manager.set_connection_state(session_id, "incomplete")
        logger.log_error(f"ssh_handler session_id={session_id} ip={client_ip} error={exc}")
    finally:
        try:
            finalize_and_log_session(
                session_id=session_id,
                client_ip=client_ip,
                protocol_tag="[SSH]",
                session_manager=session_manager,
                logger=logger,
            )
        except Exception as exc:
            logger.log_error(f"session_finalize session_id={session_id} ip={client_ip} error={exc}")

        if transport is not None:
            transport.close()

        try:
            client_socket.close()
        except Exception:
            pass
