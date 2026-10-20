"""Threaded TCP SSH honeypot server bootstrap."""

from __future__ import annotations

import socket
import threading
from pathlib import Path

import paramiko

from core.logger import HoneypotLogger
from core.session_manager import SessionManager
from ssh.ssh_handler import handle_ssh_client


class SSHHoneypotServer:
    """Listen for SSH clients and dispatch each connection to a worker thread."""

    def __init__(
        self,
        host: str,
        port: int,
        logger: HoneypotLogger,
        session_manager: SessionManager,
        host_key_path: str,
    ) -> None:
        self.host = host
        self.port = int(port)
        self.logger = logger
        self.session_manager = session_manager
        self.host_key_path = host_key_path
        self.host_key = self._load_or_create_host_key(host_key_path)

    def _load_or_create_host_key(self, key_path: str) -> paramiko.RSAKey:
        path = Path(key_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        if path.exists():
            return paramiko.RSAKey.from_private_key_file(str(path))

        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(str(path))
        return key

    def serve_forever(self) -> None:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(100)

        print(f"[+] SSH honeypot listening on {self.host}:{self.port}")

        try:
            while True:
                client_socket, client_addr = server_socket.accept()
                ip = client_addr[0]

                worker = threading.Thread(
                    target=handle_ssh_client,
                    args=(
                        client_socket,
                        ip,
                        self.host_key,
                        self.session_manager,
                        self.logger,
                    ),
                    daemon=True,
                )
                worker.start()
        except KeyboardInterrupt:
            print("\n[!] Stopping SSH honeypot")
        finally:
            server_socket.close()
