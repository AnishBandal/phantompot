"""Threaded TCP Telnet honeypot server bootstrap."""

from __future__ import annotations

import socket
import threading

from core.logger import HoneypotLogger
from core.session_manager import SessionManager
from telnet.telnet_handler import handle_telnet_client


class TelnetHoneypotServer:
    """Listen for Telnet clients and dispatch each connection to a worker thread."""

    def __init__(
        self,
        host: str,
        port: int,
        logger: HoneypotLogger,
        session_manager: SessionManager,
    ) -> None:
        self.host = host
        self.port = int(port)
        self.logger = logger
        self.session_manager = session_manager

    def serve_forever(self) -> None:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(100)

        print(f"[+] Telnet honeypot listening on {self.host}:{self.port}")

        try:
            while True:
                client_socket, client_addr = server_socket.accept()
                ip = client_addr[0]

                worker = threading.Thread(
                    target=handle_telnet_client,
                    args=(client_socket, ip, self.session_manager, self.logger),
                    daemon=True,
                )
                worker.start()
        except KeyboardInterrupt:
            print("\n[!] Stopping Telnet honeypot")
        finally:
            server_socket.close()
