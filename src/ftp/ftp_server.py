"""Simple FTP honeypot server (fake service) implemented with sockets.

Listens on port 2121 by default, accepts any USER/PASS, logs credentials
via `log_event`, and returns fake FTP responses without touching the real
filesystem or running real services.
"""

from __future__ import annotations

import socket
import threading
from typing import Optional

try:
    from ..core.logger import log_event
    from ..core.utils import generate_session_id, utc_now_iso
    from ..core.logger import get_default_logger
    from ..session_manager import SessionManager
except Exception:
    try:
        from src.core.logger import log_event
        from src.core.utils import generate_session_id, utc_now_iso
        from src.core.logger import get_default_logger
        from src.core.session_manager import SessionManager
    except Exception:
        def log_event(payload):
            return


_RECV_BUFFER = 4096
_BACKLOG = 50




class FTPHoneypotServer:
    """Compatibility wrapper exposing `serve_forever()` used by the main app.

    This server accepts connections and dispatches each client to
    `ftp_handler.handle_ftp_client` in a dedicated thread. It expects a
    `logger` and `session_manager` object compatible with the rest of the
    application.
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 2121,
        logger=None,
        session_manager=None,
    ) -> None:
        self.host = host
        self.port = int(port)
        self.logger = logger
        self.session_manager = session_manager
        self._sock: Optional[socket.socket] = None
        self._running = threading.Event()

    def serve_forever(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(_BACKLOG)
        self._running.set()
        
        print(f"[+] FTP honeypot listening on {self.host}:{self.port}")

        try:
            while self._running.is_set():
                try:
                    client, addr = self._sock.accept()
                    t = threading.Thread(
                        target=self._handle_client_thread,
                        args=(client, addr),
                        daemon=True,
                    )
                    t.start()
                except OSError:
                    break
                except Exception:
                    continue
        finally:
            self.shutdown()

    def shutdown(self) -> None:
        self._running.clear()
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass

    def _handle_client_thread(self, client_sock: socket.socket, addr) -> None:
        client_ip = addr[0]
        try:
            from .ftp_handler import handle_ftp_client

            # Ensure a logger and session_manager are available; prefer
            # instances passed into the server, otherwise fall back to
            # module-level defaults so the standalone server still logs.
            logger = self.logger if self.logger is not None else get_default_logger()
            session_manager = self.session_manager if self.session_manager is not None else SessionManager(event_sink=logger.log_event)

            handle_ftp_client(
                client_socket=client_sock,
                client_ip=client_ip,
                session_manager=session_manager,
                logger=logger,
            )
        except Exception:
            try:
                client_sock.close()
            except Exception:
                pass


def run_server(host: str = "0.0.0.0", port: int = 2121) -> None:
    # Start a standalone FTP server using default logger and session manager.
    try:
        logger = get_default_logger()
    except Exception:
        logger = None

    try:
        session_manager = SessionManager(event_sink=logger.log_event if logger is not None else None)
    except Exception:
        session_manager = None

    server = FTPHoneypotServer(host=host, port=port, logger=logger, session_manager=session_manager)
    server.serve_forever()


if __name__ == "__main__":
    run_server()
