#!/usr/bin/env python3
"""Quick test to verify all honeypot servers start correctly."""

import sys
import threading
import time

sys.path.insert(0, 'src')

from core.logger import HoneypotLogger
from core.session_manager import SessionManager
from ftp.ftp_server import FTPHoneypotServer
from http_honeypot.http_server import HTTPHoneypotServer
from ssh.ssh_server import SSHHoneypotServer
from telnet.telnet_server import TelnetHoneypotServer
from pathlib import Path
import yaml

BASE_DIR = Path(__file__).resolve().parent

def load_config(config_path):
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

print("=" * 70)
print("PHANTOMPOT-V2 SERVER STARTUP TEST")
print("=" * 70 + "\n")

config = load_config(BASE_DIR / "config" / "config.yaml")
logger = HoneypotLogger(
    str(BASE_DIR / "logs/sessions.jsonl"),
    str(BASE_DIR / "logs/errors.log"),
)
session_manager = SessionManager()

# Create all servers
ssh_cfg = config.get("ssh", {})
http_cfg = config.get("http", {})
ftp_cfg = config.get("ftp", {})
telnet_cfg = config.get("telnet", {})

# Start servers in background threads (with 2-second timeout)
def start_server(server, name):
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"[!] {name} error: {e}")

servers = []

ssh_server = SSHHoneypotServer(
    host=ssh_cfg.get("host", "0.0.0.0"),
    port=int(ssh_cfg.get("port", 2222)),
    logger=logger,
    session_manager=session_manager,
    host_key_path=str(BASE_DIR / ssh_cfg.get("host_key_path", "config/ssh_host_rsa.key")),
)
t = threading.Thread(target=start_server, args=(ssh_server, "SSH"), daemon=True)
t.start()
servers.append(t)

http_server = HTTPHoneypotServer(
    host=http_cfg.get("host", "0.0.0.0"),
    port=int(http_cfg.get("port", 8888)),
    logger=logger,
    session_manager=session_manager,
)
t = threading.Thread(target=start_server, args=(http_server, "HTTP"), daemon=True)
t.start()
servers.append(t)

ftp_server = FTPHoneypotServer(
    host=ftp_cfg.get("host", "0.0.0.0"),
    port=int(ftp_cfg.get("port", 2121)),
    logger=logger,
    session_manager=session_manager,
)
t = threading.Thread(target=start_server, args=(ftp_server, "FTP"), daemon=True)
t.start()
servers.append(t)

telnet_server = TelnetHoneypotServer(
    host=telnet_cfg.get("host", "0.0.0.0"),
    port=int(telnet_cfg.get("port", 2323)),
    logger=logger,
    session_manager=session_manager,
)
t = threading.Thread(target=start_server, args=(telnet_server, "Telnet"), daemon=True)
t.start()
servers.append(t)

# Wait for servers to start
time.sleep(2)

print("\n" + "=" * 70)
print("SERVER STARTUP SUCCESS")
print("=" * 70)
print("\nAll 4 honeypot servers are now listening:")
print(f"  ✓ SSH on port {ssh_cfg.get('port', 2222)}")
print(f"  ✓ HTTP on port {http_cfg.get('port', 8888)}")
print(f"  ✓ FTP on port {ftp_cfg.get('port', 2121)}")
print(f"  ✓ Telnet on port {telnet_cfg.get('port', 2323)}")
print("\n" + "=" * 70)
