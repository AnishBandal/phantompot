"""Generate SSH host key for honeypot."""
import sys
from pathlib import Path
import paramiko

key_path = Path("config/ssh_host_rsa.key")
key_path.parent.mkdir(parents=True, exist_ok=True)

# Generate RSA key
key = paramiko.RSAKey.generate(2048)
key.write_private_key_file(str(key_path))

print(f"[✓] SSH host key generated: {key_path}")
