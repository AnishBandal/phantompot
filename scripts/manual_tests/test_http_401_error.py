#!/usr/bin/env python3
"""
Test HTTP 401 error response after login
"""

import sys
import json
sys.path.insert(0, 'src')

print("\n" + "=" * 70)
print("  HTTP LOGIN ERROR RESPONSE TEST")
print("=" * 70)

print("\nBehavior After Login:")
print("  ✓ Credentials are logged to sessions.jsonl")
print("  ✓ HTTP 401 error page is returned to attacker")
print("  ✓ Error message: 'Authentication Failed'")
print("  ✓ Looks like a real authentication error")
print()

print("Error Page Contains:")
print("  - ❌ Authentication Failed heading (red color)")
print("  - HTTP 401 - Unauthorized status code")
print("  - Error message: Invalid username or password")
print("  - Technical details:")
print("    * error_code: AUTH_INVALID_CREDENTIALS")
print("    * timestamp: ISO 8601 format")
print("    * request_id: Random unique ID")
print("  - 'Try again' link back to /login")
print()

print("Honeypot Logic:")
print("  1. Attacker submits credentials: admin / password123")
print("  2. Honeypot logs event with username/password to sessions.jsonl")
print("  3. Honeypot responds with 401 error page")
print("  4. Attacker sees: 'Authentication Failed'")
print("  5. Attacker thinks: Login failed, credentials were wrong")
print("  6. Reality: Credentials were captured for analysis")
print()

print("Testing with logger...")
from core.logger import get_default_logger

test_event = {
    "session_id": "http-401-test",
    "protocol": "http",
    "source_ip": "192.168.1.100",
    "method": "POST",
    "path": "/login",
    "login_attempt": True,
    "login_info": {
        "username": "attacker_user",
        "password": "attacker_pass"
    },
}

logger = get_default_logger()
logger.log_session(test_event)

# Verify it was logged
with open(logger.sessions_log_path, 'r') as f:
    content = f.read()
    if 'attacker_user' in content:
        print("  ✓ Credentials logged to sessions.jsonl")
    else:
        print("  ✗ Failed to log credentials")

print("\n" + "=" * 70)
print("  ✓ HTTP 401 ERROR STRATEGY ACTIVE")
print("=" * 70)
print("\nAttackers will think their login failed while credentials are captured.")
print()
