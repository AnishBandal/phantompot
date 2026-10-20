#!/usr/bin/env python3
"""
Test HTTP logging by simulating requests and checking logs
"""

import sys
import json
import time
sys.path.insert(0, 'src')

from core.logger import get_default_logger

print("\n" + "=" * 70)
print("  HTTP LOGGING TEST")
print("=" * 70)

logger = get_default_logger()
print(f"\nLogging to: {logger.sessions_log_path}")

# Simulate an HTTP GET request
http_get_event = {
    "session_id": "http-test-get-001",
    "protocol": "http",
    "source_ip": "192.168.1.100",
    "timestamp": time.time(),
    "method": "GET",
    "path": "/",
    "headers": {"User-Agent": "Mozilla/5.0", "Accept": "text/html"},
    "payload_raw": None,
    "payload_parsed": None,
    "login_attempt": False,
}

# Simulate an HTTP POST login request
http_post_event = {
    "session_id": "http-test-post-002",
    "protocol": "http",
    "source_ip": "192.168.1.101",
    "timestamp": time.time(),
    "method": "POST",
    "path": "/login",
    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
    "payload_raw": "username=admin&password=secret123",
    "payload_parsed": {"username": "admin", "password": "secret123"},
    "login_attempt": True,
    "login_info": {"username": "admin", "password": "secret123"},
}

print("\n1. Logging test HTTP GET request...")
logger.log_session(http_get_event)
print("   ✓ GET request logged")

print("\n2. Logging test HTTP POST (login) request...")
logger.log_session(http_post_event)
print("   ✓ POST request logged")

print("\n3. Reading back logged events from sessions.jsonl...")
with open(logger.sessions_log_path, 'r') as f:
    lines = f.readlines()
    
# Find our test events
get_found = False
post_found = False

for line in lines:
    try:
        event = json.loads(line)
        if event.get('session_id') == 'http-test-get-001':
            get_found = True
            print(f"   ✓ GET event found: {event['method']} {event['path']}")
        elif event.get('session_id') == 'http-test-post-002':
            post_found = True
            print(f"   ✓ POST event found: {event['method']} {event['path']} (login_attempt={event.get('login_attempt')})")
    except json.JSONDecodeError:
        pass

if get_found and post_found:
    print("\n" + "=" * 70)
    print("  ✓ HTTP LOGGING IS WORKING CORRECTLY")
    print("=" * 70)
    print("\nAll HTTP requests are properly logged to sessions.jsonl")
else:
    print("\n" + "=" * 70)
    print("  ✗ HTTP LOGGING TEST FAILED")
    print("=" * 70)
    if not get_found:
        print("  - GET request not found in logs")
    if not post_found:
        print("  - POST request not found in logs")

print()
