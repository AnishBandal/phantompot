#!/usr/bin/env python3
"""
Diagnose why HTTP records don't appear in dashboard
"""

import sys
import json
from pathlib import Path
sys.path.insert(0, 'src')

print("\n" + "=" * 80)
print("  HTTP DASHBOARD VISIBILITY DIAGNOSIS")
print("=" * 80)

# Check what's in the log file
log_file = Path("logs/sessions.jsonl")

print("\n1. LOG FILE STRUCTURE CHECK:")
print(f"   Log file: {log_file}")
print(f"   Exists: {log_file.exists()}")

if log_file.exists():
    print(f"   Size: {log_file.stat().st_size} bytes")
    
    # Sample a few records
    protocols_found = {}
    ssh_sample = None
    http_sample = None
    
    with open(log_file, 'r') as f:
        for line in f:
            if line.strip():
                try:
                    record = json.loads(line)
                    protocol = record.get('protocol', 'unknown')
                    
                    if protocol not in protocols_found:
                        protocols_found[protocol] = 0
                    protocols_found[protocol] += 1
                    
                    if protocol == 'ssh' and ssh_sample is None:
                        ssh_sample = record
                    elif protocol == 'http' and http_sample is None:
                        http_sample = record
                except json.JSONDecodeError:
                    pass
    
    print(f"\n   Protocols in log:")
    for protocol, count in sorted(protocols_found.items()):
        print(f"     - {protocol}: {count} records")

# Compare record structures
print("\n2. RECORD STRUCTURE COMPARISON:")

print("\n   SSH/Connection-based record:")
if ssh_sample:
    print(f"   Key fields present:")
    critical_fields = ['session_id', 'protocol', 'duration', 'login_attempts', 'commands', 
                      'anomaly', 'anomaly_score', 'severity', 'ip', 'start_time']
    for field in critical_fields:
        has_field = field in ssh_sample
        status = "✓" if has_field else "✗"
        print(f"     {status} {field}")
else:
    print("     ℹ No SSH records found in log")

print("\n   HTTP/Request-based record:")
if http_sample:
    print(f"   Key fields present:")
    http_fields = list(http_sample.keys())
    print(f"     Fields: {', '.join(http_fields)}")
    
    # Check for dashboard-required fields
    critical_fields = ['duration', 'login_attempts', 'commands', 'anomaly', 'anomaly_score', 'severity']
    missing = [f for f in critical_fields if f not in http_sample]
    
    if missing:
        print(f"\n   ✗ Missing dashboard fields: {', '.join(missing)}")
        print(f"\n   Why HTTP doesn't show in dashboard:")
        print(f"   - Dashboard expects 'duration' field")
        print(f"   - Dashboard expects 'commands' array")
        print(f"   - Dashboard expects 'login_attempts' array")
        print(f"   - HTTP events are per-request, not sessions")
        print(f"   - HTTP events missing anomaly fields to trigger ML enrichment")
else:
    print("     ℹ No HTTP records found in log")

# Show the actual HTTP record structure
print("\n3. HTTP RECORD STRUCTURE:")
if http_sample:
    print(f"   {json.dumps(http_sample, indent=4)}")
else:
    print("   ℹ No sample HTTP record to display")

# Show what dashboard expects
print("\n4. DASHBOARD EXPECTATIONS:")
print("""
   The dashboard's build_dataframe() function expects:
   
   ✓ Required fields:
     - protocol: str (ssh, ftp, telnet, http)
     - duration: float (session length in seconds)
     - login_attempts: list (authentication attempts)
     - commands: list (executed commands)
     - ip or source_ip: str (source address)
     - start_time or timestamp: datetime
     
   ✓ Optional (auto-enriched):
     - anomaly: str (attack/normal)
     - anomaly_score: float
     - severity: str (high/medium/low)
     - total_login_attempts: calculated from login_attempts[]
     - commands_count: calculated from commands[]
     
   HTTP records use:
     - session_id, protocol, source_ip, timestamp, method, path
     - headers, payload_raw, payload_parsed, login_attempt, login_info
   
   Missing: duration, login_attempts[], commands[]
""")

print("\n5. SOLUTION:")
print("""
   Option A: Convert HTTP to session format
   - Group HTTP requests into logical sessions
   - Track credentials as login_attempts[]
   - Track payloads as commands[]
   - Add duration field
   
   Option B: Update dashboard to handle HTTP
   - Recognize HTTP per-request format
   - Generate synthetic session containers
   - Enrich HTTP events with ML predictions
   
   RECOMMENDATION: Option A
   - Makes HTTP consistent with other protocols
   - Dashboard works without modification
   - Better for SIEM analysis and KPI metrics
""")

print("\n" + "=" * 80)
print("  DIAGNOSIS COMPLETE")
print("=" * 80 + "\n")
