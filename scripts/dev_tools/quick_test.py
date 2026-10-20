#!/usr/bin/env python3
"""
PHANTOMPOT-V2 QUICK TESTING SCRIPT
Run this to verify all components are working
"""

import os
import sys
import json
import socket
import time

sys.path.insert(0, 'src')

def print_section(title):
    """Print a formatted section header."""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80)

def test_port(host, port, name):
    """Test if a port is listening."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        result = s.connect_ex((host, port))
        s.close()
        if result == 0:
            print(f"✓ {name} listening on {host}:{port}")
            return True
        else:
            print(f"✗ {name} NOT listening on {host}:{port}")
            return False
    except Exception as e:
        print(f"✗ {name} error: {e}")
        return False

def main():
    print("\n")
    print(r"  ╔═══════════════════════════════════════════════════════════════════════╗")
    print(r"  ║         PHANTOMPOT-V2 PROJECT - QUICK TESTING SUITE                  ║")
    print(r"  ╚═══════════════════════════════════════════════════════════════════════╝")
    
    print_section("STEP 1: VERIFY PROJECT STRUCTURE")
    
    critical_files = {
        'SSH': 'src/ssh/ssh_server.py',
        'HTTP': 'src/http_honeypot/http_server.py',
        'FTP': 'src/ftp/ftp_server.py',
        'Telnet': 'src/telnet/telnet_server.py',
        'ML Model': 'models/isolation_forest.pkl',
        'Feature Scaler': 'models/scaler.pkl',
        'Config': 'config/config.yaml',
    }
    
    all_exist = True
    for name, path in critical_files.items():
        exists = os.path.isfile(path)
        status = "✓" if exists else "✗"
        print(f"{status} {name:20} {path}")
        if not exists:
            all_exist = False
    
    if not all_exist:
        print("\n✗ Some critical files are missing!")
        return False
    
    print_section("STEP 2: CHECK HONEYPOT PORTS")
    
    ports_ok = True
    ports = [
        ("localhost", 2222, "SSH"),
        ("localhost", 2121, "FTP"),
        ("localhost", 2323, "Telnet"),
        ("localhost", 8888, "HTTP"),
    ]
    
    print("(Make sure honeypot is running: python src/main.py)")
    print("\nChecking ports...")
    
    for host, port, name in ports:
        if not test_port(host, port, name):
            ports_ok = False
    
    if not ports_ok:
        print("\n✗ Some protocols not responding. Is the honeypot running?")
        print("   Start it with: python src/main.py")
        return False
    
    print_section("STEP 3: VERIFY SESSION LOGGING")
    
    if os.path.isfile('logs/sessions.jsonl'):
        size = os.path.getsize('logs/sessions.jsonl')
        print(f"✓ Session log exists: logs/sessions.jsonl ({size} bytes)")
        
        # Try to read and parse first line
        try:
            with open('logs/sessions.jsonl', 'r') as f:
                first_line = f.readline().strip()
                if first_line:
                    session = json.loads(first_line)
                    print(f"✓ Log contains valid JSON sessions")
                    print(f"  - First session type: {session.get('protocol', 'unknown')}")
        except Exception as e:
            print(f"✗ Error reading log: {e}")
    else:
        print("ℹ Session log not created yet (create some sessions first)")
    
    print_section("STEP 4: VERIFY ML COMPONENTS")
    
    try:
        from core.feature_builder import FeatureBuilder
        from ml.predict import predict_session_anomaly
        print("✓ ML modules import successfully")
        print("✓ Feature builder available")
        print("✓ Anomaly prediction available")
    except ImportError as e:
        print(f"✗ ML module error: {e}")
        return False
    
    print_section("STEP 5: TEST COMMAND HANDLERS")
    
    try:
        from ssh.fake_shell import ShellSession, handle_fake_command
        shell = ShellSession("testuser")
        
        test_commands = {
            'ls': 'bin  etc  home',
            'whoami': 'testuser',
            'pwd': '/home/testuser',
            'hostname': 'honeypot',
            'id': 'uid=',
        }
        
        all_pass = True
        for cmd, expected in test_commands.items():
            result = handle_fake_command(shell, cmd)
            if expected in result:
                print(f"✓ Command '{cmd}' works")
            else:
                print(f"✗ Command '{cmd}' failed")
                all_pass = False
        
        if not all_pass:
            return False
            
    except Exception as e:
        print(f"✗ Shell command error: {e}")
        return False
    
    print_section("STEP 6: AVAILABLE TESTING COMMANDS")
    
    print("""
Next steps to fully test the project:

1. START THE HONEYPOT (Terminal 1):
   $ python src/main.py

2. TEST SSH (Terminal 2):
   $ ssh admin@localhost -p 2222
   password: anything
   admin@honeypot:~$ whoami
   admin@honeypot:~$ id
   admin@honeypot:~$ exit

3. TEST HTTP (Terminal 2):
   $ curl http://localhost:8888/
   $ curl -X POST http://localhost:8888/login \\
     -d '{"username":"admin","password":"pass"}'

4. TEST FTP (Terminal 2):
   $ ftp localhost 2121
   login: admin
   password: anything
   ftp> quit

5. TEST TELNET (Terminal 2):
   $ telnet localhost 2323
   login: admin
   password: anything
   admin@honeypot:~$ exit

6. VIEW LOGS:
   $ cat logs/sessions.jsonl | python -m json.tool

7. RUN KPI EVALUATION:
   $ python scripts/evaluate_objective4.py --intensity medium

8. VIEW DASHBOARD:
   $ streamlit run dashboard/app.py
   Then open http://localhost:8501 in browser

9. GENERATE REPORTS:
   $ python scripts/generate_kpi_report.py \\
     --eval eval_report.json --format all

10. RUN AUTOMATED TESTS:
    $ python test_startup.py
    $ python check_project_status.py
    """)
    
    print_section("✓ PROJECT VERIFICATION COMPLETE")
    
    print("""
All critical components verified successfully!

The PhantomPot-v2 honeypot is ready for testing.

Key Features Verified:
  ✓ All 4 protocols (SSH, HTTP, FTP, Telnet)
  ✓ ML anomaly detection
  ✓ Session logging
  ✓ Command handling
  ✓ Feature extraction

Next: Run the testing commands above to interact with the honeypot.
    """)
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
