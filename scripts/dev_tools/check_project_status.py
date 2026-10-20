#!/usr/bin/env python3
"""Check project status and completeness."""

import os
import sys

# Check existence of key files
files_to_check = {
    'SSH': ['src/ssh/ssh_server.py', 'src/ssh/ssh_handler.py', 'src/ssh/fake_shell.py'],
    'HTTP': ['src/http/http_server.py', 'src/http/request_handler.py'],
    'FTP': ['src/ftp/ftp_server.py', 'src/ftp/ftp_handler.py'],
    'Telnet': ['src/telnet/telnet_server.py', 'src/telnet/telnet_handler.py'],
    'ML': ['src/ml/predict.py', 'models/isolation_forest.pkl', 'models/scaler.pkl'],
    'KPI': ['src/core/kpi_metrics.py', 'scripts/evaluate_objective4.py'],
    'Logging': ['src/core/logger.py', 'src/core/session_manager.py'],
}

print('=' * 70)
print('PROJECT OBJECTIVE CHECKLIST')
print('=' * 70)

for objective, files in files_to_check.items():
    print(f'\n{objective}:')
    all_exist = True
    for f in files:
        exists = os.path.isfile(f)
        status = '✓' if exists else '✗'
        print(f'  {status} {f}')
        if not exists:
            all_exist = False
    status_str = 'COMPLETE' if all_exist else 'INCOMPLETE'
    print(f'  Status: {status_str}')

print('\n' + '=' * 70)

# Check main.py imports
print('\nMAIN.PY IMPORT CHECK:')
print('=' * 70)

try:
    sys.path.insert(0, '.')
    from src.ssh.ssh_server import SSHHoneypotServer
    print('✓ SSH import OK')
except Exception as e:
    print(f'✗ SSH import FAILED: {e}')

try:
    from src.http.http_server import HTTPHoneypotServer
    print('✓ HTTP import OK (src.http.http_server)')
except Exception as e:
    print(f'✗ HTTP import FAILED: {e}')

try:
    from src.http_server_pkg.http_server import HTTPHoneypotServer
    print('✓ HTTP import OK (src.http_server_pkg.http_server)')
except Exception as e:
    print(f'✗ HTTP import FAILED (attempted http_server_pkg): {type(e).__name__}')

try:
    from src.ftp.ftp_server import FTPHoneypotServer
    print('✓ FTP import OK')
except Exception as e:
    print(f'✗ FTP import FAILED: {e}')

try:
    from src.telnet.telnet_server import TelnetHoneypotServer
    print('✓ Telnet import OK')
except Exception as e:
    print(f'✗ Telnet import FAILED: {e}')

print('\n' + '=' * 70)
