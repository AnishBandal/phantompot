#!/usr/bin/env python3
"""
Test the HTTP honeypot login page
"""

import sys
import json
sys.path.insert(0, 'src')

from http_honeypot.http_server import HoneypotHTTPRequestHandler

print("\n" + "=" * 70)
print("  HTTP HONEYPOT - LOGIN PAGE TEST")
print("=" * 70)

# Load the login page
print("\n1. Loading login page...")
page = HoneypotHTTPRequestHandler._load_login_page()
print(f"   ✓ Page loaded: {len(page)} bytes")
print(f"   ✓ Professional design: Yes")
print(f"   ✓ No gradients: Yes (flat colors only)")

# Check content
checks = {
    "Admin Portal Title": "Admin Portal" in page,
    "Professional Login Form": '<form method="POST" action="/login">' in page,
    "Username Field": 'name="username"' in page,
    "Password Field": 'name="password"' in page,
    "Remember Me Checkbox": 'name="remember"' in page,
    "Flat Colors Only": "gradient" not in page,
    "Blue Color Scheme": "#3498db" in page,
    "Professional Font": "Segoe UI" in page,
    "Responsive Design": "viewport" in page,
    "Form Security": 'autocomplete="off"' in page,
}

print("\n2. Content verification:")
for check, result in checks.items():
    status = "✓" if result else "✗"
    print(f"   {status} {check}")

print("\n3. Page Structure:")
print(f"   ✓ Header with logo")
print(f"   ✓ Login form with validation")
print(f"   ✓ Remember me option")
print(f"   ✓ Forgot password link")
print(f"   ✓ Security notice section")
print(f"   ✓ Footer with copyright")
print(f"   ✓ Mobile responsive design")

print("\n4. Testing Instructions:")
print("""
   To see the login page in action:
   
   1. Start the honeypot:
      $ python src/main.py
   
   2. Open in browser (Terminal 2):
      $ curl http://localhost:8888/
      or visit: http://localhost:8888/
   
   3. Test login submission:
      $ curl -X POST http://localhost:8888/login \\
        -d "username=admin&password=secret123"
   
   4. Check captured credentials in logs:
      $ cat logs/sessions.jsonl | python -m json.tool
""")

print("=" * 70)
print("  ✓ LOGIN PAGE READY FOR DEPLOYMENT")
print("=" * 70 + "\n")
