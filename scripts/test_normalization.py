"""Quick normalization smoke test for PayloadAnalyzer."""
import sys
sys.path.insert(0, "src")
from http.payload_analyzer import PayloadAnalyzer

analyzer = PayloadAnalyzer()

test_cases = [
    ("Plain path traversal",       "/../../../etc/passwd",              {},                   "path_traversal"),
    ("URL-encoded traversal",      "/%2e%2e/%2e%2e/etc/passwd",         {},                   "path_traversal"),
    ("Double-encoded traversal",   "/%252e%252e/%252e%252e/etc/passwd", {},                   "path_traversal"),
    ("Backslash traversal",        "/..\\..\\etc\\passwd",              {},                   "path_traversal"),
    ("Null-byte injection",        "/admin%00.jpg",                     {},                   "admin_panel_probe"),
    ("Fullwidth chars (Unicode)",  "/\uff0e\uff0e/etc/passwd",          {},                   "path_traversal"),
    ("SQLi union select",          "/page?id=1 UNION SELECT 1,2,3",    {},                   "sqli_probe"),
    ("SQLi time-based SLEEP",      "/page?id=1;SLEEP(5)",               {},                   "sqli_time_based"),
    ("SSTI {{7*7}}",               "/page?name={{7*7}}",               {},                   "ssti_probe"),
    ("Double-encoded /admin",      "/%61dmin",                          {},                   "admin_panel_probe"),
    ("Scanner UA sqlmap",          "/",                                 {"user-agent": "sqlmap/1.7"}, "scanner_ua:sqlmap"),
]

ok = fail = 0
for desc, path, extra_headers, expected in test_cases:
    headers = {"user-agent": "Mozilla/5.0"}
    headers.update(extra_headers)
    req = {"method": "GET", "path": path, "headers": headers, "body": ""}
    result = analyzer.analyze(req)
    detected = any(expected in r for r in result["reasons"])
    if detected:
        ok += 1
        print(f"  PASS  {desc}")
    else:
        fail += 1
        print(f"  FAIL  {desc}")
        print(f"         normalized_path = {result['normalized_path']!r}")
        print(f"         reasons         = {result['reasons']}")

print(f"\n{ok}/{ok+fail} tests passed.")
sys.exit(0 if fail == 0 else 1)
