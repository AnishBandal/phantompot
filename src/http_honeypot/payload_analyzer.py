"""HTTP request payload analyzer.

Inspects parsed HTTP requests for known attack signatures:
path traversal, SQL injection probes, shell injections,
credential stuffing paths, and scanner fingerprints.

NORMALIZATION
-------------
Before any pattern matching, the target text (path + body) is
passed through a multi-stage normalization pipeline to defeat
common evasion techniques:

  1. URL-decode (single pass)      — %2e%2e  → ..
  2. Double-decode (second pass)   — %252e   → %2e → ..
  3. Null-byte stripping           — foo%00.jpg → foo.jpg
  4. Backslash → forward slash     — ..\\ → ../
  5. Redundant slash collapsing    — //admin// → /admin/
  6. Unicode NFKC normalisation    — ﹒﹒/ → ../  (fullwidth etc.)
  7. Lower-case                    — already handled by re.IGNORECASE
                                     but applied explicitly for safety
"""

from __future__ import annotations

import re
import unicodedata
from urllib.parse import unquote
from typing import Any, Dict, List


# ---------------------------------------------------------------------------
# Normalization pipeline
# ---------------------------------------------------------------------------

def _normalize(text: str) -> str:
    """Return a fully normalized version of *text* for pattern matching."""

    # 1. Strip null bytes (used to truncate strings in C-based parsers)
    text = text.replace("\x00", "").replace("%00", "")

    # 2. Double-decode first so %252e → %2e is caught before single-decode
    try:
        text = unquote(text)   # first pass:  %252e → %2e
        text = unquote(text)   # second pass: %2e   → .
    except Exception:
        pass

    # 3. Unicode NFKC normalization collapses fullwidth / lookalike chars
    #    e.g.  ／  (U+FF0F) → /,   ．  (U+FF0E) → .
    text = unicodedata.normalize("NFKC", text)

    # 4. Backslash → forward slash  (Windows-style path traversal)
    text = text.replace("\\", "/")

    # 5. Collapse consecutive slashes
    text = re.sub(r"/+", "/", text)

    # 6. Lower-case for deterministic matching
    text = text.lower()

    return text


# ---------------------------------------------------------------------------
# Suspicious path / payload patterns (applied after normalization)
# ---------------------------------------------------------------------------

_SUSPICIOUS_PATTERNS: List[tuple[str, str]] = [
    # Admin / control panels
    (r"/admin", "admin_panel_probe"),
    (r"/manager", "admin_panel_probe"),
    (r"/phpmyadmin", "phpmyadmin_probe"),
    (r"/wp-admin", "wordpress_admin_probe"),
    (r"/wp-login", "wordpress_login_probe"),
    (r"/xmlrpc", "wordpress_xmlrpc_probe"),
    # Credential endpoints
    (r"/login", "login_probe"),
    (r"/signin", "login_probe"),
    (r"/auth", "auth_probe"),
    # Sensitive file exposure
    (r"/\.env", "env_file_probe"),
    (r"/\.git", "git_exposure_probe"),
    (r"/config", "config_probe"),
    (r"/backup", "backup_probe"),
    (r"/\.htpasswd", "htpasswd_probe"),
    (r"/web\.config", "webconfig_probe"),
    # Remote code execution indicators
    (r"cmd=", "rce_probe"),
    (r"exec=", "rce_probe"),
    (r"system\(", "rce_probe"),
    (r"passthru", "rce_probe"),
    (r"shell_exec", "rce_probe"),
    (r"`[^`]+`", "rce_probe"),                      # backtick execution
    (r"\$\([^)]+\)", "rce_probe"),                   # $(...) subshell
    # Path traversal — matched POST normalization so encoded forms are caught
    (r"\.\./", "path_traversal"),
    (r"/\.\.", "path_traversal"),
    # SQL injection
    (r"'--", "sqli_probe"),
    (r"union.{0,20}select", "sqli_probe"),
    (r"or\s+1\s*=\s*1", "sqli_probe"),
    (r"drop\s+table", "sqli_probe"),
    (r"insert\s+into", "sqli_probe"),
    (r"sleep\s*\(", "sqli_time_based"),
    (r"benchmark\s*\(", "sqli_time_based"),
    (r"waitfor\s+delay", "sqli_time_based"),
    (r"'\s*or\s*'", "sqli_probe"),
    # NoSQL injection
    (r"\$where", "nosqli_probe"),
    (r"\$gt|\\$lt|\\$ne", "nosqli_probe"),
    # Server-side template injection
    (r"\{\{.*\}\}", "ssti_probe"),
    (r"\{%.*%\}", "ssti_probe"),
    # XXE
    (r"<!entity", "xxe_probe"),
    (r"<!doctype", "xxe_probe"),
    # Known scanner / botnet paths
    (r"/boaform", "router_exploit_probe"),
    (r"/cgi-bin", "cgi_probe"),
    (r"/actuator", "spring_actuator_probe"),
    (r"/solr", "solr_probe"),
    (r"/jmx-console", "jboss_probe"),
    (r"/jenkins", "jenkins_probe"),
    (r"/jndi:", "log4shell_probe"),                  # Log4Shell
    (r"\\$\{jndi:", "log4shell_probe"),
]

_COMPILED = [
    (re.compile(pattern, re.IGNORECASE | re.DOTALL), label)
    for pattern, label in _SUSPICIOUS_PATTERNS
]

# ---------------------------------------------------------------------------
# Suspicious user-agent fragments (normalized before matching)
# ---------------------------------------------------------------------------

_SUSPICIOUS_UA_FRAGMENTS = [
    "sqlmap", "nikto", "nmap", "masscan", "zgrab", "dirbuster",
    "hydra", "metasploit", "python-requests", "go-http-client",
    "curl", "wget", "libwww-perl", "wpscan", "nuclei", "acunetix",
    "nessus", "openvas", "burpsuite",
]

# ---------------------------------------------------------------------------
# Public analyzer class
# ---------------------------------------------------------------------------

class PayloadAnalyzer:
    """Analyze an HTTP request dict for attack indicators.

    All string inputs are normalized before pattern matching so that
    encoded evasion variants (URL encoding, double-encoding, unicode,
    null-byte injection, backslash substitution) are detected.
    """

    def analyze(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Return analysis result with ``is_suspicious`` and matched ``reasons``.

        Args:
            request: Parsed request dict with keys ``path``, ``method``,
                     ``headers`` (dict), and ``body``.

        Returns:
            Dict with:
              - ``is_suspicious`` (bool)
              - ``reasons``       (list of matched category strings)
              - ``normalized_path`` (str, for logging/debugging)
        """
        raw_path: str = request.get("path", "")
        method: str = request.get("method", "GET")
        user_agent: str = request.get("headers", {}).get("user-agent", "")
        raw_body: str = request.get("body", "")

        # --- normalization ---------------------------------------------------
        norm_path = _normalize(raw_path)
        norm_body = _normalize(raw_body)
        norm_ua   = _normalize(user_agent)

        # Combined target for signature matching
        target_text = f"{norm_path} {norm_body}"

        reasons: List[str] = []

        # --- signature matching ----------------------------------------------
        for pattern, label in _COMPILED:
            if pattern.search(target_text):
                if label not in reasons:
                    reasons.append(label)

        # --- user-agent check ------------------------------------------------
        for fragment in _SUSPICIOUS_UA_FRAGMENTS:
            if fragment in norm_ua:
                reasons.append(f"scanner_ua:{fragment}")
                break

        # --- POST to login path ----------------------------------------------
        norm_path_clean = norm_path.split("?")[0].rstrip("/") or "/"
        if method == "POST" and any(
            kw in norm_path_clean
            for kw in ("/login", "/signin", "/auth", "/wp-login")
        ):
            if "login_probe" not in reasons:
                reasons.append("login_probe")

        return {
            "is_suspicious": bool(reasons),
            "reasons": reasons,
            "normalized_path": norm_path,
        }
