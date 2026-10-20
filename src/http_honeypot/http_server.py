"""Simple HTTP honeypot server.

Listens on the configured HTTP port, simulates common endpoints, and logs each
request via the shared SessionManager -> FeatureBuilder -> ML -> HoneypotLogger
pipeline used by other protocols.
"""

from __future__ import annotations

import http.server
import json
import socketserver
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

try:
    # Prefer package-relative imports in package execution mode.
    from ..core.logger import HoneypotLogger, get_default_logger
    from ..core.session_finalizer import finalize_and_log_session
    from ..core.session_manager import SessionManager
    from .payload_analyzer import PayloadAnalyzer
except Exception:
    # Fallback to absolute imports if running as a script.
    try:
        from core.logger import HoneypotLogger, get_default_logger
        from core.session_finalizer import finalize_and_log_session
        from core.session_manager import SessionManager
        from http_honeypot.payload_analyzer import PayloadAnalyzer
    except Exception:
        try:
            from src.core.logger import HoneypotLogger, get_default_logger
            from src.core.session_finalizer import finalize_and_log_session
            from src.core.session_manager import SessionManager
            from src.http_honeypot.payload_analyzer import PayloadAnalyzer
        except Exception:
            HoneypotLogger = Any  # type: ignore

            def get_default_logger() -> Any:  # type: ignore
                return None

            SessionManager = Any  # type: ignore
            PayloadAnalyzer = Any  # type: ignore

            def finalize_and_log_session(*args: Any, **kwargs: Any) -> None:  # type: ignore
                return


class HoneypotHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    # Server identification string returned in responses
    server_version = "PhantomPotHTTP/1.0"
    logger: Optional[HoneypotLogger] = None
    session_manager: Optional[SessionManager] = None
    payload_analyzer: Any = PayloadAnalyzer()
    
    # Professional admin login page (embedded directly)
    _login_page_html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Portal - Login</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', 'Ubuntu', 'Cantarell', sans-serif;
            background-color: #f5f5f5;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
        }
        .login-container {
            background-color: #ffffff;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
            width: 100%;
            max-width: 400px;
            padding: 40px;
        }
        .login-header {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo {
            display: inline-block;
            width: 50px;
            height: 50px;
            background-color: #2c3e50;
            border-radius: 6px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #ffffff;
            font-weight: bold;
            font-size: 24px;
            margin-bottom: 15px;
        }
        .login-title {
            color: #2c3e50;
            font-size: 28px;
            font-weight: 600;
            margin-bottom: 8px;
        }
        .login-subtitle {
            color: #7f8c8d;
            font-size: 14px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            color: #2c3e50;
            font-weight: 500;
            margin-bottom: 8px;
            font-size: 14px;
        }
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 12px 14px;
            border: 1px solid #bdc3c7;
            border-radius: 6px;
            font-size: 14px;
            color: #2c3e50;
            transition: border-color 0.2s;
        }
        input[type="text"]:focus,
        input[type="password"]:focus {
            outline: none;
            border-color: #3498db;
            box-shadow: 0 0 0 3px rgba(52, 152, 219, 0.1);
        }
        .form-options {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 25px;
            font-size: 13px;
        }
        .remember-me {
            display: flex;
            align-items: center;
        }
        input[type="checkbox"] {
            margin-right: 6px;
            cursor: pointer;
        }
        .remember-me label {
            margin: 0;
            cursor: pointer;
            font-weight: 400;
            color: #7f8c8d;
        }
        .forgot-password {
            color: #3498db;
            text-decoration: none;
        }
        .login-btn {
            width: 100%;
            padding: 12px;
            background-color: #3498db;
            color: #ffffff;
            border: none;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: background-color 0.2s;
        }
        .login-btn:hover {
            background-color: #2980b9;
        }
        .security-info {
            background-color: #ecf0f1;
            border-left: 4px solid #27ae60;
            padding: 12px;
            border-radius: 4px;
            margin-top: 25px;
            font-size: 12px;
            color: #27ae60;
        }
        .footer-text {
            text-align: center;
            color: #7f8c8d;
            font-size: 12px;
            margin-top: 20px;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <div class="logo">AP</div>
            <h1 class="login-title">Admin Portal</h1>
            <p class="login-subtitle">Enterprise Access Control</p>
        </div>
        <form method="POST" action="/login">
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" placeholder="Enter your username" required autocomplete="off">
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="Enter your password" required autocomplete="off">
            </div>
            <div class="form-options">
                <div class="remember-me">
                    <input type="checkbox" id="remember" name="remember">
                    <label for="remember">Remember me</label>
                </div>
                <a href="/help/forgot-password" class="forgot-password">Forgot password?</a>
            </div>
            <button type="submit" class="login-btn">Sign In</button>
        </form>
        <div class="security-info">
            <strong>🔒 Security Notice</strong><br>
            Secure connection verified. Two-factor authentication enabled.
        </div>
        <div class="footer-text">
            <p>© 2024 Enterprise Systems. All rights reserved.</p>
        </div>
    </div>
</body>
</html>"""

    @classmethod
    def _load_login_page(cls) -> str:
        """Return the embedded login page HTML."""
        return cls._login_page_html

    def _respond_html(self, html: str, status: int = 200) -> None:
        """Send an HTML response."""
        try:
            encoded = html.encode('utf-8')
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            # Client closed connection before response could be sent
            pass
        except Exception as e:
            # Log unexpected errors but don't crash
            print(f"[!] Error sending HTML response: {e}")

    def _respond_dummy(self, status: int = 200, body: Optional[Dict[str, Any]] = None) -> None:
        # Send a simple JSON response. This simulates a real endpoint
        # but performs no actions or lookups.
        if body is None:
            body = {"status": "ok"}
        try:
            encoded = json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            # Client closed connection before response could be sent
            pass
        except Exception as e:
            # Log unexpected errors but don't crash
            print(f"[!] Error sending JSON response: {e}")

    def _parse_request_payload(self) -> Tuple[Optional[str], Optional[Any]]:
        # Read and parse the request body if present.
        # Returns the raw text and a best-effort parsed object (JSON or form data).
        content_length = int(self.headers.get("Content-Length", "0") or 0)
        if content_length <= 0:
            return None, None
        raw = self.rfile.read(content_length)
        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception:
            text = raw.decode("latin-1", errors="replace")

        parsed = None
        ctype = self.headers.get("Content-Type", "")
        if "application/json" in ctype:
            try:
                parsed = json.loads(text)
            except Exception:
                parsed = None
        elif "application/x-www-form-urlencoded" in ctype:
            parsed = {k: v for k, v in parse_qs(text).items()}
        else:
            # For other types keep raw text
            parsed = None

        return text, parsed

    @staticmethod
    def _first_value(value: Any) -> str:
        if isinstance(value, list):
            return str(value[0]) if value else ""
        return "" if value is None else str(value)

    def _record_http_session(
        self,
        method: str,
        path: str,
        ip: str,
        is_suspicious: bool,
        login_attempt: bool,
        login_info: Optional[Dict[str, Any]],
        attack_reasons: Optional[List[str]] = None,
    ) -> Optional[bool]:
        sm = self.__class__.session_manager
        logger = self.__class__.logger
        if sm is None or logger is None:
            return None

        session_id = sm.create_session(ip=ip, protocol="http")
        auth_accepted: Optional[bool] = None
        if login_attempt and login_info:
            auth_accepted = sm.authenticate(
                session_id,
                self._first_value(login_info.get("username")),
                self._first_value(login_info.get("password")),
            )

        sm.add_command(
            session_id=session_id,
            command=f"{method} {path}",
            is_suspicious=bool(is_suspicious),
            outcome=("simulated_login_accepted" if auth_accepted else "authentication_rejected") if login_attempt else ("signature_match" if is_suspicious else "request_recorded"),
            event_metadata={
                "method": method,
                "path": path,
                "response_status": 200 if auth_accepted else (401 if login_attempt else 200),
                "signature_reasons": list(attack_reasons or []),
            },
            attack_tags=list(attack_reasons or []),
        )

        finalize_and_log_session(
            session_id=session_id,
            client_ip=ip,
            protocol_tag="[HTTP]",
            session_manager=sm,
            logger=logger,
            attack_reasons=attack_reasons,
        )
        return auth_accepted

    def do_GET(self) -> None:
        # Handle incoming GET requests: log the request and return a response.
        parsed = urlparse(self.path)
        path = parsed.path
        ip = self.client_address[0] if self.client_address else "0.0.0.0"

        headers_lower = {k.lower(): v for k, v in self.headers.items()}
        analysis = self.__class__.payload_analyzer.analyze(
            {
                "method": "GET",
                "path": self.path,
                "headers": headers_lower,
                "body": "",
            }
        )

        # Persist via shared protocol-agnostic session pipeline.
        self._record_http_session(
            method="GET",
            path=path,
            ip=ip,
            is_suspicious=bool(analysis.get("is_suspicious", False)),
            login_attempt=False,
            login_info=None,
            attack_reasons=analysis.get("reasons", []),
        )
        print(f"[+] HTTP GET logged: {ip} -> {path}")

        # Serve the login page for root and login-related paths
        if path == "/" or path == "/login" or path == "/admin" or path.startswith("/admin/"):
            login_page = self._load_login_page()
            self._respond_html(login_page, 200)
        # Return 503 error for dashboard (tricks attacker into thinking server is down)
        elif path == "/dashboard" or path == "/api/dashboard" or path == "/home":
            error_503 = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Service Unavailable</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f5f5f5; margin: 0; padding: 20px; }
.container { max-width: 500px; margin: 100px auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.15); text-align: center; }
h1 { color: #e74c3c; margin: 0 0 10px 0; font-size: 48px; font-weight: 600; }
.status-text { color: #c0392b; font-size: 14px; font-weight: 600; margin-bottom: 20px; letter-spacing: 0.5px; }
.description { color: #34495e; font-size: 15px; line-height: 1.6; margin-bottom: 25px; }
.status-code { background: #ecf0f1; padding: 15px; border-radius: 6px; font-family: monospace; color: #555; font-size: 12px; margin-bottom: 25px; }
.retry-info { color: #7f8c8d; font-size: 12px; }
.retry-link { margin-top: 30px; }
.retry-link a { display: inline-block; padding: 10px 20px; background: #3498db; color: white; text-decoration: none; border-radius: 6px; font-size: 14px; }
.retry-link a:hover { background: #2980b9; }
</style>
</head><body>
<div class="container">
<h1>503</h1>
<p class="status-text">SERVICE UNAVAILABLE</p>
<p class="description">
The server is temporarily unable to handle the request.<br>
Please try again in a few moments.
</p>
<div class="status-code">
HTTP/1.1 503 Service Unavailable<br>
Server Error: Internal Server Maintenance<br>
Retry-After: 60
</div>
<p class="retry-info">
If this problem persists, please contact support.
</p>
<div class="retry-link">
<a href="/login">Back to Login</a>
</div>
</div>
</body></html>
            """
            self._respond_html(error_503, 503)
        else:
            self._respond_dummy(200, {"message": "Nothing to see here", "path": path})

    def do_POST(self) -> None:
        # Handle incoming POST requests: parse body, log, and respond.
        parsed = urlparse(self.path)
        path = parsed.path
        ip = self.client_address[0] if self.client_address else "0.0.0.0"

        payload_raw, payload_parsed = self._parse_request_payload()
        headers_lower = {k.lower(): v for k, v in self.headers.items()}

        analysis = self.__class__.payload_analyzer.analyze(
            {
                "method": "POST",
                "path": self.path,
                "headers": headers_lower,
                "body": payload_raw or "",
            }
        )

        # Detect login attempts and extract credentials
        login_attempt = False
        login_info: Dict[str, Any] = {}
        if "/login" in path or "/admin" in path:
            login_attempt = True
            login_info = {"username": "", "password": ""}
        if isinstance(payload_parsed, dict):
            lower_keys = {k.lower(): v for k, v in payload_parsed.items()}
            for key in ("username", "user", "email"):
                if key in lower_keys:
                    login_attempt = True
                    login_info["username"] = lower_keys.get(key)
            for key in ("password", "pass"):
                if key in lower_keys:
                    login_attempt = True
                    login_info["password"] = lower_keys.get(key)

        # Persist via shared protocol-agnostic session pipeline.
        auth_accepted = self._record_http_session(
            method="POST",
            path=path,
            ip=ip,
            is_suspicious=bool(analysis.get("is_suspicious", False)),
            login_attempt=login_attempt,
            login_info=login_info if login_info else None,
            attack_reasons=analysis.get("reasons", []),
        )
        
        if login_attempt:
            user = login_info.get('username', '?')
            print(f"[+] HTTP POST logged: {ip} -> {path} (user: {user})")
        else:
            print(f"[+] HTTP POST logged: {ip} -> {path}")

        if login_attempt and auth_accepted is True:
            success_html = """<!doctype html><html><head><title>Control Console</title><meta charset="utf-8"></head>
<body style="font-family:system-ui;background:#eef3f7;color:#152536"><main style="max-width:680px;margin:8vh auto;background:white;padding:32px;border:1px solid #d5dee8;border-radius:12px">
<p style="color:#087f8c;font-weight:700">SIMULATED DECOY CONSOLE</p><h1>Operations portal</h1>
<p>Authentication accepted by the isolated honeypot simulation.</p><ul><li>System status: operational (simulated)</li><li>Recent activity: no new notices</li></ul>
<p style="color:#64748b">This environment does not provide access to host systems.</p></main></body></html>"""
            self._respond_html(success_html, 200)
            return

        # Unknown accounts receive the existing controlled 401 response.
        if path == "/login" or path.startswith("/admin"):
            error_page = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Authentication Error</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f5f5f5; margin: 0; padding: 20px; }
.container { max-width: 500px; margin: 80px auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
h1 { color: #e74c3c; margin: 0 0 10px 0; font-size: 24px; }
.error-code { color: #7f8c8d; font-size: 14px; margin-bottom: 20px; }
.error-message { color: #34495e; margin-bottom: 15px; line-height: 1.6; }
.error-details { background: #f8f9fa; border-left: 4px solid #e74c3c; padding: 12px; border-radius: 4px; color: #555; font-size: 12px; font-family: monospace; }
.retry-link { margin-top: 20px; }
.retry-link a { color: #3498db; text-decoration: none; }
.retry-link a:hover { text-decoration: underline; }
</style>
</head><body>
<div class="container">
<h1>❌ Authentication Failed</h1>
<p class="error-code">HTTP 401 - Unauthorized</p>
<div class="error-message">
The credentials you provided are invalid or insufficient.<br>
Please verify your username and password.
</div>
<div class="error-details">
error_code: AUTH_INVALID_CREDENTIALS<br>
message: Invalid username or password<br>
timestamp: """ + __import__('datetime').datetime.utcnow().isoformat() + """Z<br>
request_id: """ + __import__('uuid').uuid4().hex[:12] + """
</div>
<div class="retry-link">
<a href="/login">← Try again</a>
</div>
</div>
</body></html>
            """
            self._respond_html(error_page, 401)
        else:
            self._respond_dummy(200, {"message": "Received", "path": path})

    def log_message(self, format: str, *args) -> None:  # silence default console logging
        # Override to avoid noisy console logs; logging is performed via `log_event`.
        return


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


class HTTPHoneypotServer:
    """Compatibility wrapper exposing `serve_forever()` for use with main.py.
    
    Takes the same parameters as SSH/FTP/Telnet servers for consistency.
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8888,
        logger=None,
        session_manager=None,
    ) -> None:
        self.host = host
        self.port = int(port)
        self.logger = logger
        self.session_manager = session_manager
        self._httpd: Optional[ThreadedHTTPServer] = None

    def serve_forever(self) -> None:
        """Start the HTTP server and block until interrupted."""
        server_address = (self.host, self.port)
        if self.logger is None:
            self.logger = get_default_logger()
        if self.session_manager is None:
            self.session_manager = SessionManager(event_sink=self.logger.log_event)

        HoneypotHTTPRequestHandler.logger = self.logger
        HoneypotHTTPRequestHandler.session_manager = self.session_manager

        self._httpd = ThreadedHTTPServer(server_address, HoneypotHTTPRequestHandler)
        try:
            print(f"[*] HTTP honeypot listening on {self.host}:{self.port}")
            self._httpd.serve_forever()
        except KeyboardInterrupt:
            self._httpd.shutdown()
        finally:
            if self._httpd:
                self._httpd.server_close()


def run_server(host: str = "0.0.0.0", port: int = 8888) -> None:
    # Start a standalone HTTP server with default shared services.
    server = HTTPHoneypotServer(host=host, port=port)
    server.serve_forever()


if __name__ == "__main__":
    run_server()
