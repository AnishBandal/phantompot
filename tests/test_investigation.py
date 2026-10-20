import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "dashboard"))

from core.event_schema import validate_event
from core.logger import HoneypotLogger
from core.session_manager import SessionManager
from investigation import (
    aggregate_report,
    correlate_sessions,
    generate_recommendations,
    investigation_report,
    normalize_events,
    reconstruct_flow,
    report_html,
    report_pdf,
)


class InvestigationTests(unittest.TestCase):
    def test_auth_outcomes_and_password_not_persisted(self):
        events = []
        manager = SessionManager(event_sink=events.append, auth_config={"ssh": {"accept_any": False, "accounts": {"demo": "decoy"}}})
        session_id = manager.create_session("192.0.2.10", "ssh")
        self.assertFalse(manager.authenticate(session_id, "demo", "wrong"))
        self.assertTrue(manager.authenticate(session_id, "demo", "decoy"))
        self.assertTrue(all(validate_event(event) for event in events))
        summary = manager.finalize_session(session_id)
        self.assertEqual([item["outcome"] for item in summary["login_attempts"]], ["rejected", "accepted_simulated"])
        self.assertTrue(all("password" not in item for item in summary["login_attempts"]))
        self.assertEqual([event["event_type"] for event in events], ["connection_opened", "authentication_attempt", "authentication_attempt", "session_ended"])

    def test_event_log_is_separate_jsonl(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            logger = HoneypotLogger(str(root / "sessions.jsonl"), str(root / "errors.log"))
            event = {"event_id": "e1", "schema_version": 1, "session_id": "s1", "timestamp": "2026-01-01T00:00:00+00:00", "source_ip": "127.0.0.1", "protocol": "ssh", "event_type": "connection_opened", "event_category": "connection", "action": "connect", "outcome": "observed", "severity": "informational", "evidence": None, "attack_tags": [], "simulation": False, "metadata": {}}
            logger.log_event(event)
            self.assertEqual(json.loads((root / "events.jsonl").read_text()), event)

    def test_ordering_and_conservative_correlation(self):
        sessions = [
            {"session_id": "s1", "ip": "192.0.2.2", "protocol": "ssh", "start_time": "2026-01-01T00:00:00Z"},
            {"session_id": "s2", "ip": "192.0.2.2", "protocol": "http", "start_time": "2026-01-01T00:05:00Z"},
            {"session_id": "s3", "ip": "192.0.2.3", "protocol": "ftp", "start_time": "2026-01-01T00:06:00Z"},
        ]
        edges = correlate_sessions(sessions, 900)
        self.assertEqual(len(edges), 1)
        self.assertIn("potentially_related", edges[0]["relationship"])
        events = normalize_events([], sessions)
        flow = reconstruct_flow(sessions, events, "s1")
        self.assertEqual([e["event_type"] for e in flow["events"]], ["connection_opened"])
        self.assertTrue(flow["outcome"].startswith("Session outcome incomplete"))

    def test_recommendations_require_evidence_and_reports_redact(self):
        sessions = [{"session_id": "s1", "ip": "192.0.2.4", "protocol": "ssh", "start_time": "2026-01-01T00:00:00Z", "end_time": "2026-01-01T00:01:00Z", "login_attempts": [{"username": "demo", "password": "never-report", "outcome": "rejected"}]}]
        event = {"event_id": "e-auth", "session_id": "s1", "timestamp": "2026-01-01T00:00:10Z", "event_type": "authentication_attempt", "event_category": "authentication", "action": "login", "outcome": "rejected", "protocol": "ssh", "source_ip": "192.0.2.4", "severity": "medium", "evidence": {"username": "demo"}, "attack_tags": ["authentication_failure"], "simulation": True, "metadata": {}}
        recommendations = generate_recommendations(sessions, [event])
        self.assertEqual(recommendations[0]["recommendation_id"], "AUTH-001")
        flow = reconstruct_flow(sessions, [event], "s1")
        report = investigation_report(flow, recommendations)
        self.assertNotIn("never-report", json.dumps(report))
        self.assertTrue(report_html(report).startswith("<!doctype html>"))
        self.assertTrue(report_pdf(report).startswith(b"%PDF-1.4"))
        self.assertEqual(aggregate_report(sessions, [event], recommendations)["event_count"], 1)

    def test_legacy_auth_outcome_is_unknown(self):
        sessions = [{"session_id": "old", "protocol": "telnet", "ip": "127.0.0.1", "login_attempts": [{"username": "root", "password": "old-secret"}]}]
        events = normalize_events([], sessions)
        auth = next(event for event in events if event["event_type"] == "authentication_attempt")
        self.assertEqual(auth["outcome"], "unknown")
        self.assertNotIn("old-secret", json.dumps(auth))

    def test_partial_event_log_fills_gaps_without_duplicates(self):
        session = {"session_id": "partial", "protocol": "ssh", "ip": "192.0.2.1", "start_time": "2026-01-01T00:00:00Z", "end_time": "2026-01-01T00:00:10Z", "login_attempts": [{"username": "one", "outcome": "rejected"}, {"username": "two", "outcome": "rejected"}], "commands": [{"command": "whoami"}]}
        connection = {"event_id": "persisted-connection", "session_id": "partial", "event_type": "connection_opened", "timestamp": "2026-01-01T00:00:00Z"}
        events = normalize_events([connection], [session])
        self.assertEqual(sum(event["event_type"] == "connection_opened" for event in events), 1)
        self.assertEqual(sum(event["event_type"] == "authentication_attempt" for event in events), 2)
        self.assertEqual(sum(event["event_type"] == "command_observed" for event in events), 1)
        self.assertEqual(sum(event["event_type"] == "session_ended" for event in events), 1)


if __name__ == "__main__":
    unittest.main()
