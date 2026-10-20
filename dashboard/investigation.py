"""Evidence-first attack flow, conservative correlation, recommendations and reports."""

from __future__ import annotations

import hashlib
import html
import json
from datetime import datetime, timezone
from typing import Any


STAGE_RULES = [
    ("connection_opened", "Initial connection"),
    ("recon", "Service interaction / reconnaissance"),
    ("authentication_attempt", "Authentication attempt"),
    ("simulated_login_accepted", "Simulated authentication accepted"),
    ("command_observed", "Command / discovery activity"),
    ("http_request_observed", "HTTP request observed"),
    ("exploit", "Suspicious request or command"),
    ("session_ended", "Session termination"),
]


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def _safe(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if hasattr(value, "isoformat") and value.__class__.__name__ in {"Timestamp", "datetime64"}:
        return value.isoformat()
    if value.__class__.__name__ in {"NAType", "NaTType"}:
        return None
    if isinstance(value, dict):
        return {str(k): ("[REDACTED]" if str(k).lower() in {"password", "passwd", "secret"} else _safe(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [_safe(item) for item in value]
    return value


def synthesize_legacy_events(sessions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Create explicitly marked compatibility events from historical summaries."""
    events: list[dict[str, Any]] = []
    for session in sessions:
        sid = str(session.get("session_id", "unknown"))
        base = {"session_id": sid, "source_ip": session.get("ip", "unknown"), "protocol": session.get("protocol", "unknown"), "schema_version": 0, "simulation": False, "evidence_kind": "legacy_session_summary"}
        starts = session.get("start_time")
        events.append({**base, "event_id": f"legacy:{sid}:connection", "timestamp": starts, "event_type": "connection_opened", "event_category": "connection", "action": "connection_open", "outcome": "observed", "severity": "informational", "evidence": {"source": "legacy session summary"}, "attack_tags": [], "metadata": {"legacy": True}})
        for index, attempt in enumerate(session.get("login_attempts", []) if isinstance(session.get("login_attempts"), list) else []):
            if not isinstance(attempt, dict):
                continue
            events.append({**base, "event_id": f"legacy:{sid}:auth:{index}", "timestamp": attempt.get("timestamp", starts), "event_type": "authentication_attempt", "event_category": "authentication", "action": "login", "outcome": attempt.get("outcome", "unknown"), "severity": "unknown", "evidence": {"username": attempt.get("username")}, "attack_tags": [], "metadata": {"legacy": True, "outcome_unrecorded": "outcome" not in attempt}})
        for index, command in enumerate(session.get("commands", []) if isinstance(session.get("commands"), list) else []):
            if isinstance(command, str):
                command = {"command": command}
            if not isinstance(command, dict):
                continue
            text = str(command.get("command", ""))
            suspicious = bool(command.get("is_suspicious", False))
            events.append({**base, "event_id": f"legacy:{sid}:action:{index}", "timestamp": command.get("timestamp", starts), "event_type": "http_request_observed" if str(session.get("protocol", "")).lower() == "http" else "command_observed", "event_category": "request" if str(session.get("protocol", "")).lower() == "http" else "command", "action": text, "outcome": "flagged" if suspicious else "recorded", "severity": "medium" if suspicious else "informational", "evidence": {"command": text}, "attack_tags": list(session.get("attack_tags", [])) if suspicious else [], "metadata": {"legacy": True}})
        if session.get("end_time"):
            events.append({**base, "event_id": f"legacy:{sid}:ended", "timestamp": session.get("end_time"), "event_type": "session_ended", "event_category": "lifecycle", "action": "session_end", "outcome": "unknown", "severity": "unknown", "evidence": None, "attack_tags": [], "metadata": {"legacy": True, "terminal_outcome_unrecorded": True}})
    return events


def normalize_events(events: list[dict[str, Any]], sessions: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    combined = list(events)
    seen = {str(event.get("event_id")) for event in combined}
    actual_counts: dict[tuple[str, str], int] = {}
    for event in combined:
        key = (str(event.get("session_id", "unknown")), str(event.get("event_type", "unknown")))
        actual_counts[key] = actual_counts.get(key, 0) + 1
    legacy_counts: dict[tuple[str, str], int] = {}
    for event in synthesize_legacy_events(sessions or []):
        key = (str(event.get("session_id", "unknown")), str(event.get("event_type", "unknown")))
        legacy_counts[key] = legacy_counts.get(key, 0) + 1
        # Fill gaps in partial event logs without duplicating event categories
        # already represented by persisted records.
        if legacy_counts[key] <= actual_counts.get(key, 0):
            continue
        if event["event_id"] not in seen:
            combined.append(event)
            seen.add(event["event_id"])
    for event in combined:
        event.setdefault("event_id", "unknown")
        event.setdefault("evidence", None)
        event.setdefault("metadata", {})
        event.setdefault("attack_tags", [])
        event.setdefault("outcome", "unknown")
        event.setdefault("simulation", False)
    combined.sort(key=lambda event: (_parse_time(event.get("timestamp")) or datetime.min.replace(tzinfo=timezone.utc), str(event.get("event_id"))))
    return combined


def stage_for_event(event: dict[str, Any]) -> str:
    kind = str(event.get("event_type", ""))
    outcome = str(event.get("outcome", "")).lower()
    if kind == "connection_opened":
        return "Initial connection"
    if kind == "authentication_attempt" and outcome == "accepted_simulated":
        return "Simulated authentication accepted"
    if kind == "authentication_attempt":
        return "Authentication attempt"
    if kind == "session_ended":
        return "Session termination"
    tags = " ".join(str(tag) for tag in event.get("attack_tags", []))
    if outcome in {"flagged", "signature_match", "blocked"} or tags:
        return "Suspicious request or command"
    if kind == "http_request_observed":
        return "HTTP request observed"
    if kind == "command_observed":
        return "Command / discovery activity"
    return "Service interaction / reconnaissance"


def reconstruct_flow(sessions: list[dict[str, Any]], events: list[dict[str, Any]], selected_session_id: str) -> dict[str, Any]:
    selected = [event for event in events if str(event.get("session_id")) == str(selected_session_id)]
    selected.sort(key=lambda event: (_parse_time(event.get("timestamp")) or datetime.min.replace(tzinfo=timezone.utc), str(event.get("event_id"))))
    session = next((row for row in sessions if str(row.get("session_id")) == str(selected_session_id)), {})
    observed_stages = [stage_for_event(event) for event in selected]
    stages: list[str] = []
    for stage in observed_stages:
        if not stages or stages[-1] != stage:
            stages.append(stage)
    suspicious_actions = [event for event in selected if stage_for_event(event) == "Suspicious request or command"]
    accepted = [event for event in selected if event.get("outcome") == "accepted_simulated"]
    outcome = "No terminal event recorded"
    if any(event.get("event_type") == "session_ended" and event.get("outcome") == "disconnected" for event in selected):
        outcome = "Session disconnected; decoy impact beyond recorded interactions is unknown"
    elif any(event.get("event_type") == "session_ended" and event.get("outcome") == "incomplete" for event in selected):
        outcome = "Session ended before the simulated interaction completed"
    elif any(event.get("event_type") == "session_ended" for event in selected):
        outcome = "Session ended; decoy impact beyond recorded interactions is unknown"
    elif session.get("connection_state") == "disconnected":
        outcome = "Session summary records disconnection; no separate termination event was preserved"
    elif selected:
        outcome = "Session outcome incomplete; no termination event recorded"
    return {
        "session": session,
        "events": selected,
        "stages": stages,
        "observed_stages": observed_stages,
        "outcome": outcome,
        "unresolved": ["No evidence establishes compromise of a real host.", "Unrecorded activity outside this honeypot session is unknown."],
        "accepted_logins": accepted,
        "suspicious_actions": suspicious_actions,
    }


def correlate_sessions(sessions: list[dict[str, Any]], window_seconds: int = 900) -> list[dict[str, Any]]:
    """Link same-source sessions in time as potentially related, never same actor."""
    rows = sorted(sessions, key=lambda row: _parse_time(row.get("start_time")) or datetime.max.replace(tzinfo=timezone.utc))
    relationships: list[dict[str, Any]] = []
    for i, left in enumerate(rows):
        left_time = _parse_time(left.get("start_time"))
        if left_time is None:
            continue
        for right in rows[i + 1:]:
            right_time = _parse_time(right.get("start_time"))
            if right_time is None:
                continue
            delta = (right_time - left_time).total_seconds()
            if delta > window_seconds:
                break
            if left.get("ip") and left.get("ip") == right.get("ip") and left.get("session_id") != right.get("session_id"):
                relationships.append({"source_session_id": left.get("session_id"), "target_session_id": right.get("session_id"), "source_ip": left.get("ip"), "time_delta_seconds": delta, "relationship": "potentially_related_same_source_within_window", "caveat": "Shared source address and timing do not prove a common actor or campaign."})
    return relationships


def generate_recommendations(sessions: list[dict[str, Any]], events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    evidence = normalize_events(events, sessions)
    recs: list[dict[str, Any]] = []

    def add(rec_id: str, title: str, priority: str, area: str, reason: str, steps: list[str], benefit: str, effort: str, matched: list[dict[str, Any]]) -> None:
        if not matched:
            return
        refs = sorted({str(item.get("session_id", "unknown")) for item in matched})
        recs.append({"recommendation_id": rec_id, "title": title, "priority": priority, "area": area, "evidence": matched[:30], "reason": reason, "remediation_steps": steps, "expected_benefit": benefit, "effort_estimate": effort, "verification": "Review the corresponding authentication, application, or command-audit telemetry on systems you administer; confirm the control is enabled and test it with an approved check.", "source_session_ids": refs, "generation": "automatically_generated", "finding_scope": "Observed in the honeypot; this does not establish that a production system has the same weakness."})

    failed = [event for event in evidence if event.get("event_type") == "authentication_attempt" and event.get("outcome") == "rejected"]
    if len(failed) >= 1:
        priority = "high" if len(failed) >= 5 else "medium"
        add("AUTH-001", "Review protections for exposed administrative authentication", priority, "Identity and access", f"Observed {len(failed)} rejected decoy authentication attempt(s). This is evidence of attempted access against the honeypot only.", ["Require MFA for real administrative access.", "Restrict management services to trusted networks.", "Apply rate limits and account-protection controls.", "Alert on repeated failures and review authentication policy."], "Reduces the chance of credential guessing succeeding against real services.", "Moderate", failed)

    http_events = [event for event in evidence if event.get("event_type") == "http_request_observed" and (event.get("attack_tags") or event.get("outcome") in {"flagged", "signature_match"})]
    if http_events:
        add("WEB-001", "Review web input handling and administrative endpoint controls", "high" if len(http_events) >= 5 else "medium", "Web application security", f"Observed {len(http_events)} HTTP request event(s) carrying signature tags or flagged outcomes.", ["Review input validation and context-aware output encoding.", "Use parameterized queries for database access.", "Verify authorization on administrative endpoints.", "Review application, reverse-proxy, and WAF logs against the observed paths and signatures."], "Helps reduce exposure to common injection and unauthorized endpoint probing patterns.", "Moderate", http_events)

    commands = [event for event in evidence if event.get("event_type") == "command_observed" and event.get("outcome") == "flagged"]
    if commands:
        add("CMD-001", "Review remote shell privilege and command auditing", "high" if len(commands) >= 5 else "medium", "Endpoint and privilege management", f"Observed {len(commands)} command event(s) marked suspicious by the honeypot command classifier.", ["Apply least privilege to remote accounts.", "Disable unnecessary remote shell access.", "Review privileged account use and command/process auditing."], "Improves detection and limits impact if a real remote account is misused.", "Low to moderate", commands)

    connections = [event for event in evidence if event.get("event_type") == "connection_opened"]
    if len(connections) >= 5:
        add("NET-001", "Review exposed services and network access boundaries", "medium", "Network exposure", f"Observed {len(connections)} honeypot connection events in the selected evidence set.", ["Inventory internet-facing services.", "Restrict services that do not need external access.", "Review network segmentation and monitor repeated service discovery."], "Reduces unnecessary attack surface and improves visibility into reconnaissance.", "Moderate", connections)
    return sorted(recs, key=lambda rec: ({"critical": 0, "high": 1, "medium": 2, "low": 3}.get(rec["priority"], 4), -len(rec["evidence"]), rec["recommendation_id"]))


def investigation_report(flow: dict[str, Any], recommendations: list[dict[str, Any]]) -> dict[str, Any]:
    session = flow.get("session", {})
    events = flow.get("events", [])
    identifiers = sorted(str(event.get("event_id")) for event in events)
    report_id = "INV-" + hashlib.sha256("|".join(identifiers or [str(session.get("session_id", "unknown"))]).encode()).hexdigest()[:12].upper()
    ip = session.get("ip", "unknown")
    auth_events = [event for event in events if event.get("event_type") == "authentication_attempt"]
    auth_outcomes = [{"timestamp": event.get("timestamp"), "outcome": event.get("outcome", "unknown"), "username": (event.get("evidence") or {}).get("username")} for event in auth_events]
    action_events = [event for event in events if event.get("event_type") in {"command_observed", "http_request_observed"}]
    return _safe({
        "report_title": "PhantomPot Attack Investigation",
        "investigation_id": report_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "executive_summary": f"Observed {len(events)} persisted event(s) in one {session.get('protocol', 'unknown')} honeypot session from source {ip}. This is observed activity in the decoy environment, not evidence of production compromise.",
        "time_window": {"start": session.get("start_time"), "end": session.get("end_time")},
        "protocols": sorted({str(event.get("protocol", "unknown")) for event in events}),
        "sessions": [session.get("session_id")] if session.get("session_id") else [],
        "source_addresses": [{"ip": ip, "attribution_caveat": "An observed source address does not identify a person or prove attribution."}],
        "attack_timeline": [{"timestamp": event.get("timestamp"), "stage": stage_for_event(event), "event": event} for event in events],
        "authentication_outcomes": auth_outcomes,
        "key_commands_requests_and_payload_findings": [{"timestamp": event.get("timestamp"), "action": event.get("action"), "outcome": event.get("outcome"), "evidence": event.get("evidence"), "attack_tags": event.get("attack_tags")} for event in action_events],
        "evidence_references": identifiers,
        "detected_categories": sorted({str(tag) for event in events for tag in event.get("attack_tags", [])}),
        "model_metadata": {key: session.get(key) for key in ("anomaly", "anomaly_score", "severity", "confidence_label", "confidence_score", "decision_band") if key in session},
        "observed_outcome": flow.get("outcome"),
        "limitations_and_unresolved_questions": flow.get("unresolved", []),
        "recommendations": recommendations,
        "verification_steps": [rec["verification"] for rec in recommendations],
    })


def aggregate_report(sessions: list[dict[str, Any]], events: list[dict[str, Any]], recommendations: list[dict[str, Any]]) -> dict[str, Any]:
    protocols: dict[str, int] = {}
    severities: dict[str, int] = {}
    attack_types: dict[str, int] = {}
    for session in sessions:
        protocol = str(session.get("protocol", "unknown")); protocols[protocol] = protocols.get(protocol, 0) + 1
        severity = str(session.get("severity", "unknown")); severities[severity] = severities.get(severity, 0) + 1
        attack = str(session.get("attack_type", "none"))
        if attack != "none": attack_types[attack] = attack_types.get(attack, 0) + 1
    auth = [event for event in events if event.get("event_type") == "authentication_attempt"]
    source_counts: dict[str, int] = {}
    for session in sessions:
        address = str(session.get("ip", "unknown")); source_counts[address] = source_counts.get(address, 0) + 1
    dates = [_parse_time(row.get("start_time")) for row in sessions]
    time_window = {"start": min((value for value in dates if value), default=None), "end": max((value for value in dates if value), default=None)}
    return _safe({"report_title": "PhantomPot Aggregate Security Report", "generated_at": datetime.now(timezone.utc).isoformat(), "scope": "Filtered honeypot observations; source addresses are not actor attribution.", "time_window": time_window, "session_count": len(sessions), "event_count": len(events), "protocol_breakdown": protocols, "severity_distribution": severities, "attack_categories": attack_types, "authentication_outcomes": {outcome: sum(1 for event in auth if event.get("outcome") == outcome) for outcome in sorted({str(event.get("outcome", "unknown")) for event in auth})}, "top_observed_source_addresses": sorted(source_counts.items(), key=lambda item: (-item[1], item[0]))[:10], "event_references": [event.get("event_id") for event in events], "recommendations": recommendations, "detection_limitations": ["Honeypot observations do not prove production compromise.", "Historical session summaries may not include authentication outcomes or event-level evidence.", "Source addresses can represent shared infrastructure and do not establish actor identity." ]})


def report_html(report: dict[str, Any]) -> str:
    title = html.escape(str(report.get("report_title", "Security Report")))
    body = html.escape(json.dumps(report, indent=2, ensure_ascii=False))
    return f"<!doctype html><html><head><meta charset='utf-8'><title>{title}</title><style>body{{font:15px/1.5 Inter,system-ui,sans-serif;color:#1e293b;background:#f1f5f9;margin:0;padding:3rem}}main{{max-width:1000px;margin:auto;background:#fff;padding:2.5rem;border:1px solid #cbd5e1;border-radius:12px}}h1{{color:#0f2942}}pre{{white-space:pre-wrap;word-break:break-word;background:#f8fafc;padding:1rem;border:1px solid #e2e8f0;border-radius:8px}}@media print{{body{{background:white;padding:0}}main{{border:0}}}}</style></head><body><main><h1>{title}</h1><pre>{body}</pre></main></body></html>"


def report_pdf(report: dict[str, Any]) -> bytes:
    """Create a compact dependency-free printable PDF report."""
    lines = json.dumps(report, indent=2, ensure_ascii=False).splitlines()
    escaped_lines = [line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)") for line in lines]
    chunks = [escaped_lines[index:index + 48] for index in range(0, len(escaped_lines), 48)] or [[]]
    objects: list[bytes] = []
    page_ids = []
    next_id = 4
    for chunk in chunks:
        page_id, content_id = next_id, next_id + 1
        next_id += 2
        page_ids.append(page_id)
        commands = ["BT", "/F1 9 Tf", "48 790 Td", "12 TL"]
        for line in chunk:
            commands.append(f"({line[:150]}) Tj T*")
        commands.append("ET")
        content = "\n".join(commands).encode("latin-1", errors="replace")
        objects.extend([
            f"{page_id} 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] /Resources << /Font << /F1 3 0 R >> >> /Contents {content_id} 0 R >> endobj\n".encode(),
            f"{content_id} 0 obj << /Length {len(content)} >> stream\n".encode() + content + b"\nendstream endobj\n",
        ])
    kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
    base = [b"%PDF-1.4\n", b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n", f"2 0 obj << /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >> endobj\n".encode(), b"3 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n"]
    all_objects = base + objects
    offsets = [0]
    payload = bytearray(b"%PDF-1.4\n")
    for obj in all_objects[1:]:
        offsets.append(len(payload)); payload.extend(obj)
    xref = len(payload)
    payload.extend(f"xref\n0 {len(all_objects)}\n0000000000 65535 f \n".encode())
    for offset in offsets[1:]: payload.extend(f"{offset:010d} 00000 n \n".encode())
    payload.extend(f"trailer << /Size {len(all_objects)} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF".encode())
    return bytes(payload)
