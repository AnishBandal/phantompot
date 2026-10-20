from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pandas as pd
import plotly.express as px
import streamlit as st
import plotly.graph_objects as go

ROOT_DIR = Path(__file__).resolve().parents[1]
SRC_DIR = ROOT_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

try:
    from ml.predict import predict_session_anomaly
except Exception:
    predict_session_anomaly = None

try:
    from investigation import (
        aggregate_report,
        correlate_sessions,
        generate_recommendations,
        investigation_report,
        normalize_events,
        reconstruct_flow,
        report_html,
        report_pdf,
        stage_for_event,
    )
except ImportError:
    from dashboard.investigation import (
        aggregate_report, correlate_sessions, generate_recommendations,
        investigation_report, normalize_events, reconstruct_flow,
        report_html, report_pdf, stage_for_event,
    )

SEVERITY_ORDER = ["critical", "high", "medium", "low", "unknown"]
SEVERITY_COLORS = {
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#22c55e",
    "unknown": "#64748b",
}
EXPECTED_PROTOCOLS = ["ssh", "http", "ftp", "telnet"]
ACTIVE_THEME = "Dark"


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        result = float(value)
        return result if pd.notna(result) else default
    except (TypeError, ValueError):
        return default


def _severity_from_score(score: float, high_cutoff: float, medium_cutoff: float) -> str:
    if score < high_cutoff:
        return "high"
    if score < medium_cutoff:
        return "medium"
    return "low"


def _anomaly_from_score(score: float, attack_cutoff: float) -> str:
    return "attack" if score < attack_cutoff else "normal"


def _score_classifications(frame: pd.DataFrame, high: float, medium: float, attack: float) -> tuple[pd.Series, pd.Series]:
    tuned_severity: list[str] = []
    tuned_anomaly: list[str] = []
    for _, row in frame.iterrows():
        score = pd.to_numeric(row.get("anomaly_score"), errors="coerce")
        if pd.isna(score):
            tuned_severity.append(str(row.get("severity", "unknown")))
            tuned_anomaly.append(str(row.get("anomaly", "unknown")))
        else:
            tuned_severity.append(_severity_from_score(float(score), high, medium))
            tuned_anomaly.append(_anomaly_from_score(float(score), attack))
    return pd.Series(tuned_severity, index=frame.index), pd.Series(tuned_anomaly, index=frame.index)


def _normalize_tags(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if value is None:
        return []
    text = str(value).strip()
    if not text:
        return []
    if text.startswith("[") and text.endswith("]"):
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                return [str(item).strip() for item in parsed if str(item).strip()]
        except (ValueError, TypeError):
            pass
    return [text]


def _redact_secrets(value: Any) -> Any:
    """Remove submitted credentials from dashboard exports and detail tables."""
    if isinstance(value, dict):
        return {key: ("[REDACTED]" if str(key).lower() in {"password", "passwd", "secret"} else _redact_secrets(item)) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_secrets(item) for item in value]
    return value


def _model_threshold_defaults() -> tuple[float, float, float]:
    try:
        metadata = json.loads((ROOT_DIR / "models" / "model_metadata.json").read_text(encoding="utf-8"))
        thresholds = metadata.get("thresholds", {})
        return (_safe_float(thresholds.get("attack"), -0.2), _safe_float(thresholds.get("severity_high"), -0.5), _safe_float(thresholds.get("severity_medium"), -0.2))
    except (OSError, ValueError, TypeError):
        return -0.2, -0.5, -0.2


def load_sessions(log_path: Path, max_rows: int = 5000) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Read the tail of JSONL without loading the whole file; retain parse diagnostics."""
    info: dict[str, Any] = {"exists": log_path.exists(), "parse_errors": 0, "invalid_records": 0, "bytes": 0}
    if not log_path.exists():
        return [], info
    try:
        info["bytes"] = log_path.stat().st_size
        with log_path.open("rb") as handle:
            handle.seek(0, 2)
            end = handle.tell()
            chunk_size = 65536
            data = b""
            pos = end
            while pos > 0 and data.count(b"\n") <= max_rows:
                take = min(chunk_size, pos)
                pos -= take
                handle.seek(pos)
                data = handle.read(take) + data
        lines = data.decode("utf-8", errors="replace").splitlines()
        if pos > 0 and lines:
            lines = lines[1:]
        lines = lines[-max_rows:]
    except OSError as exc:
        info["read_error"] = str(exc)
        return [], info

    sessions: list[dict[str, Any]] = []
    for line in lines:
        if not line.strip():
            continue
        try:
            record = json.loads(line)
            if isinstance(record, dict):
                sessions.append(record)
            else:
                info["invalid_records"] += 1
        except (json.JSONDecodeError, UnicodeDecodeError):
            info["parse_errors"] += 1
    return sessions, info


def load_events(log_path: Path, max_rows: int = 20000) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Read versioned event JSONL, retaining malformed-record diagnostics."""
    records, info = load_sessions(log_path, max_rows)
    valid = []
    for record in records:
        if isinstance(record.get("event_id"), str) and isinstance(record.get("session_id"), str) and record.get("event_type"):
            valid.append(record)
        else:
            info["invalid_records"] = info.get("invalid_records", 0) + 1
    return valid, info


def enrich_predictions(sessions: list[dict[str, Any]]) -> None:
    if predict_session_anomaly is None:
        return
    for session in sessions:
        if all(key in session for key in ("anomaly", "anomaly_score", "severity")):
            continue
        try:
            prediction = predict_session_anomaly(session)
            for field in ("anomaly", "anomaly_score", "severity", "confidence_label", "confidence_score", "decision_band"):
                if field in prediction:
                    session.setdefault(field, prediction[field])
        except Exception:
            continue


def build_dataframe(sessions: list[dict[str, Any]]) -> pd.DataFrame:
    if not sessions:
        return pd.DataFrame()
    enrich_predictions(sessions)
    frame = pd.DataFrame(sessions).copy()
    defaults: dict[str, Any] = {
        "session_id": "unknown",
        "ip": "unknown",
        "protocol": "unknown",
        "start_time": None,
        "end_time": None,
        "duration": 0,
        "total_login_attempts": 0,
        "commands_count": 0,
        "suspicious_commands_count": 0,
        "anomaly_score": None,
        "anomaly": "unknown",
        "severity": "unknown",
        "attack_type": "none",
        "confidence_label": "unknown",
        "confidence_score": None,
        "decision_band": "unknown",
        "login_attempts": None,
        "commands": None,
    }
    for field, default in defaults.items():
        if field not in frame.columns:
            frame[field] = default
    for column in ("duration", "total_login_attempts", "commands_count", "suspicious_commands_count", "anomaly_score", "confidence_score"):
        frame[column] = pd.to_numeric(frame[column], errors="coerce")
    frame["start_time"] = pd.to_datetime(frame["start_time"], errors="coerce", utc=True)
    frame["end_time"] = pd.to_datetime(frame["end_time"], errors="coerce", utc=True)
    frame["protocol"] = frame["protocol"].fillna("unknown").astype(str).str.lower()
    for column in ("ip", "session_id", "anomaly", "severity", "attack_type", "confidence_label", "decision_band"):
        frame[column] = frame[column].fillna("unknown").astype(str)
    frame["severity"] = frame["severity"].str.lower()
    frame["attack_tags"] = frame.get("attack_tags", pd.Series([[] for _ in range(len(frame))], index=frame.index)).apply(_normalize_tags)
    frame["simulation"] = frame.get("simulation", pd.Series([None] * len(frame), index=frame.index))
    frame["simulation_label"] = frame["simulation"].map({True: "synthetic", False: "observed"}).fillna("unknown")
    frame["auth_outcomes"] = frame.get("login_attempts", pd.Series([[] for _ in range(len(frame))], index=frame.index)).apply(
        lambda attempts: sorted({str(attempt.get("outcome", "unknown")) for attempt in attempts if isinstance(attempt, dict)}) if isinstance(attempts, list) else []
    )
    frame["auth_outcomes_text"] = frame["auth_outcomes"].apply(lambda outcomes: ", ".join(outcomes) if outcomes else "unknown")
    frame["attack_tags_text"] = frame["attack_tags"].apply(lambda tags: ", ".join(tags) if tags else "—")
    frame["attack_type"] = frame["attack_type"].replace({"": "none", "nan": "none"})
    frame["anomaly"] = frame["anomaly"].str.lower()
    frame["anomaly_tuned"] = frame["anomaly"]
    frame["severity_tuned"] = frame["severity"]
    frame["attack_ratio"] = frame["suspicious_commands_count"].fillna(0) / frame["commands_count"].fillna(0).clip(lower=1)
    frame["activity_intensity"] = frame["commands_count"].fillna(0) / frame["duration"].fillna(0).clip(lower=1)
    frame["login_intensity"] = frame["total_login_attempts"].fillna(0) / frame["duration"].fillna(0).clip(lower=1)
    return frame.sort_values("start_time", ascending=False, na_position="last").reset_index(drop=True)


def build_commands_dataframe(sessions: list[dict[str, Any]]) -> pd.DataFrame:
    rows: list[dict[str, Any]] = []
    for session in sessions:
        commands = session.get("commands", [])
        if not isinstance(commands, list):
            continue
        for command in commands:
            if isinstance(command, str):
                command = {"command": command}
            if not isinstance(command, dict):
                continue
            rows.append({
                "session_id": session.get("session_id", "unknown"),
                "ip": session.get("ip", "unknown"),
                "protocol": session.get("protocol", "unknown"),
                "command": str(command.get("command", "")),
                "is_suspicious": bool(command.get("is_suspicious", False)),
                "timestamp": pd.to_datetime(command.get("timestamp"), errors="coerce", utc=True),
            })
    result = pd.DataFrame(rows)
    if not result.empty:
        result["verb"] = result["command"].str.split().str[0].fillna("(empty)")
    return result


def apply_demo_thresholds(frame: pd.DataFrame, commands: pd.DataFrame, high: float, medium: float, attack: float) -> tuple[pd.DataFrame, pd.DataFrame]:
    tuned = frame.copy()
    tuned["severity_tuned"], tuned["anomaly_tuned"] = _score_classifications(tuned, high, medium, attack)
    return tuned, commands.copy()


def inject_styles(theme: str = "Dark") -> None:
    light = theme == "Light"
    tokens = (
        {"bg": "#f1f5f9", "panel": "#ffffff", "panel2": "#f8fafc", "border": "#d7e0ea", "muted": "#5f7185", "text": "#162333", "cyan": "#087eaa", "plot": "plotly_white", "grid": "#e4eaf0"}
        if light else
        {"bg": "#0b1017", "panel": "#111923", "panel2": "#151f2b", "border": "#263445", "muted": "#8fa1b5", "text": "#e6edf5", "cyan": "#38bdf8", "plot": "plotly_dark", "grid": "#202c3a"}
    )
    global ACTIVE_THEME
    ACTIVE_THEME = theme
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=DM+Mono:wght@400;500&display=swap');
    :root { --bg:THEME_BG; --panel:THEME_PANEL; --panel2:THEME_PANEL2; --border:THEME_BORDER; --muted:THEME_MUTED; --text:THEME_TEXT; --cyan:THEME_CYAN; --grid:THEME_GRID; }
    html, body, [class*="css"] { font-family:'Inter',system-ui,-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; }
    .stApp { background:var(--bg); color:var(--text); }
    [data-testid="stHeader"] { background:var(--bg); }
    [data-testid="stSidebar"] { background:var(--panel2); border-right:1px solid var(--border); color:var(--text); }
    [data-testid="stSidebar"] > div:first-child { padding-top:1rem; }
    h1,h2,h3 { letter-spacing:-.025em; }
    h1 { font-size:1.65rem !important; }
    h2 { font-size:1.18rem !important; }
    h3 { font-size:1rem !important; }
    [data-testid="stMetric"] { background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:15px 17px; min-height:112px; }
    [data-testid="stMetricLabel"] { color:var(--muted); font-size:.78rem; }
    [data-testid="stMetricValue"] { font-family:'DM Mono',monospace; font-size:1.55rem; color:var(--text); }
    [data-testid="stMetricDelta"] { font-size:.72rem; }
    div[data-testid="stPlotlyChart"] { background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:8px; }
    [data-testid="stDataFrame"] { border:1px solid var(--border); border-radius:9px; overflow:hidden; }
    .soc-header { display:flex; align-items:center; justify-content:space-between; border:1px solid var(--border); background:var(--panel); border-radius:12px; padding:17px 22px; margin-bottom:20px; }
    .soc-brand { display:flex; gap:13px; align-items:center; }
    .soc-mark { display:grid; place-items:center; width:39px; height:39px; border-radius:10px; background:#10293a; color:var(--cyan); font-size:1.2rem; border:1px solid #1e5068; }
    .soc-title { font-weight:700; font-size:1.08rem; color:var(--text); }
    .soc-subtitle { color:var(--muted); font-size:.76rem; margin-top:2px; }
    .soc-status { color:var(--muted); font: .75rem 'DM Mono',monospace; text-align:right; }
    .soc-status strong { color:#4ade80; font-weight:500; }
    .eyebrow { color:#7f94aa; text-transform:uppercase; letter-spacing:.11em; font: .67rem 'DM Mono',monospace; margin:3px 0 8px; }
    .section-note { color:var(--muted); font-size:.8rem; margin-top:-7px; }
    .stButton button, .stDownloadButton button { border-radius:7px; }
    hr { border-color:var(--border); }
    [data-testid="stTextInput"] input, [data-testid="stSelectbox"] div, [data-testid="stMultiSelect"] div { border-color:var(--border); }
    [data-testid="stAlert"] { border:1px solid var(--border); }
    </style>
    """.replace("THEME_BG", tokens["bg"]).replace("THEME_PANEL2", tokens["panel2"]).replace("THEME_PANEL", tokens["panel"]).replace("THEME_BORDER", tokens["border"]).replace("THEME_MUTED", tokens["muted"]).replace("THEME_TEXT", tokens["text"]).replace("THEME_CYAN", tokens["cyan"]).replace("THEME_GRID", tokens["grid"]), unsafe_allow_html=True)


def chart(fig: Any, height: int = 310) -> None:
    fig.update_layout(
        template="plotly_white" if ACTIVE_THEME == "Light" else "plotly_dark", height=height, margin=dict(l=12, r=12, t=34, b=12),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="Inter, sans-serif", color="#475569" if ACTIVE_THEME == "Light" else "#a8b7c8", size=11),
        colorway=["#0e7490", "#64748b", "#3b82f6", "#eab308", "#f97316", "#dc2626", "#14b8a6"],
        legend_title_text="", hoverlabel=dict(bgcolor="#ffffff" if ACTIVE_THEME == "Light" else "#111923", bordercolor="#cbd5e1" if ACTIVE_THEME == "Light" else "#34465a"),
    )
    fig.update_xaxes(showgrid=False, zeroline=False, linecolor="#d7e0ea" if ACTIVE_THEME == "Light" else "#263445")
    fig.update_yaxes(gridcolor="#e4eaf0" if ACTIVE_THEME == "Light" else "#202c3a", zeroline=False)
    st.plotly_chart(fig, width="stretch")


def metric_row(frame: pd.DataFrame, events: list[dict[str, Any]]) -> None:
    total = len(frame)
    unique_ips = frame["ip"].nunique() if total else 0
    anomalous = int((frame["anomaly_tuned"] == "attack").sum()) if total else 0
    critical_high = int(frame["severity_tuned"].isin(["critical", "high"]).sum()) if total else 0
    logins = int(frame["total_login_attempts"].fillna(0).sum()) if total else 0
    suspicious = int(frame["suspicious_commands_count"].fillna(0).sum()) if total else 0
    protocols = frame.loc[frame["protocol"].ne("unknown"), "protocol"].nunique() if total else 0
    latest = frame["start_time"].dropna().max() if total and frame["start_time"].notna().any() else None
    latest_label = latest.strftime("%d %b · %H:%M UTC") if latest is not None else "—"
    failed = sum(1 for event in events if event.get("event_type") == "authentication_attempt" and event.get("outcome") == "rejected")
    accepted = sum(1 for event in events if event.get("event_type") == "authentication_attempt" and event.get("outcome") == "accepted_simulated")
    http_findings = sum(1 for event in events if event.get("event_type") == "http_request_observed" and event.get("attack_tags"))
    cells = st.columns(4)
    for col, label, value, hint in [
        (cells[0], "CAPTURED SESSIONS", f"{total:,}", "Finalized records"),
        (cells[1], "SOURCE ADDRESSES", f"{unique_ips:,}", "Unique observed IPs"),
        (cells[2], "ANOMALOUS SESSIONS", f"{anomalous:,}", "Current model classification"),
        (cells[3], "HIGH SEVERITY", f"{critical_high:,}", "High or critical labels"),
    ]:
        col.metric(label, value, help=hint)
    cells2 = st.columns(4)
    for col, label, value, hint in [
        (cells2[0], "FAILED AUTHENTICATIONS", f"{failed:,}", "Known rejected attempts; legacy outcomes remain unknown"),
        (cells2[1], "SIMULATED LOGINS ACCEPTED", f"{accepted:,}", "Decoy-policy accepts, not host access"),
        (cells2[2], "HTTP SIGNATURE FINDINGS", f"{http_findings:,}", "HTTP events carrying analyzer tags"),
        (cells2[3], "SUSPICIOUS COMMANDS", f"{suspicious:,}", "Flagged command events"),
    ]:
        col.metric(label, value, help=hint)
    cells3 = st.columns(4)
    for col, label, value, hint in [
        (cells3[0], "ACTIVE PROTOCOLS", f"{protocols}/4", "With captured activity"),
        (cells3[1], "LATEST SESSION", latest_label, "Timestamp as recorded · UTC"),
        (cells3[2], "PERSISTED EVENTS", f"{len(events):,}", "Event records in current scope"),
        (cells3[3], "LOGIN ATTEMPTS", f"{logins:,}", "Captured attempts; historical credentials are redacted in views"),
    ]:
        col.metric(label, value, help=hint)


def filter_sidebar(frame: pd.DataFrame) -> tuple[pd.DataFrame, dict[str, Any]]:
    st.sidebar.markdown("<div class='eyebrow'>Investigation scope</div>", unsafe_allow_html=True)
    protocols = sorted(frame["protocol"].unique().tolist())
    selected_protocols = st.sidebar.multiselect("Protocol", protocols, default=protocols, key="filter_protocol")
    ip_values = sorted(frame["ip"].unique().tolist())
    selected_ips = st.sidebar.multiselect("Source IP", ip_values, default=ip_values, key="filter_ip")
    severities = sorted(frame["severity_tuned"].astype(str).unique().tolist())
    selected_severities = st.sidebar.multiselect("Severity", severities, default=severities, key="filter_severity")
    anomalies = sorted(frame["anomaly_tuned"].astype(str).unique().tolist())
    selected_anomalies = st.sidebar.multiselect("Anomaly class", anomalies, default=anomalies, key="filter_anomaly")
    attack_types = sorted(frame["attack_type"].astype(str).unique().tolist())
    selected_types = st.sidebar.multiselect("Attack type", attack_types, default=attack_types, key="filter_attack_type")
    all_tags = sorted({tag for tags in frame["attack_tags"] for tag in tags})
    selected_tags = st.sidebar.multiselect("Attack tags", all_tags, default=all_tags, key="filter_attack_tags")
    auth_options = sorted({outcome for outcomes in frame["auth_outcomes"] for outcome in outcomes})
    selected_auth = st.sidebar.multiselect("Authentication outcome", auth_options, default=auth_options, key="filter_auth_outcome")
    simulation_options = sorted(frame["simulation_label"].astype(str).unique().tolist())
    selected_simulation = st.sidebar.multiselect("Activity source", simulation_options, default=simulation_options, key="filter_simulation")
    score_values = frame["anomaly_score"].dropna()
    score_range = None
    if not score_values.empty and score_values.min() != score_values.max():
        score_range = st.sidebar.slider("Anomaly score", float(score_values.min()), float(score_values.max()), (float(score_values.min()), float(score_values.max())), key="filter_score")
    valid_times = frame["start_time"].dropna()
    time_range = None
    if not valid_times.empty and valid_times.min() != valid_times.max():
        time_range = st.sidebar.date_input("Session date range (UTC)", value=(valid_times.min().date(), valid_times.max().date()), key="filter_dates")
    result = frame.copy()
    result = result[result["protocol"].isin(selected_protocols)]
    result = result[result["ip"].isin(selected_ips)]
    result = result[result["severity_tuned"].astype(str).isin(selected_severities)]
    result = result[result["anomaly_tuned"].astype(str).isin(selected_anomalies)]
    result = result[result["attack_type"].astype(str).isin(selected_types)]
    if auth_options and len(selected_auth) < len(auth_options):
        result = result[result["auth_outcomes"].apply(lambda outcomes: bool(set(selected_auth).intersection(outcomes)))]
    result = result[result["simulation_label"].astype(str).isin(selected_simulation)]
    if all_tags and len(selected_tags) < len(all_tags):
        tags_set = set(selected_tags)
        result = result[result["attack_tags"].apply(lambda tags: bool(tags_set.intersection(tags)))]
    if score_range: result = result[result["anomaly_score"].between(*score_range)]
    if time_range and len(time_range) == 2:
        low = pd.Timestamp(time_range[0], tz="UTC")
        high = pd.Timestamp(time_range[1], tz="UTC") + pd.Timedelta(days=1)
        result = result[result["start_time"].between(low, high, inclusive="left")]
    controls = {"protocol": selected_protocols, "ip": selected_ips, "severity": selected_severities, "anomaly": selected_anomalies, "attack_type": selected_types, "tags": selected_tags, "authentication_outcome": selected_auth, "simulation": selected_simulation}
    return result, controls


def recent_table(frame: pd.DataFrame, key: str) -> None:
    columns = ["start_time", "ip", "protocol", "anomaly_tuned", "severity_tuned", "attack_type", "anomaly_score"]
    available = [column for column in columns if column in frame]
    st.dataframe(frame[available].head(30), hide_index=True, width="stretch", column_config={
        "start_time": st.column_config.DatetimeColumn("Timestamp", format="YYYY-MM-DD HH:mm:ss.SSS z"),
        "ip": st.column_config.TextColumn("Source IP"),
        "protocol": st.column_config.TextColumn("Protocol"),
        "anomaly_tuned": st.column_config.TextColumn("Detection"),
        "severity_tuned": st.column_config.TextColumn("Severity"),
        "attack_type": st.column_config.TextColumn("Attack type"),
        "anomaly_score": st.column_config.NumberColumn("Model score", format="%.4f"),
    }, key=key)


def render_session_detail(frame: pd.DataFrame, key: str = "session_detail", events: list[dict[str, Any]] | None = None) -> None:
    if frame.empty:
        st.info("No sessions are available in this view.")
        return
    options = frame.index.tolist()
    labels = {idx: f"{frame.loc[idx, 'start_time']} · {frame.loc[idx, 'protocol'].upper()} · {frame.loc[idx, 'ip']} · {frame.loc[idx, 'session_id']}" for idx in options}
    selected_idx = st.selectbox("Select a session", options, format_func=lambda idx: labels[idx], key=key)
    selected = frame.loc[selected_idx]
    a, b, c, d = st.columns(4)
    a.metric("Protocol", selected["protocol"].upper())
    b.metric("Source", str(selected["ip"]))
    c.metric("Detection", str(selected["anomaly_tuned"]).title())
    d.metric("Severity", str(selected["severity_tuned"]).title())
    left, right = st.columns([1, 1])
    with left:
        st.markdown("**Session metadata**")
        fields = ["session_id", "start_time", "end_time", "duration", "total_login_attempts", "commands_count", "suspicious_commands_count", "anomaly", "anomaly_score", "severity", "confidence_label", "confidence_score", "decision_band", "attack_type", "attack_tags"]
        st.json({field: selected.get(field) for field in fields if field in selected.index}, expanded=True)
    with right:
        with st.expander("Login attempts", expanded=True):
            attempts = selected.get("login_attempts")
            if isinstance(attempts, list) and attempts:
                # Credentials are intentionally omitted from dashboard rendering.
                safe_attempts = [_redact_secrets(item) for item in attempts]
                st.dataframe(pd.DataFrame(safe_attempts), hide_index=True, width="stretch")
            else:
                st.caption("No login attempts recorded.")
        with st.expander("Recorded command and request events", expanded=True):
            commands = selected.get("commands")
            if isinstance(commands, list) and commands:
                st.dataframe(pd.DataFrame([_redact_secrets(item) for item in commands]), hide_index=True, width="stretch")
            else:
                st.caption("No command or request events recorded.")
        with st.expander("HTTP analysis fields"):
            http_fields = [field for field in selected.index if any(word in str(field).lower() for word in ("http", "payload", "method", "path", "signature", "reason", "status"))]
            if http_fields:
                st.json({field: selected.get(field) for field in http_fields})
            else:
                st.caption("No structured HTTP payload-analysis fields are present in this session record.")
    session_events = [event for event in (events or []) if str(event.get("session_id")) == str(selected.get("session_id"))]
    with st.expander("Versioned event evidence", expanded=bool(session_events)):
        if session_events:
            safe_events = [_redact_secrets(event) for event in session_events]
            event_rows = [{"timestamp": event.get("timestamp"), "event_type": event.get("event_type"), "action": event.get("action"), "outcome": event.get("outcome"), "severity": event.get("severity"), "simulation": event.get("simulation"), "event_id": event.get("event_id")} for event in safe_events]
            st.dataframe(pd.DataFrame(event_rows), hide_index=True, width="stretch")
            event_id = st.selectbox("Inspect event", [str(event.get("event_id")) for event in safe_events], key=f"{key}_event")
            st.json(next(event for event in safe_events if str(event.get("event_id")) == event_id), expanded=True)
        else:
            st.caption("No versioned event records are linked to this session.")


def render_overview(frame: pd.DataFrame, events: list[dict[str, Any]]) -> None:
    metric_row(frame, events)
    st.markdown("<div class='eyebrow'>Threat landscape</div>", unsafe_allow_html=True)
    c1, c2 = st.columns([1.55, 1])
    with c1:
        st.subheader("Session activity")
        timeline = frame.dropna(subset=["start_time"]).copy()
        if timeline.empty:
            st.info("No valid session timestamps are available.")
        else:
            span = (timeline["start_time"].max() - timeline["start_time"].min()).total_seconds()
            unit = "min" if span <= 86400 else "h" if span <= 1209600 else "D"
            timeline["time_bucket"] = timeline["start_time"].dt.floor(unit)
            counts = timeline.groupby(["time_bucket", "severity_tuned"], observed=True).size().reset_index(name="sessions")
            fig = px.area(counts, x="time_bucket", y="sessions", color="severity_tuned", category_orders={"severity_tuned": SEVERITY_ORDER}, color_discrete_map=SEVERITY_COLORS)
            fig.update_layout(xaxis_title="Recorded time (UTC)", yaxis_title="Sessions")
            chart(fig, 330)
    with c2:
        st.subheader("Protocol mix")
        data = frame["protocol"].value_counts().rename_axis("protocol").reset_index(name="sessions")
        if data.empty: st.info("No protocol values are recorded.")
        else: chart(px.pie(data, names="protocol", values="sessions", hole=.62, color_discrete_sequence=["#38bdf8", "#818cf8", "#2dd4bf", "#f59e0b", "#64748b"]), 330)
    c3, c4 = st.columns(2)
    with c3:
        st.subheader("Severity distribution")
        data = frame["severity_tuned"].astype(str).value_counts().rename_axis("severity").reset_index(name="sessions")
        if not data.empty: chart(px.bar(data, x="severity", y="sessions", color="severity", category_orders={"severity": SEVERITY_ORDER}, color_discrete_map=SEVERITY_COLORS), 275)
        else: st.info("No severity labels available.")
    with c4:
        st.subheader("Detection outcome")
        data = frame["anomaly_tuned"].astype(str).value_counts().rename_axis("classification").reset_index(name="sessions")
        if not data.empty: chart(px.bar(data, x="classification", y="sessions", color="classification", color_discrete_map={"attack": "#f97316", "normal": "#22c55e", "unknown": "#64748b"}), 275)
        else: st.info("No detection outcomes available.")
    c5, c6 = st.columns(2)
    with c5:
        st.subheader("Observed attack types")
        data = frame[frame["attack_type"].ne("none")]["attack_type"].value_counts().head(10).rename_axis("attack_type").reset_index(name="sessions")
        if not data.empty: chart(px.bar(data.sort_values("sessions"), x="sessions", y="attack_type", orientation="h", color_discrete_sequence=["#38bdf8"]), 300)
        else: st.info("No attack types are present in the current scope.")
    with c6:
        st.subheader("Top source addresses")
        data = frame.groupby("ip", as_index=False).agg(sessions=("session_id", "count"), suspicious_commands=("suspicious_commands_count", "sum")).sort_values("sessions", ascending=False).head(10)
        if not data.empty: chart(px.bar(data.sort_values("sessions"), x="sessions", y="ip", orientation="h", color="suspicious_commands", color_continuous_scale=["#164e63", "#38bdf8"]), 300)
        else: st.info("No source addresses are recorded.")
    c7, c8 = st.columns(2)
    with c7:
        st.subheader("Authentication outcomes")
        auth = [event for event in events if event.get("event_type") == "authentication_attempt"]
        if auth:
            auth_counts = pd.Series([event.get("outcome", "unknown") for event in auth]).value_counts().rename_axis("outcome").reset_index(name="attempts")
            chart(px.bar(auth_counts, x="outcome", y="attempts", color="outcome", color_discrete_map={"rejected": "#f97316", "accepted_simulated": "#14b8a6", "unknown": "#64748b"}), 270)
        else: st.info("Authentication outcomes are unavailable for the selected event records.")
    with c8:
        st.subheader("Observed attack stages")
        stage_counts = pd.Series([stage_for_event(event) for event in events]).value_counts().rename_axis("stage").reset_index(name="events") if events else pd.DataFrame()
        if not stage_counts.empty: chart(px.bar(stage_counts.sort_values("events"), x="events", y="stage", orientation="h", color_discrete_sequence=["#38bdf8"]), 270)
        else: st.info("No event-level stages are available.")
    score_frame = frame.dropna(subset=["anomaly_score"])
    st.subheader("Model anomaly-score distribution")
    if score_frame.empty: st.info("No model anomaly scores are available in this scope.")
    else: chart(px.histogram(score_frame, x="anomaly_score", color="severity_tuned", nbins=30, color_discrete_map=SEVERITY_COLORS), 260)
    tags = frame[["attack_tags"]].explode("attack_tags").dropna()
    if not tags.empty:
        st.subheader("Observed behavior tags")
        tag_counts = tags[tags["attack_tags"].astype(str).ne("")]["attack_tags"].value_counts().head(12).rename_axis("tag").reset_index(name="sessions")
        if not tag_counts.empty: chart(px.bar(tag_counts.sort_values("sessions"), x="sessions", y="tag", orientation="h", color_discrete_sequence=["#818cf8"]), 280)
    st.subheader("Recent finalized sessions")
    recent_table(frame, "overview_recent")


def render_live(frame: pd.DataFrame, events: list[dict[str, Any]], refreshed_at: datetime) -> None:
    st.caption(f"Log snapshot refreshed {refreshed_at.strftime('%Y-%m-%d %H:%M:%S UTC')} · Records appear after session finalization and the next refresh.")
    event_frame = pd.DataFrame(events)
    if not event_frame.empty:
        event_frame["source"] = event_frame["simulation"].map({True: "synthetic scenario", False: "observed input / decoy response"}).fillna("unknown")
        e1, e2, e3, e4 = st.columns(4)
        protocols = sorted(event_frame["protocol"].dropna().astype(str).unique())
        selected_protocols = e1.multiselect("Event protocol", protocols, default=protocols, key="live_event_protocol")
        sources = sorted(event_frame["source"].unique())
        selected_sources = e2.multiselect("Event source", sources, default=sources, key="live_event_source")
        ips = sorted(event_frame["source_ip"].dropna().astype(str).unique())
        selected_ips = e3.multiselect("Event source IP", ips, default=ips, key="live_event_ip")
        kinds = sorted(event_frame["event_type"].dropna().astype(str).unique())
        selected_kinds = e4.multiselect("Event type", kinds, default=kinds, key="live_event_type")
        event_frame = event_frame[event_frame["protocol"].isin(selected_protocols) & event_frame["source"].isin(selected_sources) & event_frame["source_ip"].isin(selected_ips) & event_frame["event_type"].isin(selected_kinds)]
        event_cols = [column for column in ["timestamp", "source_ip", "protocol", "event_type", "action", "outcome", "severity", "source", "session_id"] if column in event_frame]
        st.subheader("Latest persisted events")
        st.dataframe(event_frame[event_cols].sort_values("timestamp", ascending=False).head(200), hide_index=True, width="stretch")
    else:
        st.info("No event-level records are available. Legacy sessions will still appear below with reconstructed summary events.")
    st.metric("Latest finalized session", frame["start_time"].max().strftime("%Y-%m-%d %H:%M:%S UTC") if frame["start_time"].notna().any() else "Unknown")
    recent_table(frame, "live_activity_table")
    render_session_detail(frame.head(300), "live_session_detail", events)


def render_attack_flow(frame: pd.DataFrame, events: list[dict[str, Any]], relationships: list[dict[str, Any]]) -> None:
    if frame.empty:
        st.info("No sessions available for attack-flow reconstruction.")
        return
    labels = {str(row.session_id): f"{row.start_time} · {str(row.protocol).upper()} · {row.ip} · {row.session_id}" for row in frame.itertuples()}
    session_id = st.selectbox("Investigation session", list(labels), format_func=lambda key: labels[key], key="flow_session")
    flow = reconstruct_flow(frame.to_dict(orient="records"), events, session_id)
    current = flow.get("session", {})
    st.caption("Timeline contains persisted observations. ‘Potentially related’ links use same source address and time window only; they do not establish common attribution.")
    if not flow["events"]:
        st.info("No event records are linked to this session. Historical summaries can show only evidence they retained.")
    else:
        timeline = pd.DataFrame([{"time": pd.to_datetime(event.get("timestamp"), errors="coerce", utc=True), "stage": stage_for_event(event), "action": event.get("action", "unknown"), "outcome": event.get("outcome", "unknown"), "event_id": event.get("event_id"), "event": event} for event in flow["events"]])
        st.subheader("Chronological attack timeline")
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=timeline["time"], y=timeline["stage"], mode="lines+markers", marker={"size": 11, "color":"#38bdf8"}, line={"color":"#38bdf8","width":2}, customdata=timeline[["action","outcome","event_id"]], hovertemplate="%{x}<br>%{y}<br>%{customdata[0]}<br>Outcome: %{customdata[1]}<br>Event: %{customdata[2]}<extra></extra>"))
        chart(fig, max(260, min(580, 85 + 45 * len(timeline))))
        st.subheader("Observed stage progression")
        stage_frame = pd.DataFrame({"order": range(1, len(flow["stages"]) + 1), "stage": flow["stages"]})
        if not stage_frame.empty: chart(px.scatter(stage_frame, x="order", y="stage", text="stage", color_discrete_sequence=["#14b8a6"]), 220)
        st.subheader("Event evidence")
        event_rows = [{"timestamp": event.get("timestamp"), "stage": stage_for_event(event), "action": event.get("action"), "outcome": event.get("outcome"), "evidence": json.dumps(event.get("evidence"), ensure_ascii=False), "source": "synthetic" if event.get("simulation") else "observed", "event_id": event.get("event_id")} for event in flow["events"]]
        st.dataframe(pd.DataFrame(event_rows), hide_index=True, width="stretch")
        event_ids = [str(event.get("event_id")) for event in flow["events"]]
        selected_event_id = st.selectbox("Inspect event evidence", event_ids, key="flow_event_detail")
        selected_event = next(event for event in flow["events"] if str(event.get("event_id")) == selected_event_id)
        st.json(_redact_secrets(selected_event), expanded=True)
    same_session = current.get("session_id")
    related = [edge for edge in relationships if same_session in {edge["source_session_id"], edge["target_session_id"]}]
    st.subheader("Potentially related sessions")
    if related:
        st.dataframe(pd.DataFrame(related), hide_index=True, width="stretch")
        node_ids = sorted({same_session} | {edge["source_session_id"] for edge in related} | {edge["target_session_id"] for edge in related})
        node_labels = {str(row.get("session_id")): f"{str(row.get('protocol','unknown')).upper()} · {row.get('session_id')}" for row in frame.to_dict(orient="records")}
        positions = {node_id: (index % 2, index // 2) for index, node_id in enumerate(node_ids)}
        graph = go.Figure()
        for edge in related:
            start, end = positions[edge["source_session_id"]], positions[edge["target_session_id"]]
            graph.add_trace(go.Scatter(x=[start[0], end[0]], y=[start[1], end[1]], mode="lines", line={"color":"#94a3b8","dash":"dot","width":2}, hoverinfo="text", text=[edge["caveat"], edge["caveat"]], showlegend=False))
        graph.add_trace(go.Scatter(x=[positions[node][0] for node in node_ids], y=[positions[node][1] for node in node_ids], mode="markers+text", marker={"size":22,"color":["#0e7490" if node == same_session else "#64748b" for node in node_ids]}, text=[node_labels.get(node,node) for node in node_ids], textposition="bottom center", customdata=node_ids, hovertemplate="Session %{customdata}<br>%{text}<extra></extra>", showlegend=False))
        graph.update_xaxes(visible=False); graph.update_yaxes(visible=False, scaleanchor="x", scaleratio=1)
        chart(graph, max(230, min(420, 150 + len(node_ids)*40)))
    else: st.caption("No same-source sessions fell within the configured correlation window.")
    st.subheader("Observed outcome and unresolved questions")
    st.info(flow["outcome"])
    for limitation in flow["unresolved"]: st.caption("• " + limitation)
    flow_recommendations = generate_recommendations([flow["session"]], flow["events"])
    st.subheader("Recommendations for this investigation")
    if flow_recommendations:
        for recommendation in flow_recommendations:
            st.write(f"**{recommendation['priority'].title()} · {recommendation['title']}** — {recommendation['reason']}")
    else:
        st.caption("No recommendation rule matched this session's recorded evidence.")


def render_recommendations(frame: pd.DataFrame, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    recommendations = generate_recommendations(frame.to_dict(orient="records"), events)
    st.caption("Guidance is generated only from recorded honeypot evidence. It does not assert that production systems share an observed weakness and does not run remediation automatically.")
    if not recommendations:
        st.success("No recommendation rules matched the current evidence. This is not a security certification.")
    for recommendation in recommendations:
        with st.expander(f"{recommendation['priority'].upper()} · {recommendation['title']} · {recommendation['recommendation_id']}", expanded=True):
            a, b = st.columns([2, 1])
            with a:
                st.markdown("**Observed evidence**")
                st.write(recommendation["reason"])
                st.markdown("**Suggested review steps**")
                for step in recommendation["remediation_steps"]: st.write("• " + step)
            with b:
                st.write("Area:", recommendation["area"])
                st.write("Effort:", recommendation["effort_estimate"])
                st.write("Potential benefit:", recommendation["expected_benefit"])
                st.write("Evidence sessions:", ", ".join(recommendation["source_session_ids"]) or "—")
                st.caption(recommendation["finding_scope"])
    return recommendations


def render_reports(frame: pd.DataFrame, events: list[dict[str, Any]], recommendations: list[dict[str, Any]]) -> None:
    sessions = frame.to_dict(orient="records")
    mode = st.radio("Report type", ["Individual investigation", "Aggregate security report"], horizontal=True, key="report_mode")
    if mode == "Individual investigation" and sessions:
        labels = {str(row.get("session_id")): f"{row.get('start_time')} · {str(row.get('protocol','unknown')).upper()} · {row.get('ip')} · {row.get('session_id')}" for row in sessions}
        selected_id = st.selectbox("Session to report", list(labels), format_func=lambda key: labels[key], key="report_session")
        report_sessions = [session for session in sessions if str(session.get("session_id")) == selected_id]
        report_events = [event for event in events if str(event.get("session_id")) == selected_id]
        report_recommendations = generate_recommendations(report_sessions, report_events)
        report = investigation_report(reconstruct_flow(sessions, events, selected_id), report_recommendations)
    else:
        report = aggregate_report(sessions, events, recommendations)
    st.subheader("Report preview")
    st.caption("Secrets are redacted. Source addresses are reported as observed indicators, not actor attribution.")
    st.json(report, expanded=True)
    report_json = json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8")
    html_data = report_html(report).encode("utf-8")
    pdf_data = report_pdf(report)
    report_id = str(report.get("investigation_id", "aggregate-report"))
    a, b, c = st.columns(3)
    a.download_button("Download JSON", report_json, f"{report_id}.json", "application/json", width="stretch")
    b.download_button("Download print-ready HTML", html_data, f"{report_id}.html", "text/html", width="stretch")
    c.download_button("Download PDF", pdf_data, f"{report_id}.pdf", "application/pdf", width="stretch")
    csv_frame = frame.drop(columns=["attack_tags"], errors="ignore").copy()
    for column in csv_frame.columns:
        if csv_frame[column].map(lambda value: isinstance(value, (dict, list))).any():
            csv_frame[column] = csv_frame[column].map(lambda value: json.dumps(_redact_secrets(value), ensure_ascii=False) if isinstance(value, (dict, list)) else value)
    st.download_button("Download filtered session CSV", csv_frame.to_csv(index=False).encode("utf-8"), "phantom-pot-sessions.csv", "text/csv", width="stretch")
    if events:
        event_frame = pd.DataFrame([_redact_secrets(event) for event in events])
        for column in event_frame.columns:
            if event_frame[column].map(lambda value: isinstance(value, (dict, list))).any():
                event_frame[column] = event_frame[column].map(lambda value: json.dumps(_redact_secrets(value), ensure_ascii=False) if isinstance(value, (dict, list)) else value)
        st.download_button("Download filtered event CSV", event_frame.to_csv(index=False).encode("utf-8"), "phantom-pot-events.csv", "text/csv", width="stretch")


def render_attack_intelligence(frame: pd.DataFrame, commands: pd.DataFrame, events: list[dict[str, Any]]) -> None:
    a, b = st.columns(2)
    with a:
        st.subheader("Attack type distribution")
        data = frame[frame["attack_type"].ne("none")]["attack_type"].value_counts().rename_axis("attack_type").reset_index(name="sessions")
        if not data.empty: chart(px.bar(data, x="sessions", y="attack_type", orientation="h", color_discrete_sequence=["#f97316"]), 310)
        else: st.info("No typed attacks in the selected records.")
    with b:
        st.subheader("Attack tags and signatures")
        tags = frame[["attack_tags"]].explode("attack_tags").dropna()
        data = tags["attack_tags"].value_counts().head(15).rename_axis("tag").reset_index(name="sessions")
        if not data.empty: chart(px.bar(data, x="sessions", y="tag", orientation="h", color_discrete_sequence=["#38bdf8"]), 310)
        else: st.info("No attack tags are present in this dataset.")
    st.subheader("Suspicious command patterns")
    if commands.empty: st.info("No recorded command events are available.")
    else:
        suspicious = commands[commands["is_suspicious"]]
        if suspicious.empty: st.info("No command event is marked suspicious in this scope.")
        else:
            counts = suspicious["verb"].value_counts().head(15).rename_axis("command").reset_index(name="events")
            chart(px.bar(counts, x="events", y="command", orientation="h", color_discrete_sequence=["#fb923c"]), 280)
            st.dataframe(suspicious[["timestamp", "ip", "protocol", "command"]].head(100), hide_index=True, width="stretch")
    st.subheader("HTTP request intelligence")
    http = frame[frame["protocol"] == "http"]
    if http.empty:
        st.info("No HTTP sessions in the current filter scope.")
    else:
        events = []
        for _, row in http.iterrows():
            for event in row.get("commands", []) if isinstance(row.get("commands"), list) else []:
                raw = event.get("command", "") if isinstance(event, dict) else str(event)
                if raw:
                    parts = raw.split(" ", 1)
                    events.append({"method": parts[0], "path": parts[1] if len(parts) > 1 else "/", "source": row["ip"], "suspicious": bool(event.get("is_suspicious", False)) if isinstance(event, dict) else False})
        if not events: st.info("HTTP sessions are present, but no structured method/path payload fields were recorded.")
        else:
            http_events = pd.DataFrame(events)
            h1, h2 = st.columns(2)
            with h1: chart(px.bar(http_events["method"].value_counts().rename_axis("method").reset_index(name="requests"), x="method", y="requests", color_discrete_sequence=["#38bdf8"]), 260)
            with h2:
                paths = http_events.groupby(["path", "suspicious"], as_index=False).size().sort_values("size", ascending=False).head(12)
                chart(px.bar(paths, x="size", y="path", color="suspicious", orientation="h", color_discrete_map={True: "#f97316", False: "#38bdf8"}), 260)
            st.dataframe(http_events, hide_index=True, width="stretch")
        st.caption("Payload-analysis reasons and HTTP status codes are not present in the current session log schema.")
    high = frame[frame["anomaly_tuned"].eq("attack")]
    if not high.empty:
        st.subheader("Highest model anomaly scores")
        cols = ["start_time", "ip", "protocol", "anomaly_score", "severity_tuned", "attack_type", "attack_tags_text"]
        st.dataframe(high[cols].sort_values("anomaly_score").head(25), hide_index=True, width="stretch")
    st.subheader("Authentication patterns")
    auth = [event for event in events if event.get("event_type") == "authentication_attempt"]
    if auth:
        outcomes = pd.DataFrame([{"outcome": event.get("outcome", "unknown"), "protocol": event.get("protocol", "unknown"), "username": (event.get("evidence") or {}).get("username", "unknown")} for event in auth])
        x, y = st.columns(2)
        with x: chart(px.histogram(outcomes, x="outcome", color="protocol", barmode="group"), 270)
        with y:
            top_users = outcomes["username"].value_counts().head(10).rename_axis("submitted username").reset_index(name="attempts")
            chart(px.bar(top_users.sort_values("attempts"), x="attempts", y="submitted username", orientation="h", color_discrete_sequence=["#64748b"]), 270)
        if any(event.get("outcome") == "unknown" for event in auth): st.caption("Some historical login attempts have unknown outcomes because their original session summaries did not record acceptance or rejection.")
    else: st.info("No authentication-attempt events are present in this scope.")
    st.subheader("Repeated activity over time")
    activity = pd.DataFrame([{"timestamp": pd.to_datetime(event.get("timestamp"), errors="coerce", utc=True), "protocol": event.get("protocol", "unknown")} for event in events])
    if not activity.empty and activity["timestamp"].notna().any():
        activity["bucket"] = activity["timestamp"].dt.floor("h")
        counts = activity.groupby(["bucket", "protocol"]).size().reset_index(name="events")
        chart(px.line(counts, x="bucket", y="events", color="protocol", markers=True), 280)
    else: st.info("No timestamped activity events are available.")


def render_protocol_analytics(frame: pd.DataFrame, events: list[dict[str, Any]] | None = None) -> None:
    available = [p for p in EXPECTED_PROTOCOLS if p in set(frame["protocol"])]
    if not available:
        st.info("No sessions for SSH, HTTP, FTP, or Telnet are present in this filter scope.")
        return
    protocol = st.selectbox("Protocol focus", available, key="protocol_focus")
    selected = frame[frame["protocol"] == protocol]
    st.markdown(f"<div class='eyebrow'>{protocol.upper()} investigation</div>", unsafe_allow_html=True)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Sessions", f"{len(selected):,}")
    c2.metric("Login attempts", f"{int(selected['total_login_attempts'].fillna(0).sum()):,}")
    c3.metric("Suspicious commands", f"{int(selected['suspicious_commands_count'].fillna(0).sum()):,}")
    duration_mean = selected["duration"].mean()
    c4.metric("Mean duration", f"{duration_mean:.3f}s" if pd.notna(duration_mean) else "—")
    left, right = st.columns(2)
    with left:
        data = selected["severity_tuned"].astype(str).value_counts().rename_axis("severity").reset_index(name="sessions")
        st.subheader("Severity")
        if not data.empty: chart(px.bar(data, x="severity", y="sessions", color="severity", color_discrete_map=SEVERITY_COLORS), 280)
        else: st.info("No severity values available.")
    with right:
        st.subheader("Session activity over time")
        timed = selected.dropna(subset=["start_time"]).copy()
        if timed.empty: st.info("No valid timestamps available.")
        else:
            timed["bucket"] = timed["start_time"].dt.floor("h")
            data = timed.groupby("bucket").size().reset_index(name="sessions")
            chart(px.line(data, x="bucket", y="sessions", markers=True, color_discrete_sequence=["#38bdf8"]), 280)
    st.subheader("Protocol sessions")
    recent_table(selected, f"protocol_table_{protocol}")
    render_session_detail(selected.head(300), f"protocol_detail_{protocol}", events)
    if protocol == "http":
        st.caption("HTTP status codes and structured payload-analysis findings are not available in the current stored session records.")


def render_ml(frame: pd.DataFrame, high: float, medium: float, attack: float) -> None:
    st.caption("Model anomaly score, dashboard confidence metadata, and severity are separate fields. Threshold controls below change dashboard classification only; they do not alter the running honeypot or model artifacts.")
    original = int(frame["anomaly"].eq("attack").sum())
    tuned = int(frame["anomaly_tuned"].eq("attack").sum())
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Model anomaly labels", f"{original:,}")
    c2.metric("Dashboard threshold result", f"{tuned:,}")
    c3.metric("Mean model score", f"{frame['anomaly_score'].mean():.4f}" if frame["anomaly_score"].notna().any() else "—")
    c4.metric("Mean confidence score", f"{frame['confidence_score'].mean():.3f}" if frame["confidence_score"].notna().any() else "—")
    left, right = st.columns(2)
    with left:
        st.subheader("Anomaly score distribution")
        scores = frame.dropna(subset=["anomaly_score"])
        if scores.empty: st.info("No model scores are available.")
        else:
            fig = px.histogram(scores, x="anomaly_score", color="severity_tuned", nbins=35, color_discrete_map=SEVERITY_COLORS)
            for value, color, label in [(attack, "#38bdf8", "Attack threshold"), (high, "#ef4444", "High severity"), (medium, "#eab308", "Medium severity")]:
                fig.add_vline(x=value, line_dash="dash", line_color=color, annotation_text=label)
            chart(fig, 320)
    with right:
        st.subheader("Confidence labels")
        data = frame["confidence_label"].value_counts().rename_axis("confidence label").reset_index(name="sessions")
        if not data.empty: chart(px.bar(data, x="confidence label", y="sessions", color_discrete_sequence=["#818cf8"]), 320)
        else: st.info("Confidence labels are not present.")
    c3, c4 = st.columns(2)
    with c3:
        st.subheader("Decision bands")
        data = frame["decision_band"].value_counts().rename_axis("decision band").reset_index(name="sessions")
        if not data.empty: chart(px.bar(data, x="sessions", y="decision band", orientation="h", color_discrete_sequence=["#2dd4bf"]), 270)
        else: st.info("Decision-band values are not present.")
    with c4:
        st.subheader("Dashboard threshold tuning")
        attack_new = st.slider("Attack score cutoff", -1.0, 0.5, float(attack), .01, key="ml_attack_cutoff")
        high_new = st.slider("High severity cutoff", -1.5, 0.0, float(high), .01, key="ml_high_cutoff")
        medium_new = st.slider("Medium severity cutoff", -1.0, 0.5, float(medium), .01, key="ml_medium_cutoff")
        tuned_severity, tuned_attack = _score_classifications(frame, high_new, medium_new, attack_new)
        st.metric("Sessions classified attack with these settings", f"{int(tuned_attack.eq('attack').sum()):,}")
        st.caption(f"Current visualization cutoffs: attack < {attack_new:.2f} · high < {high_new:.2f} · medium < {medium_new:.2f}")


def render_health(log_path: Path, info: dict[str, Any], frame: pd.DataFrame, config_path: Path, error_path: Path, event_path: Path | None = None, event_info: dict[str, Any] | None = None, events: list[dict[str, Any]] | None = None) -> None:
    st.caption("Health checks report file/config/artifact availability. Configured ports do not prove that listeners are running.")
    model_files = [ROOT_DIR / "models" / "isolation_forest.pkl", ROOT_DIR / "models" / "scaler.pkl", ROOT_DIR / "models" / "model_metadata.json"]
    try:
        import yaml
        config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        config_status = "Readable"
        config_error = None
    except Exception as exc:
        config, config_status, config_error = {}, "Unavailable", str(exc)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Session log", "Readable" if info.get("exists") and not info.get("read_error") else "Unavailable")
    c2.metric("Records loaded", f"{len(frame):,}")
    c3.metric("Malformed lines", f"{info.get('parse_errors', 0):,}")
    c4.metric("Config", config_status)
    if event_path is not None:
        st.metric("Event log", "Readable" if (event_info or {}).get("exists") and not (event_info or {}).get("read_error") else "Unavailable")
        latest_event = max((str(event.get("timestamp", "")) for event in (events or [])), default="Unknown")
        st.caption(f"Latest event timestamp in loaded scope: {latest_event or 'Unknown'}")
    details = [
        {"Check": "Session log", "Status": "available" if info.get("exists") else "missing", "Detail": str(log_path)},
        {"Check": "Log size", "Status": "known", "Detail": f"{info.get('bytes', 0):,} bytes"},
        {"Check": "Invalid JSON records", "Status": "none" if info.get("parse_errors", 0) == 0 and info.get("invalid_records", 0) == 0 else "present", "Detail": f"{info.get('parse_errors', 0)} parse errors · {info.get('invalid_records', 0)} non-object records"},
        {"Check": "Configuration", "Status": config_status.lower(), "Detail": str(config_path) if not config_error else config_error},
    ]
    if event_path is not None:
        event_info = event_info or {}
        details.append({"Check": "Versioned event log", "Status": "available" if event_info.get("exists") and not event_info.get("read_error") else "missing or unreadable", "Detail": f"{event_path} · {event_info.get('bytes', 0):,} bytes · {event_info.get('parse_errors', 0)} malformed lines"})
    for artifact in model_files:
        details.append({"Check": f"Model artifact · {artifact.name}", "Status": "available" if artifact.exists() else "missing", "Detail": str(artifact.relative_to(ROOT_DIR))})
    if "read_error" in info: details.append({"Check": "Log read", "Status": "error", "Detail": info["read_error"]})
    st.subheader("Verified component status")
    st.dataframe(pd.DataFrame(details), hide_index=True, width="stretch")
    st.subheader("Configured protocol ports")
    port_rows = []
    for protocol in EXPECTED_PROTOCOLS:
        settings = config.get(protocol, {}) if isinstance(config, dict) else {}
        port_rows.append({"Protocol": protocol.upper(), "Configured host": settings.get("host", "unknown"), "Configured port": settings.get("port", "unknown"), "Listener status": "Unknown · not probed"})
    st.dataframe(pd.DataFrame(port_rows), hide_index=True, width="stretch")
    st.subheader("Recent runtime errors")
    if error_path.exists():
        try:
            lines = error_path.read_text(encoding="utf-8", errors="replace").splitlines()[-50:]
            if lines: st.code("\n".join(lines), language="text")
            else: st.caption("Error log exists and is empty.")
        except OSError as exc: st.warning(f"Could not read error log: {exc}")
    else: st.caption("Error log file is not present.")


def render_kpis(frame: pd.DataFrame) -> None:
    st.caption("Descriptive counts from captured records. These are not independent model validation measurements.")
    if frame.empty:
        st.info("No records available for KPI summaries.")
        return
    attacks = int(frame["anomaly"].eq("attack").sum())
    normal = int(frame["anomaly"].eq("normal").sum())
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Captured sessions", f"{len(frame):,}")
    c2.metric("Model attack labels", f"{attacks:,}")
    c3.metric("Model normal labels", f"{normal:,}")
    c4.metric("Captured login attempts", f"{int(frame['total_login_attempts'].fillna(0).sum()):,}")
    a, b = st.columns(2)
    with a:
        data = frame.groupby("protocol", as_index=False).agg(sessions=("session_id", "count"), model_attacks=("anomaly", lambda values: values.eq("attack").sum()))
        chart(px.bar(data, x="protocol", y=["sessions", "model_attacks"], barmode="group", color_discrete_sequence=["#38bdf8", "#f97316"]), 300)
    with b:
        chart(px.histogram(frame, x="duration", color="protocol", nbins=30), 300)


def main() -> None:
    st.set_page_config(page_title="PhantomPot | Security Operations", page_icon="◈", layout="wide", initial_sidebar_state="expanded")
    if "theme" not in st.session_state:
        st.session_state.theme = "Dark"
    inject_styles(st.session_state.theme)
    st.markdown("""
    <div class="soc-header">
      <div class="soc-brand"><div class="soc-mark">◈</div><div><div class="soc-title">PhantomPot <span style="color:#8295a9;font-weight:500">/ SECURITY OPERATIONS</span></div><div class="soc-subtitle">Multi-protocol honeypot · Threat investigation and anomaly monitoring</div></div></div>
      <div class="soc-status"><strong>● DATA VIEW</strong><br/>Refresh to load latest finalized sessions</div>
    </div>
    """, unsafe_allow_html=True)
    default_log = ROOT_DIR / "logs" / "sessions.jsonl"
    with st.sidebar:
        st.markdown("<div class='eyebrow'>Workspace</div>", unsafe_allow_html=True)
        theme = st.selectbox("Appearance", ["Dark", "Light"], key="theme")
        if theme != ACTIVE_THEME:
            inject_styles(theme)
        log_path = Path(st.text_input("Session log", str(default_log), key="log_path"))
        event_path = Path(st.text_input("Event log", str(ROOT_DIR / "logs" / "events.jsonl"), key="event_path"))
        max_rows = st.select_slider("Load latest records", options=[500, 1000, 2500, 5000, 10000, 20000], value=5000)
        auto_refresh = st.toggle("Auto-refresh", value=False, help="Periodically reloads the log; this is not push-based live streaming.")
        interval = st.select_slider("Refresh interval", options=[5, 10, 15, 30, 60], value=10, format_func=lambda value: f"{value} sec", disabled=not auto_refresh)
        if st.button("Refresh data", width="stretch"):
            st.cache_data.clear()
            st.rerun()
        st.divider()
        st.markdown("<div class='eyebrow'>Dashboard-only thresholds</div>", unsafe_allow_html=True)
        default_attack, default_high, default_medium = _model_threshold_defaults()
        attack = st.slider("Attack score cutoff", -1.0, 0.5, default_attack, .01, help="Session is shown as attack below this model score.")
        high = st.slider("High severity cutoff", -1.5, 0.0, default_high, .01)
        medium = st.slider("Medium severity cutoff", -1.0, 0.5, default_medium, .01)
        if high >= medium:
            st.warning("For ordered severity bands, the high cutoff should be lower than the medium cutoff.")
        st.divider()
        st.caption("Thresholds only change this dashboard view. They do not alter honeypot runtime detection or model files.")

    @st.cache_data(show_spinner="Reading session log…")
    def cached_load(path: str, limit: int, modified: int, size: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        return load_sessions(Path(path), limit)

    @st.cache_data(show_spinner="Reading event log…")
    def cached_events(path: str, limit: int, modified: int, size: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        return load_events(Path(path), limit)

    try:
        stat = log_path.stat()
        sessions, log_info = cached_load(str(log_path), max_rows, stat.st_mtime_ns, stat.st_size)
    except OSError:
        sessions, log_info = cached_load(str(log_path), max_rows, 0, 0)
    try:
        event_stat = event_path.stat()
        raw_events, event_info = cached_events(str(event_path), max_rows * 4, event_stat.st_mtime_ns, event_stat.st_size)
    except OSError:
        raw_events, event_info = cached_events(str(event_path), max_rows * 4, 0, 0)
    refreshed_at = datetime.now(timezone.utc)
    all_events = normalize_events(raw_events, sessions)
    frame = build_dataframe(sessions)
    commands = build_commands_dataframe(sessions)
    frame, _ = apply_demo_thresholds(frame, commands, high, medium, attack)
    if log_info.get("read_error"):
        st.error(f"Unable to read the session log: {log_info['read_error']}")
    if log_info.get("parse_errors") or log_info.get("invalid_records"):
        st.warning(f"Skipped {log_info.get('parse_errors', 0)} malformed JSON line(s) and {log_info.get('invalid_records', 0)} non-object record(s) in the loaded log tail.")
    if not log_info.get("exists"):
        st.info(f"Session log not found at {log_path}. Start the honeypot to create it.")
    if not event_info.get("exists"):
        st.caption(f"Event log not found at {event_path}; compatibility events will be reconstructed from available session summaries.")
    if event_info.get("parse_errors") or event_info.get("invalid_records"):
        st.warning(f"Event log tail contains {event_info.get('parse_errors', 0)} malformed line(s) and {event_info.get('invalid_records', 0)} unrecognized record(s).")
    elif frame.empty:
        st.info("The session log is empty or contains no valid records. Start the honeypot and generate authorized test traffic.")
    if auto_refresh:
        try:
            from streamlit_autorefresh import st_autorefresh
            st_autorefresh(interval=interval * 1000, key="soc_autorefresh")
        except ImportError:
            st.caption("Optional auto-refresh package is not installed; use Refresh data to reload the log.")
    if frame.empty:
        section = st.sidebar.radio("Navigation", ["Security Overview", "Live Activity", "Attack Flow", "Attack Intelligence", "Session Explorer", "Protocol Analytics", "ML & Detection", "Security Recommendations", "Reports", "System Health", "KPI Summary"], key="navigation_empty")
        if section == "System Health": render_health(log_path, log_info, frame, ROOT_DIR / "config" / "config.yaml", ROOT_DIR / "logs" / "errors.log", event_path, event_info, all_events)
        elif section == "Live Activity" and all_events:
            st.dataframe(pd.DataFrame(all_events).head(200), hide_index=True, width="stretch")
        elif section in {"Security Recommendations", "Reports"}:
            st.info("Generate or load session records to create evidence-based recommendations and reports.")
        return

    with st.sidebar:
        selected_frame, filters = filter_sidebar(frame)
        st.caption(f"{len(selected_frame):,} of {len(frame):,} loaded sessions in scope")
        st.divider()
        section = st.radio("Navigation", ["Security Overview", "Live Activity", "Attack Flow", "Attack Intelligence", "Session Explorer", "Protocol Analytics", "ML & Detection", "Security Recommendations", "Reports", "System Health", "KPI Summary"], key="navigation")

    if selected_frame.empty:
        st.warning("No sessions match the selected investigation filters. Adjust the sidebar scope.")
        if section == "System Health": render_health(log_path, log_info, frame, ROOT_DIR / "config" / "config.yaml", ROOT_DIR / "logs" / "errors.log", event_path, event_info, all_events)
        return
    selected_ids = set(selected_frame["session_id"].astype(str))
    selected_events = [event for event in all_events if str(event.get("session_id")) in selected_ids]
    selected_commands = commands[commands["session_id"].astype(str).isin(selected_ids)] if not commands.empty else commands
    st.markdown(f"<div class='eyebrow'>Investigation scope · {len(selected_frame):,} sessions · {len(filters['protocol'])} protocols selected</div>", unsafe_allow_html=True)
    if section == "Security Overview": render_overview(selected_frame, selected_events)
    elif section == "Live Activity": render_live(selected_frame, selected_events, refreshed_at)
    elif section == "Attack Flow":
        try:
            import yaml
            cfg = yaml.safe_load((ROOT_DIR / "config" / "config.yaml").read_text(encoding="utf-8")) or {}
            window = int(cfg.get("deception", {}).get("correlation_window_seconds", 900))
        except Exception:
            window = 900
        render_attack_flow(selected_frame, selected_events, correlate_sessions(selected_frame.to_dict(orient="records"), window))
    elif section == "Attack Intelligence": render_attack_intelligence(selected_frame, selected_commands, selected_events)
    elif section == "Session Explorer":
        st.subheader("Session Explorer")
        st.caption("Filters apply across every investigation view. Export contains the filtered session records.")
        export_frame = selected_frame.drop(columns=["attack_tags"], errors="ignore").copy()
        for column in export_frame.columns:
            if export_frame[column].map(lambda value: isinstance(value, (dict, list))).any():
                export_frame[column] = export_frame[column].map(lambda value: json.dumps(_redact_secrets(value), ensure_ascii=False) if isinstance(value, (dict, list)) else value)
        csv = export_frame.to_csv(index=False).encode("utf-8")
        st.download_button("Export filtered sessions as CSV", csv, "phantom-pot-filtered-sessions.csv", "text/csv")
        recent_table(selected_frame, "explorer_table")
        render_session_detail(selected_frame.head(1000), "explorer_detail")
    elif section == "Protocol Analytics": render_protocol_analytics(selected_frame, selected_events)
    elif section == "ML & Detection": render_ml(selected_frame, high, medium, attack)
    elif section == "Security Recommendations": render_recommendations(selected_frame, selected_events)
    elif section == "Reports":
        recommendations = generate_recommendations(selected_frame.to_dict(orient="records"), selected_events)
        render_reports(selected_frame, selected_events, recommendations)
    elif section == "System Health": render_health(log_path, log_info, frame, ROOT_DIR / "config" / "config.yaml", ROOT_DIR / "logs" / "errors.log", event_path, event_info, all_events)
    elif section == "KPI Summary": render_kpis(selected_frame)
    if auto_refresh:
        st.caption(f"Auto-refresh enabled · interval {interval}s · data source is the finalized-session JSONL log.")


if __name__ == "__main__":
    main()
