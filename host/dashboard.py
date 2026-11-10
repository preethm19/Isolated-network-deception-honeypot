import html
import re
from datetime import timedelta

import pandas as pd
import requests
import streamlit as st
from streamlit_autorefresh import st_autorefresh

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
API_URL = "http://192.168.57.2:5000/events"
DEFAULT_REFRESH_S = 3

st.set_page_config(
    page_title="Honeypot Security Monitor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Design tokens
C = {
    "bg": "#0E1116",
    "panel": "#151A22",
    "panel_2": "#1B222C",
    "border": "#262F3B",
    "text": "#E6EAF0",
    "muted": "#8A94A3",
    "accent": "#4C9AFF",
    "CRITICAL": "#E5484D",
    "HIGH": "#F76B15",
    "MEDIUM": "#F5B83D",
    "LOW": "#3FB68B",
}
SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
EVENT_COLORS = {
    "CONNECTION": C["accent"],
    "LOGIN_ATTEMPT": C["MEDIUM"],
    "COMMAND_EXECUTED": C["CRITICAL"],
}

st.markdown(
    f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap');

html, body, [class*="css"], .stApp {{
    font-family: 'IBM Plex Sans', system-ui, sans-serif;
}}
.stApp {{ background: {C['bg']}; color: {C['text']}; }}
header[data-testid="stHeader"] {{ background: transparent; }}
.block-container {{ padding-top: 1.6rem; padding-bottom: 3rem; max-width: 1500px; }}

section[data-testid="stSidebar"] {{
    background: {C['panel']};
    border-right: 1px solid {C['border']};
}}

h1, h2, h3, h4 {{ color: {C['text']}; letter-spacing: -0.01em; }}
h3 {{ font-size: 1.05rem !important; font-weight: 600 !important; margin-bottom: .4rem; }}

/* Page header */
.topbar {{
    display: flex; justify-content: space-between; align-items: center;
    padding-bottom: 1rem; margin-bottom: 1.2rem;
    border-bottom: 1px solid {C['border']};
}}
.topbar .title {{ font-size: 1.55rem; font-weight: 600; line-height: 1.2; }}
.topbar .sub {{ color: {C['muted']}; font-size: .9rem; margin-top: .15rem; }}
.status {{
    display: inline-flex; align-items: center; gap: .55rem;
    padding: .45rem .9rem; border-radius: 999px; font-weight: 500; font-size: .9rem;
    border: 1px solid; white-space: nowrap;
}}
.status .dot {{ width: .6rem; height: .6rem; border-radius: 50%; background: currentColor; }}
.updated {{ color: {C['muted']}; font-size: .8rem; margin-top: .35rem; text-align: right; }}

/* KPI cards */
.kpi {{
    background: {C['panel']}; border: 1px solid {C['border']};
    border-radius: 10px; padding: 1rem 1.15rem; height: 100%;
}}
.kpi .label {{ color: {C['muted']}; font-size: .82rem; }}
.kpi .value {{ font-size: 2rem; font-weight: 600; line-height: 1.25; margin-top: .15rem; }}
.kpi .hint {{ color: {C['muted']}; font-size: .78rem; margin-top: .1rem; }}

/* Panels */
.panel-title {{ font-weight: 600; font-size: 1rem; margin: 0 0 .15rem 0; }}
.panel-sub {{ color: {C['muted']}; font-size: .82rem; margin-bottom: .6rem; }}

/* Alert rows */
.alert {{
    display: grid; grid-template-columns: 6.2rem 1fr auto; gap: 1rem; align-items: start;
    background: {C['panel']}; border: 1px solid {C['border']};
    border-left: 4px solid var(--sev); border-radius: 8px;
    padding: .7rem 1rem; margin-bottom: .5rem;
}}
.chip {{
    display: inline-block; text-align: center; padding: .15rem .5rem; border-radius: 4px;
    font-size: .75rem; font-weight: 600; color: #0E1116; background: var(--sev);
}}
.alert .cat {{ font-weight: 600; font-size: .92rem; }}
.alert .ip {{ font-family: 'IBM Plex Mono', monospace; color: {C['accent']}; font-size: .82rem; margin-left: .5rem; }}
.alert .act {{
    font-family: 'IBM Plex Mono', monospace; font-size: .82rem; color: {C['text']};
    background: {C['panel_2']}; border-radius: 4px; padding: .15rem .45rem;
    display: inline-block; margin-top: .3rem; word-break: break-all;
}}
.alert .why {{ color: {C['muted']}; font-size: .8rem; margin-top: .3rem; }}
.alert .time {{ color: {C['muted']}; font-size: .78rem; white-space: nowrap; }}

/* Tabs */
button[data-baseweb="tab"] {{ font-weight: 500; }}
div[data-baseweb="tab-list"] {{ gap: .25rem; border-bottom: 1px solid {C['border']}; }}

/* Dataframes / charts sit on a panel */
div[data-testid="stDataFrame"] {{ border: 1px solid {C['border']}; border-radius: 8px; overflow: hidden; }}
div[data-testid="stVegaLiteChart"] {{ background: {C['panel']}; border: 1px solid {C['border']};
    border-radius: 10px; padding: .6rem; }}
</style>
""",
    unsafe_allow_html=True,
)

# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------
EVENT_COLUMNS = [
    "timestamp", "event", "source_ip", "source_port", "destination_port",
    "service", "username", "details",
]


def load_events():
    try:
        response = requests.get(API_URL, timeout=5)
        response.raise_for_status()
        events = pd.DataFrame(response.json()["events"])
    except (requests.RequestException, KeyError, ValueError) as e:
        st.error(f"Unable to read events from the honeypot API ({API_URL}): {e}")
        return pd.DataFrame()

    if events.empty:
        return events

    # Guarantee every column the dashboard uses exists.
    for col in EVENT_COLUMNS:
        if col not in events.columns:
            events[col] = pd.NA

    events["timestamp"] = pd.to_datetime(events["timestamp"], errors="coerce")
    for col in ("source_port", "destination_port"):
        events[col] = pd.to_numeric(events[col], errors="coerce")
    for col in ("event", "source_ip", "service", "username", "details"):
        events[col] = events[col].fillna("").astype(str)
    return events


# ---------------------------------------------------------------------------
# Detection logic (unchanged behaviour)
# ---------------------------------------------------------------------------
RULES = [
    (r"^\s*cat\s+.*password", "CREDENTIAL DISCOVERY", "HIGH",
     "Password-related file inspection"),
    (r"^\s*cat\s+.*(?:/etc/passwd|/etc/shadow)\b", "USER ENUMERATION", "HIGH",
     "System account file inspection"),
    (r"^\s*(?:uname|hostname|lscpu|lsb_release)(?:\s|$)",
     "SYSTEM RECONNAISSANCE", "LOW", "System information gathering"),
    (r"^\s*(?:find|locate|tree)(?:\s|$)",
     "FILESYSTEM DISCOVERY", "MEDIUM", "Filesystem exploration"),
    (r"^\s*(?:ifconfig|ip\s+addr|ip\s+route|netstat|ss)(?:\s|$)",
     "NETWORK RECONNAISSANCE", "MEDIUM", "Network information gathering"),
    (r"^\s*(?:ps|top|htop)(?:\s|$)",
     "PROCESS RECONNAISSANCE", "LOW", "Process information gathering"),
    (r"^\s*(?:sudo|su)(?:\s|$)",
     "PRIVILEGE ESCALATION INTEREST", "MEDIUM",
     "Attempt to use elevated privileges"),
]
SEVERITY_POINTS = {"LOW": 5, "MEDIUM": 15, "HIGH": 30, "CRITICAL": 40}
ALERT_COLUMNS = ["Time", "Source IP", "Severity", "Category", "Activity", "Reason"]


def classify_command(command):
    matches = []
    for pattern, category, severity, reason in RULES:
        if re.search(pattern, str(command), re.IGNORECASE):
            matches.append((category, severity, reason))
    return matches


def build_alerts(data):
    alerts = []

    commands = data[data["event"] == "COMMAND_EXECUTED"]
    for _, row in commands.iterrows():
        for category, severity, reason in classify_command(row["details"]):
            alerts.append({
                "Time": row["timestamp"], "Source IP": row["source_ip"],
                "Severity": severity, "Category": category,
                "Activity": row["details"], "Reason": reason,
            })

    # Brute force: 3+ login attempts from one IP within 5 minutes.
    login_rows = data[data["event"] == "LOGIN_ATTEMPT"].dropna(subset=["timestamp"])
    for ip, group in login_rows.groupby("source_ip"):
        times = sorted(group["timestamp"].tolist())
        for start_time in times:
            end = start_time + timedelta(minutes=5)
            count = sum(start_time <= t <= end for t in times)
            if count >= 3:
                alerts.append({
                    "Time": start_time, "Source IP": ip, "Severity": "HIGH",
                    "Category": "POSSIBLE BRUTE FORCE",
                    "Activity": f"{count} login attempts within 5 minutes",
                    "Reason": "Repeated login attempts crossed the configured threshold",
                })
                break

    # Port scan: connections to 2+ different ports within 60 seconds.
    conn_rows = data[data["event"] == "CONNECTION"].dropna(
        subset=["timestamp", "destination_port"]
    )
    for ip, group in conn_rows.groupby("source_ip"):
        records = group.sort_values("timestamp")[
            ["timestamp", "destination_port"]
        ].to_dict("records")
        for rec in records:
            end = rec["timestamp"] + timedelta(seconds=60)
            ports = {
                int(item["destination_port"])
                for item in records
                if rec["timestamp"] <= item["timestamp"] <= end
            }
            if len(ports) >= 2:
                alerts.append({
                    "Time": rec["timestamp"], "Source IP": ip, "Severity": "MEDIUM",
                    "Category": "POSSIBLE PORT SCANNING",
                    "Activity": f"Connected to ports {sorted(ports)} within 60 seconds",
                    "Reason": "Connections reached multiple destination ports",
                })
                break

    if not alerts:
        return pd.DataFrame(columns=ALERT_COLUMNS)
    return pd.DataFrame(alerts).sort_values("Time", ascending=False)


def threat_level(score):
    if score >= 70:
        return "CRITICAL"
    if score >= 40:
        return "HIGH"
    if score >= 20:
        return "MEDIUM"
    return "LOW"


def threat_summary(data, alerts):
    rows = []
    for ip in sorted(set(data["source_ip"]) - {""}):
        ip_alerts = alerts[alerts["Source IP"] == ip]
        score = min(sum(SEVERITY_POINTS.get(s, 0) for s in ip_alerts["Severity"]), 100)
        subset = data[data["source_ip"] == ip]
        rows.append({
            "Source IP": ip,
            "Threat Level": threat_level(score),
            "Risk Score": score,
            "Connections": int((subset["event"] == "CONNECTION").sum()),
            "Login Attempts": int((subset["event"] == "LOGIN_ATTEMPT").sum()),
            "Commands": int((subset["event"] == "COMMAND_EXECUTED").sum()),
            "Alerts": len(ip_alerts),
            "Services": ", ".join(sorted(set(subset["service"]) - {""})),
        })
    out = pd.DataFrame(rows)
    if not out.empty:
        out = out.sort_values("Risk Score", ascending=False)
    return out


# ---------------------------------------------------------------------------
# UI helpers
# ---------------------------------------------------------------------------
def kpi(col, label, value, hint="", color=None):
    style = f"color:{color};" if color else ""
    col.markdown(
        f"""<div class="kpi"><div class="label">{html.escape(label)}</div>
        <div class="value" style="{style}">{value}</div>
        <div class="hint">{html.escape(hint)}</div></div>""",
        unsafe_allow_html=True,
    )


def alert_row(alert):
    # Command text is attacker-controlled, so it is always escaped before rendering as HTML.
    sev = alert["Severity"]
    ts = alert["Time"]
    ts_text = ts.strftime("%Y-%m-%d %H:%M:%S") if pd.notna(ts) else "unknown time"
    return f"""
    <div class="alert" style="--sev:{C.get(sev, C['muted'])}">
        <div><span class="chip">{html.escape(sev)}</span></div>
        <div>
            <div><span class="cat">{html.escape(str(alert['Category']).title())}</span>
                 <span class="ip">{html.escape(str(alert['Source IP']))}</span></div>
            <div class="act">{html.escape(str(alert['Activity']))}</div>
            <div class="why">{html.escape(str(alert['Reason']))}</div>
        </div>
        <div class="time">{ts_text}</div>
    </div>"""


def style_level(value):
    color = C.get(value)
    return f"background-color: {color}; color: #0E1116; font-weight: 600;" if color else ""


def panel_header(title, sub=""):
    st.markdown(
        f'<div class="panel-title">{html.escape(title)}</div>'
        f'<div class="panel-sub">{html.escape(sub)}</div>',
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Sidebar controls
# ---------------------------------------------------------------------------
st.sidebar.markdown("### 🛡️ Honeypot Monitor")
st.sidebar.caption("Live network security monitoring")

st.sidebar.markdown("**Refresh**")
live = st.sidebar.toggle("Live updates", value=True,
                         help="Turn off to pause refreshing, e.g. while typing a search.")
refresh_s = st.sidebar.slider("Interval (seconds)", 2, 30, DEFAULT_REFRESH_S, disabled=not live)
if live:
    st_autorefresh(interval=refresh_s * 1000, key="honeypot_live_refresh")

df = load_events()
if df.empty:
    st.warning("No honeypot events have been recorded yet. This page will update when data arrives.")
    st.stop()

st.sidebar.markdown("---")
st.sidebar.markdown("**Filters**")
available_ips = sorted(set(df["source_ip"]) - {""})
selected_ip = st.sidebar.selectbox("Source IP", ["All"] + available_ips)
window = st.sidebar.selectbox(
    "Time window", ["All time", "Last 15 minutes", "Last hour", "Last 24 hours"]
)
sev_filter = st.sidebar.multiselect("Alert severity", SEV_ORDER, default=SEV_ORDER)

data = df.copy()
if selected_ip != "All":
    data = data[data["source_ip"] == selected_ip]
if window != "All time" and data["timestamp"].notna().any():
    delta = {"Last 15 minutes": timedelta(minutes=15),
             "Last hour": timedelta(hours=1),
             "Last 24 hours": timedelta(hours=24)}[window]
    data = data[data["timestamp"] >= data["timestamp"].max() - delta]

alerts = build_alerts(data)
threats = threat_summary(data, alerts)

connections = data[data["event"] == "CONNECTION"]
logins = data[data["event"] == "LOGIN_ATTEMPT"]
commands = data[data["event"] == "COMMAND_EXECUTED"]

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
overall = "LOW"
if not threats.empty:
    top = threats["Threat Level"].tolist()
    overall = next((lvl for lvl in SEV_ORDER if lvl in top), "LOW")
overall_color = C[overall]
status_text = {
    "CRITICAL": "Critical threat detected",
    "HIGH": "High threat activity",
    "MEDIUM": "Suspicious activity",
    "LOW": "No significant threats",
}[overall]
last_event = data["timestamp"].max()
last_event_text = last_event.strftime("%Y-%m-%d %H:%M:%S") if pd.notna(last_event) else "n/a"

st.markdown(
    f"""
<div class="topbar">
    <div>
        <div class="title">Network Honeypot Security Dashboard</div>
        <div class="sub">Attacker activity, suspicious behaviour and risk indicators</div>
    </div>
    <div>
        <div class="status" style="color:{overall_color}; border-color:{overall_color}55;
             background:{overall_color}1A;"><span class="dot"></span>{status_text}</div>
        <div class="updated">{'Live, every ' + str(refresh_s) + 's' if live else 'Paused'}
             · latest event {last_event_text}</div>
    </div>
</div>
""",
    unsafe_allow_html=True,
)

# KPI row
k1, k2, k3, k4, k5 = st.columns(5)
kpi(k1, "Connections", f"{len(connections):,}", "Inbound connection events")
kpi(k2, "Source IPs", f"{data['source_ip'].replace('', pd.NA).nunique():,}", "Unique attackers seen")
kpi(k3, "Login attempts", f"{len(logins):,}", "Credential guesses")
kpi(k4, "Commands", f"{len(commands):,}", "Run inside the honeypot")
kpi(k5, "Suspicious indicators", f"{len(alerts):,}", "Rule-based detections",
    color=C["HIGH"] if len(alerts) else None)

st.markdown("<div style='height:1rem'></div>", unsafe_allow_html=True)

# ---------------------------------------------------------------------------
# Tabs
# ---------------------------------------------------------------------------
tab_overview, tab_alerts, tab_sources, tab_commands, tab_raw = st.tabs(
    ["Overview", "Alerts", "Sources", "Commands", "Raw events"]
)

# ---- Overview -------------------------------------------------------------
with tab_overview:
    panel_header("Activity timeline", "Events per minute, split by event type")
    timeline = data.dropna(subset=["timestamp"])
    if timeline.empty:
        st.info("No valid timestamps available.")
    else:
        per_min = (
            timeline.set_index("timestamp")
            .groupby([pd.Grouper(freq="1min"), "event"]).size()
            .unstack(fill_value=0)
        )
        st.bar_chart(
            per_min,
            color=[EVENT_COLORS.get(c, C["muted"]) for c in per_min.columns],
            height=280,
        )

    left, right = st.columns(2)
    with left:
        panel_header("Events by type")
        counts = data["event"].value_counts()
        if counts.empty:
            st.info("No events in this view.")
        else:
            st.bar_chart(counts, color=C["accent"], height=260)
    with right:
        panel_header("Connections by service")
        service_counts = connections["service"].replace("", pd.NA).dropna().value_counts()
        if service_counts.empty:
            st.info("No connections recorded.")
        else:
            st.bar_chart(service_counts, color=C["accent"], height=260)

    panel_header("Most active sources", "Top five by risk score")
    if threats.empty:
        st.info("No source IPs to assess.")
    else:
        st.dataframe(
            threats.head(5)[["Source IP", "Threat Level", "Risk Score", "Alerts", "Commands"]]
            .style.map(style_level, subset=["Threat Level"]),
            column_config={
                "Risk Score": st.column_config.ProgressColumn(
                    "Risk Score", min_value=0, max_value=100, format="%d"),
            },
            use_container_width=True, hide_index=True,
        )

# ---- Alerts ---------------------------------------------------------------
with tab_alerts:
    shown = alerts[alerts["Severity"].isin(sev_filter)] if not alerts.empty else alerts
    panel_header("Live security alert feed",
                 f"{len(shown)} alert(s) match the current filters; newest first, showing up to 30")
    if shown.empty:
        st.success("No suspicious activity matched the current detection rules and filters.")
    else:
        st.markdown("".join(alert_row(a) for _, a in shown.head(30).iterrows()),
                    unsafe_allow_html=True)

# ---- Sources --------------------------------------------------------------
with tab_sources:
    panel_header("Source threat assessment",
                 "One row per source IP; risk score is the sum of its alert severities, capped at 100")
    if threats.empty:
        st.info("No source IPs to assess.")
    else:
        st.dataframe(
            threats.style.map(style_level, subset=["Threat Level"]),
            column_config={
                "Risk Score": st.column_config.ProgressColumn(
                    "Risk Score", min_value=0, max_value=100, format="%d"),
            },
            use_container_width=True, hide_index=True,
        )

# ---- Commands -------------------------------------------------------------
with tab_commands:
    panel_header("Command explorer", "Everything attackers ran inside the honeypot shell")
    if commands.empty:
        st.info("No commands recorded.")
    else:
        search = st.text_input("Search commands", placeholder="e.g. cat, sudo, uname",
                               label_visibility="collapsed")
        command_view = commands
        if search:
            command_view = commands[
                commands["details"].str.contains(search, case=False, na=False, regex=False)
            ]
        st.caption(f"{len(command_view)} of {len(commands)} command(s)")
        st.dataframe(
            command_view[["timestamp", "source_ip", "username", "details"]]
            .sort_values("timestamp", ascending=False)
            .rename(columns={"timestamp": "Time", "source_ip": "Source IP",
                             "username": "User", "details": "Command"}),
            use_container_width=True, hide_index=True,
        )

# ---- Raw events -----------------------------------------------------------
with tab_raw:
    panel_header("Raw event log", "Unprocessed events for the current filters")
    st.dataframe(
        data.sort_values("timestamp", ascending=False),
        use_container_width=True, hide_index=True,
    )

st.caption(
    "Risk scores are heuristic indicators based on configured rules, not proof of compromise."
)