import re
import requests
from collections import defaultdict
from datetime import timedelta

import pandas as pd
import streamlit as st
from streamlit_autorefresh import st_autorefresh

API_URL = "http://192.168.57.2:5000/events"

def load_events():
    try:
        response = requests.get(API_URL, timeout=5)
        response.raise_for_status()

        data = response.json()
        events = pd.DataFrame(data["events"])

        # API JSON timestamps arrive as strings; convert them to datetime
        # objects before time-window calculations in build_alerts().
        if not events.empty and "timestamp" in events.columns:
            events["timestamp"] = pd.to_datetime(
                events["timestamp"], errors="coerce"
            )

        # Keep port values numeric for port-scan analysis.
        for column in ("source_port", "destination_port"):
            if column in events.columns:
                events[column] = pd.to_numeric(events[column], errors="coerce")

        return events

    except requests.RequestException as e:
        st.error(f"Unable to connect to honeypot API: {e}")
        return pd.DataFrame()

REFRESH_MS = 3000

st.set_page_config(
    page_title="Honeypot Security Monitor",
    page_icon="🛡️",
    layout="wide",
)

# Refresh the entire dashboard every 3 seconds.
st_autorefresh(interval=REFRESH_MS, key="honeypot_live_refresh")

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
                "Time": row["timestamp"],
                "Source IP": row["source_ip"],
                "Severity": severity,
                "Category": category,
                "Activity": row["details"],
                "Reason": reason,
            })

    # Brute-force heuristic: at least 3 login attempts from one IP in 5 minutes.
    login_rows = data[data["event"] == "LOGIN_ATTEMPT"].dropna(
        subset=["timestamp"]
    )
    for ip, group in login_rows.groupby("source_ip"):
        times = sorted(group["timestamp"].tolist())
        for start in range(len(times)):
            start_time = times[start]
            end = start_time + timedelta(minutes=5)

            count = sum(
                start_time <= t <= end
                for t in times
            )
            if count >= 3:
                alerts.append({
                    "Time": times[start],
                    "Source IP": ip,
                    "Severity": "HIGH",
                    "Category": "POSSIBLE BRUTE FORCE",
                    "Activity": f"{count} login attempts within 5 minutes",
                    "Reason": "Repeated login attempts crossed the configured threshold",
                })
                break

    # Port-scan heuristic: connections to 2+ different ports in 60 seconds.
    # This is an indicator, not proof; normal multi-service testing can also match.
    conn_rows = data[data["event"] == "CONNECTION"].dropna(
        subset=["timestamp", "destination_port"]
    )
    for ip, group in conn_rows.groupby("source_ip"):
        records = group.sort_values("timestamp")[
            ["timestamp", "destination_port"]
        ].to_dict("records")
        for start in range(len(records)):
            end = records[start]["timestamp"] + timedelta(seconds=60)
            ports = {
                int(item["destination_port"])
                for item in records
                if records[start]["timestamp"] <= item["timestamp"] <= end
            }
            if len(ports) >= 2:
                alerts.append({
                    "Time": records[start]["timestamp"],
                    "Source IP": ip,
                    "Severity": "MEDIUM",
                    "Category": "POSSIBLE PORT SCANNING",
                    "Activity": f"Connected to ports {sorted(ports)} within 60 seconds",
                    "Reason": "Connections reached multiple destination ports",
                })
                break

    if not alerts:
        return pd.DataFrame(columns=[
            "Time", "Source IP", "Severity", "Category", "Activity", "Reason"
        ])
    return pd.DataFrame(alerts).sort_values("Time", ascending=False)


def threat_summary(data, alerts):
    ips = sorted(set(data["source_ip"]) - {""})
    rows = []

    for ip in ips:
        ip_alerts = alerts[alerts["Source IP"] == ip] if not alerts.empty else alerts
        score = sum(SEVERITY_POINTS.get(level, 0) for level in ip_alerts["Severity"])
        score = min(score, 100)

        if score >= 70:
            level = "CRITICAL"
        elif score >= 40:
            level = "HIGH"
        elif score >= 20:
            level = "MEDIUM"
        else:
            level = "LOW"

        subset = data[data["source_ip"] == ip]
        rows.append({
            "Source IP": ip,
            "Threat Level": level,
            "Risk Score": score,
            "Connections": int((subset["event"] == "CONNECTION").sum()),
            "Login Attempts": int((subset["event"] == "LOGIN_ATTEMPT").sum()),
            "Commands": int((subset["event"] == "COMMAND_EXECUTED").sum()),
            "Alerts": len(ip_alerts),
            "Services": ", ".join(sorted(set(subset["service"]) - {""})),
        })

    return pd.DataFrame(rows)


st.sidebar.title("Honeypot Monitor")
st.sidebar.caption("Live network security monitoring")
st.sidebar.markdown("---")
st.sidebar.caption("Auto-refresh: every 3 seconds")
st.sidebar.caption("Data source: honeypot API")

df = load_events()

if df.empty:
    st.warning("No honeypot events have been recorded yet.")
    st.stop()

available_ips = sorted(set(df["source_ip"]) - {""})
selected_ip = st.sidebar.selectbox("Filter by source IP", ["All"] + available_ips)

data = df if selected_ip == "All" else df[
    df["source_ip"] == selected_ip
].copy()

alerts = build_alerts(data)
threats = threat_summary(data, alerts)

st.title("Network Honeypot Security Dashboard")
st.caption("Attacker activity, suspicious behaviour and risk indicators")

# High-level banner
critical_count = int((threats["Threat Level"] == "CRITICAL").sum()) if not threats.empty else 0
high_count = int((threats["Threat Level"] == "HIGH").sum()) if not threats.empty else 0
medium_count = int((threats["Threat Level"] == "MEDIUM").sum()) if not threats.empty else 0

if critical_count:
    st.error(f"CRITICAL THREAT: {critical_count} source IP(s) currently have a critical risk score.")
elif high_count:
    st.error(f"HIGH THREAT: {high_count} source IP(s) currently have a high risk score.")
elif medium_count:
    st.warning(f"MEDIUM THREAT: {medium_count} source IP(s) have suspicious activity.")
else:
    st.success("No source currently exceeds the low-risk threshold.")

connections = data[data["event"] == "CONNECTION"]
logins = data[data["event"] == "LOGIN_ATTEMPT"]
commands = data[data["event"] == "COMMAND_EXECUTED"]

c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Connections", len(connections))
c2.metric("Source IPs", data["source_ip"].nunique())
c3.metric("Login Attempts", len(logins))
c4.metric("Commands", len(commands))
c5.metric("Suspicious Indicators", len(alerts))

st.divider()

st.subheader("Source threat assessment")
if threats.empty:
    st.info("No source IPs to assess.")
else:
    def highlight_threat(row):
        colors = {
            "CRITICAL": "background-color: #7f1d1d; color: white;",
            "HIGH": "background-color: #b91c1c; color: white;",
            "MEDIUM": "background-color: #92400e; color: white;",
            "LOW": "background-color: #14532d; color: white;",
        }
        return [colors.get(row["Threat Level"], "")] * len(row)

    st.dataframe(
        threats.style.apply(highlight_threat, axis=1),
        use_container_width=True,
        hide_index=True,
    )

st.divider()
left, right = st.columns(2)

with left:
    st.subheader("Events by type")
    counts = data["event"].value_counts()
    if not counts.empty:
        st.bar_chart(counts)

with right:
    st.subheader("Connections by service")
    service_counts = connections["service"].value_counts()
    if not service_counts.empty:
        st.bar_chart(service_counts)
    else:
        st.info("No connections recorded.")

st.subheader("Activity timeline")
timeline = data.dropna(subset=["timestamp"]).copy()
if not timeline.empty:
    timeline = timeline.set_index("timestamp")
    st.line_chart(timeline.resample("1min").size().rename("Events"))
else:
    st.info("No valid timestamps available.")

st.divider()
st.subheader("Live security alert feed")

if alerts.empty:
    st.success("No suspicious activity matched the current detection rules.")
else:
    for _, alert in alerts.head(30).iterrows():
        title = (
            f"{alert['Severity']} | {alert['Category']} | "
            f"{alert['Source IP']} | {alert['Time']}"
        )
        message = f"Activity: `{alert['Activity']}`  \nReason: {alert['Reason']}"

        if alert["Severity"] in ("CRITICAL", "HIGH"):
            st.error(f"**{title}**\n\n{message}")
        elif alert["Severity"] == "MEDIUM":
            st.warning(f"**{title}**\n\n{message}")
        else:
            st.info(f"**{title}**\n\n{message}")

st.divider()
st.subheader("Command explorer")
if commands.empty:
    st.info("No commands recorded.")
else:
    search = st.text_input("Search recorded commands", placeholder="e.g. cat, sudo, uname")
    command_view = commands.copy()
    if search:
        command_view = command_view[
            command_view["details"].str.contains(search, case=False, na=False)
        ]
    st.dataframe(
        command_view[["timestamp", "source_ip", "username", "details"]]
        .sort_values("timestamp", ascending=False),
        use_container_width=True,
        hide_index=True,
    )

with st.expander("View raw event log"):
    st.dataframe(
        data.sort_values("timestamp", ascending=False),
        use_container_width=True,
        hide_index=True,
    )

st.caption(
    "Risk scores are heuristic indicators based on configured rules, not proof of compromise. "
    "Dashboard refreshes every 3 seconds."
)
