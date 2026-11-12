
import csv
import re
from collections import defaultdict, Counter
from datetime import datetime, timedelta

LOG_FILE = "honeypot_events_v2.csv"

# Detection thresholds
BRUTE_FORCE_THRESHOLD = 3
BRUTE_FORCE_WINDOW = 5

PORT_SCAN_THRESHOLD = 2
PORT_SCAN_WINDOW = 60


# Suspicious command detection rules
RULES = [
    {
        "pattern": r"\bcat\s+.*password",
        "category": "CREDENTIAL DISCOVERY",
        "severity": "HIGH",
        "reason": "Password-related file inspection"
    },
    {
        "pattern": r"\bcat\s+.*(?:/etc/passwd|/etc/shadow)\b",
        "category": "USER ENUMERATION",
        "severity": "HIGH",
        "reason": "System account file inspection"
    },
    {
        "pattern": r"\b(?:uname|hostname|lscpu|lsb_release)\b",
        "category": "SYSTEM RECONNAISSANCE",
        "severity": "LOW",
        "reason": "System information gathering"
    },
    {
        "pattern": r"\b(?:find|locate|tree)\b",
        "category": "FILESYSTEM DISCOVERY",
        "severity": "MEDIUM",
        "reason": "Filesystem exploration"
    },
    {
        "pattern": r"\b(?:ifconfig|ip\s+addr|ip\s+route|netstat|ss)\b",
        "category": "NETWORK RECONNAISSANCE",
        "severity": "MEDIUM",
        "reason": "Network information gathering"
    },
    {
        "pattern": r"\b(?:ps|top|htop)\b",
        "category": "PROCESS RECONNAISSANCE",
        "severity": "LOW",
        "reason": "Process information gathering"
    },
    {
        "pattern": r"\b(?:sudo|su)\b",
        "category": "PRIVILEGE ESCALATION INTEREST",
        "severity": "MEDIUM",
        "reason": "Attempt to use elevated privileges"
    }
]


def parse_time(value):
    return datetime.strptime(value, "%Y-%m-%d %H:%M:%S")


def load_events():
    try:
        with open(LOG_FILE, "r", newline="") as file:
            return list(csv.DictReader(file))
    except FileNotFoundError:
        print(f"[ERROR] {LOG_FILE} not found.")
        return []


def detect_command(command):
    matches = []

    for rule in RULES:
        if re.search(rule["pattern"], command, re.IGNORECASE):
            matches.append(rule)

    return matches


def detect_brute_force(events):
    alerts = []

    attempts = defaultdict(list)

    for event in events:
        if event["event"] == "LOGIN_ATTEMPT":
            attempts[event["source_ip"]].append(
                parse_time(event["timestamp"])
            )

    for ip, times in attempts.items():
        times.sort()

        for i in range(len(times)):
            window_end = times[i] + timedelta(
                minutes=BRUTE_FORCE_WINDOW
            )

            count = sum(
                1 for t in times
                if times[i] <= t <= window_end
            )

            if count >= BRUTE_FORCE_THRESHOLD:
                alerts.append({
                    "ip": ip,
                    "severity": "HIGH",
                    "category": "POSSIBLE BRUTE FORCE",
                    "details": f"{count} login attempts within {BRUTE_FORCE_WINDOW} minutes"
                })
                break

    return alerts


def detect_port_scanning(events):
    alerts = []

    connections = defaultdict(list)

    for event in events:
        if event["event"] == "CONNECTION":
            connections[event["source_ip"]].append({
                "time": parse_time(event["timestamp"]),
                "port": event["destination_port"]
            })

    for ip, records in connections.items():
        records.sort(key=lambda x: x["time"])

        for i in range(len(records)):
            window_end = records[i]["time"] + timedelta(
                seconds=PORT_SCAN_WINDOW
            )

            ports = {
                record["port"]
                for record in records
                if records[i]["time"] <= record["time"] <= window_end
            }

            if len(ports) >= PORT_SCAN_THRESHOLD:
                alerts.append({
                    "ip": ip,
                    "severity": "MEDIUM",
                    "category": "POSSIBLE PORT SCANNING",
                    "details": f"Ports contacted: {sorted(ports)}"
                })
                break

    return alerts


def generate_report():

    events = load_events()

    if not events:
        return

    activity = defaultdict(list)
    logins = Counter()
    connections = Counter()
    services = defaultdict(set)
    categories = defaultdict(Counter)
    alerts = []

    total_commands = 0

    for event in events:

        ip = event["source_ip"]
        event_type = event["event"]

        if event_type == "CONNECTION":
            connections[ip] += 1
            services[ip].add(event["service"])

        elif event_type == "LOGIN_ATTEMPT":
            logins[ip] += 1

        elif event_type == "COMMAND_EXECUTED":
            command = event["details"]
            total_commands += 1
            activity[ip].append(command)

            for match in detect_command(command):
                categories[ip][match["category"]] += 1

                alerts.append({
                    "ip": ip,
                    "severity": match["severity"],
                    "category": match["category"],
                    "details": f"Command: {command} | {match['reason']}"
                })

    alerts.extend(detect_brute_force(events))
    alerts.extend(detect_port_scanning(events))

    # Print administrator report
    print("\n========== HONEYPOT SECURITY REPORT ==========")

    print(f"\nTotal recorded events: {len(events)}")
    print(f"Total commands analyzed: {total_commands}")
    print(f"Unique source IPs: {len(set(e['source_ip'] for e in events))}")

    all_ips = sorted(
        set(connections) | set(logins) | set(activity)
    )

    for ip in all_ips:

        print("\n----------------------------------------------")
        print(f"SOURCE IP: {ip}")

        print("\nCONNECTION SUMMARY")
        print(f"  Total connections: {connections[ip]}")
        print(f"  Services accessed: {', '.join(sorted(services[ip])) or 'None'}")
        print(f"  Login attempts: {logins[ip]}")

        print("\nBEHAVIOUR ANALYSIS")
        print(f"  Commands executed: {len(activity[ip])}")

        if categories[ip]:
            for category, count in categories[ip].items():
                print(f"  {category}: {count}")
        else:
            print("  No suspicious command patterns detected.")

        print("\nSECURITY ALERTS")

        ip_alerts = [a for a in alerts if a["ip"] == ip]

        if ip_alerts:
            for alert in ip_alerts:
                print(
                    f"  [{alert['severity']}] "
                    f"{alert['category']}: {alert['details']}"
                )
        else:
            print("  No alerts.")

    print("\n==============================================")
    print(f"Total security alerts: {len(alerts)}")
    print("==============================================")


if __name__ == "__main__":
    generate_report()
