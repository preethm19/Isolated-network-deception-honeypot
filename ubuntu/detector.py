
from datetime import datetime, timedelta, timezone
from collections import defaultdict

from database import get_connection

BRUTE_FORCE_THRESHOLD = 3
BRUTE_FORCE_WINDOW = timedelta(minutes=5)

PORT_SCAN_THRESHOLD = 2
PORT_SCAN_WINDOW = timedelta(seconds=60)

now = datetime.now(timezone.utc)

login_attempts = defaultdict(list)
connections = defaultdict(list)

# Read recorded events from SQLite
with get_connection() as conn:

    rows = conn.execute("""
        SELECT timestamp, source_ip, event, destination_port
        FROM events
        WHERE event IN ('LOGIN_ATTEMPT', 'CONNECTION')
    """).fetchall()

    for row in rows:

        timestamp = datetime.fromisoformat(row["timestamp"])

        # Handle timestamps without timezone information
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        ip = row["source_ip"]
        event = row["event"]
        dest_port = row["destination_port"]

        if event == "LOGIN_ATTEMPT":
            login_attempts[ip].append(timestamp)

        if event == "CONNECTION":
            connections[ip].append((timestamp, dest_port))


print("\n========== HONEYPOT DETECTION REPORT ==========")


# Detect repeated login attempts
print("\n[1] REPEATED LOGIN ATTEMPTS")

detected = False

for ip, attempts in login_attempts.items():

    recent = [
        t for t in attempts
        if now - t <= BRUTE_FORCE_WINDOW
    ]

    if len(recent) >= BRUTE_FORCE_THRESHOLD:

        print(
            f"[ALERT] Possible brute-force activity "
            f"from {ip}: {len(recent)} login attempts"
        )

        detected = True

if not detected:
    print("No repeated login activity detected.")


# Detect port scanning
print("\n[2] POSSIBLE PORT SCANNING")

detected = False

for ip, records in connections.items():

    recent = [
        (t, port)
        for t, port in records
        if now - t <= PORT_SCAN_WINDOW
    ]

    unique_ports = set(
        port for t, port in recent
    )

    if len(unique_ports) >= PORT_SCAN_THRESHOLD:

        print(
            f"[ALERT] Possible port scanning "
            f"from {ip}: ports {sorted(unique_ports)}"
        )

        detected = True

if not detected:
    print("No port scanning activity detected.")


print("\n==============================================")
