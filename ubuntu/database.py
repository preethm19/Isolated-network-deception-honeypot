import sqlite3
from datetime import datetime, timezone

DB_NAME = "honeypot.db"


def get_connection():
    conn = sqlite3.connect(DB_NAME, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def log_event(
    source_ip,
    source_port,
    destination_port,
    service,
    event,
    username=None,
    details=None
):
    timestamp = datetime.now(timezone.utc).isoformat()

    try:
        with get_connection() as conn:
            conn.execute("""
                INSERT INTO events (
                    timestamp,
                    source_ip,
                    source_port,
                    destination_port,
                    service,
                    username,
                    event,
                    details
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp,
                source_ip,
                source_port,
                destination_port,
                service,
                username,
                event,
                details
            ))

        print(f"[DATABASE] Logged: {event} from {source_ip}")

    except sqlite3.Error as error:
        print(f"[DATABASE ERROR] {error}")


def get_all_events(limit=500):
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT * FROM events
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()

        return [dict(row) for row in rows]
