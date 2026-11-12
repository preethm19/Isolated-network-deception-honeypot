import sqlite3

DB_NAME = "honeypot.db"

def initialize_database():
    conn = sqlite3.connect(DB_NAME)

    conn.execute("PRAGMA journal_mode=WAL")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            source_port INTEGER,
            destination_port INTEGER,
            service TEXT,
            username TEXT,
            event TEXT,
            details TEXT
        )
    """)

    # Indexes to speed up common dashboard and detection queries
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_events_source_ip
        ON events(source_ip)
    """)

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_events_timestamp
        ON events(timestamp)
    """)

    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_events_type
        ON events(event)
    """)

    conn.commit()
    conn.close()

    print("SQLite database initialized successfully!")


if __name__ == "__main__":
    initialize_database()
