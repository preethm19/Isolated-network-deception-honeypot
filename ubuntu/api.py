
from flask import Flask, jsonify
from database import get_connection

app = Flask(__name__)


@app.route("/events", methods=["GET"])
def get_events():
    try:
        with get_connection() as conn:
            total_events = conn.execute(
                "SELECT COUNT(*) FROM events"
            ).fetchone()[0]

            rows = conn.execute("""
                SELECT * FROM events
                ORDER BY id DESC
                LIMIT 500
            """).fetchall()

        # Reverse so events are returned oldest to newest
        events = [dict(row) for row in reversed(rows)]

        return jsonify({
            "total_events": total_events,
            "events": events
        })

    except Exception as error:
        return jsonify({"error": str(error)}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "API running"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
