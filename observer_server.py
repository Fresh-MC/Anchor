# ANCHOR Passive Observer Store
# ==============================
# Minimal Flask service that receives fire-and-forget event copies from
# Anchor's /process endpoint. It is a READ-ONLY forensic mirror:
#   - Anchor pushes events here AFTER its response is finalized.
#   - This service never sends messages back to scammers.
#   - This service never mutates Anchor state.
#   - A future dashboard reads from here only.
#
# Storage: SQLite (append-only, no deletes, no updates).
# Why SQLite over in-memory: survives process restarts, bounded by disk not
# RAM, and avoids unbounded list growth in long-running demos.

import json
import os
import sqlite3
import sys
import time

try:
    from flask import Flask, request, jsonify
except ImportError:
    print("ERROR: Flask not installed. Run: pip install flask")
    sys.exit(1)

# ── App ──────────────────────────────────────────────────────────────────
app = Flask(__name__)

# ── Database ─────────────────────────────────────────────────────────────
DB_PATH = os.getenv("OBSERVER_DB_PATH", "observer_store.db")


def _get_db() -> sqlite3.Connection:
    """
    Per-request SQLite connection. WAL mode for concurrent reads.
    Not pooled — single-threaded Flask does not benefit from pooling.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.row_factory = sqlite3.Row
    return conn


def _init_db():
    """Create the events table if it doesn't exist. Append-only by design."""
    conn = _get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id  TEXT    NOT NULL,
            timestamp   REAL    NOT NULL,
            turn        INTEGER NOT NULL,
            state       TEXT    NOT NULL,
            behavior    TEXT    NOT NULL,   -- JSON string
            artifacts   TEXT    NOT NULL,   -- JSON string
            osint       TEXT    NOT NULL,   -- JSON string
            response    TEXT    NOT NULL
        )
    """)
    # Index for fast session lookups (dashboard will query by session_id)
    conn.execute("""
        CREATE INDEX IF NOT EXISTS idx_events_session
        ON events (session_id, turn)
    """)
    conn.commit()
    conn.close()


# ── Endpoints ────────────────────────────────────────────────────────────

@app.route("/observe", methods=["POST"])
def observe():
    """
    Append a single turn event. Called by Anchor's write_observer_event().
    Expects the exact observer payload schema:
    {
        "session_id": str,
        "timestamp": float,
        "turn": int,
        "state": str,
        "behavior": { "urgency": float, "pressure": float, "credential": float, "aggregate": float },
        "artifacts": { ... },
        "osint": { ... },
        "response": str
    }
    """
    try:
        data = request.get_json(silent=True)
        if not data or "session_id" not in data:
            return jsonify({"status": "error", "msg": "missing payload"}), 400

        conn = _get_db()
        conn.execute(
            """
            INSERT INTO events (session_id, timestamp, turn, state, behavior, artifacts, osint, response)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                data["session_id"],
                data.get("timestamp", time.time()),
                data.get("turn", 0),
                data.get("state", "CLARIFY"),
                json.dumps(data.get("behavior", {})),
                json.dumps(data.get("artifacts", {})),
                json.dumps(data.get("osint", {})),
                data.get("response", ""),
            ),
        )
        conn.commit()
        conn.close()
        return jsonify({"status": "ok"}), 201

    except Exception as e:
        # Surface errors here (observer is its own process; logging is fine)
        return jsonify({"status": "error", "msg": str(e)}), 500


@app.route("/sessions", methods=["GET"])
def list_sessions():
    """
    Return distinct session IDs that have at least one recorded event.
    Response: { "sessions": ["sid1", "sid2", ...] }
    """
    try:
        conn = _get_db()
        rows = conn.execute(
            "SELECT DISTINCT session_id FROM events ORDER BY session_id"
        ).fetchall()
        conn.close()
        return jsonify({"sessions": [r["session_id"] for r in rows]})
    except Exception as e:
        return jsonify({"sessions": [], "error": str(e)}), 500


@app.route("/session/<session_id>", methods=["GET"])
def get_session(session_id: str):
    """
    Return the full ordered timeline for a single session.
    Events are sorted by turn ascending (append-only guarantees order).
    Response: { "session_id": "...", "events": [ {...}, ... ] }
    """
    try:
        conn = _get_db()
        rows = conn.execute(
            "SELECT * FROM events WHERE session_id = ? ORDER BY turn ASC, id ASC",
            (session_id,),
        ).fetchall()
        conn.close()

        events = []
        for r in rows:
            events.append({
                "session_id": r["session_id"],
                "timestamp": r["timestamp"],
                "turn": r["turn"],
                "state": r["state"],
                "behavior": json.loads(r["behavior"]),
                "artifacts": json.loads(r["artifacts"]),
                "osint": json.loads(r["osint"]),
                "response": r["response"],
            })

        return jsonify({"session_id": session_id, "events": events})
    except Exception as e:
        return jsonify({"session_id": session_id, "events": [], "error": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    """Observer service health check."""
    return jsonify({"status": "healthy", "service": "ANCHOR Observer Store"})


# ── Entrypoint ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.getenv("OBSERVER_PORT", "9090"))
    _init_db()
    print(f"ANCHOR Observer Store listening on http://0.0.0.0:{port}")
    print(f"  DB: {os.path.abspath(DB_PATH)}")
    app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
