import sqlite3
import sys
import traceback
from typing import Optional

from aegis.context import get_execution_context

DB_FILE = "aegis_audit.db"


def _ensure_schema(db_path: str) -> None:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id TEXT PRIMARY KEY,
        agent_id TEXT NOT NULL,
        tool_name TEXT NOT NULL,
        payload TEXT NOT NULL,
        verdict TEXT NOT NULL CHECK (verdict IN ('ALLOW', 'BLOCK', 'REQUIRE_APPROVAL')),
        triggered_rule TEXT,
        latency_ms REAL NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    conn.commit()
    conn.close()

def init_db(db_path: str = DB_FILE):
    """Initializes the local SQLite database schema for audit logging."""
    _ensure_schema(db_path)

def log_audit_event(
    event_id: str,
    tool_name: str,
    payload: str,
    verdict: str,
    latency_ms: float,
    triggered_rule: Optional[str] = None,
    db_path: str = DB_FILE,
    agent_id: Optional[str] = None,
):
    """Inserts an audit log entry into the database and never raises on persistence failure."""

    if agent_id in (None, "unknown"):
        agent_id = get_execution_context().agent_id

    def _write_row(target_db_path: str, ensure_schema: bool = False) -> None:
        if ensure_schema:
            _ensure_schema(target_db_path)

        conn = sqlite3.connect(target_db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO audit_logs (id, agent_id, tool_name, payload, verdict, triggered_rule, latency_ms)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (event_id, agent_id, tool_name, payload, verdict, triggered_rule, latency_ms))
            conn.commit()
        finally:
            conn.close()

    try:
        _write_row(db_path)
        return True
    except Exception as primary_error:
        fallback_path = DB_FILE if db_path != DB_FILE else None
        if fallback_path is not None:
            try:
                _write_row(fallback_path, ensure_schema=True)
                return False
            except Exception as fallback_error:
                print(
                    "Aegis audit logging failed after fallback: "
                    f"primary={primary_error!r}, fallback={fallback_error!r}",
                    file=sys.stderr,
                )
                print(traceback.format_exc(), file=sys.stderr)
                return False

        print(f"Aegis audit logging failed: {primary_error!r}", file=sys.stderr)
        print(traceback.format_exc(), file=sys.stderr)
        return False