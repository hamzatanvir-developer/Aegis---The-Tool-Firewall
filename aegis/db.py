import sqlite3
from typing import Optional

DB_FILE = "aegis_audit.db"

def init_db(db_path: str = DB_FILE):
    """Initializes the local SQLite database schema for audit logging."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create audit_logs table matching your production schema
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

def log_audit_event(
    event_id: str,
    agent_id: str,
    tool_name: str,
    payload: str,
    verdict: str,
    latency_ms: float,
    triggered_rule: Optional[str] = None,
    db_path: str = DB_FILE
):
    """Inserts an audit log entry into the database."""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO audit_logs (id, agent_id, tool_name, payload, verdict, triggered_rule, latency_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (event_id, agent_id, tool_name, payload, verdict, triggered_rule, latency_ms))
    conn.commit()
    conn.close()