import threading
import urllib.request
from http.server import ThreadingHTTPServer

from aegis.dashboard import calculate_dashboard_metrics, create_dashboard_server


def _populate_audit_db(connection):
    cursor = connection.cursor()
    cursor.execute(
        """
        CREATE TABLE audit_logs (
            id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            tool_name TEXT NOT NULL,
            payload TEXT NOT NULL,
            verdict TEXT NOT NULL,
            triggered_rule TEXT,
            latency_ms REAL NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    cursor.executemany(
        "INSERT INTO audit_logs (id, agent_id, tool_name, payload, verdict, triggered_rule, latency_ms) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [
            ("1", "agent-a", "tool_a", "{}", "ALLOW", None, 1.0),
            ("2", "agent-b", "tool_b", "{}", "BLOCK", "block_destructive_sql", 2.0),
            ("3", "agent-a", "tool_c", "{}", "BLOCK", "block_destructive_sql", 3.0),
        ],
    )
    connection.commit()


def test_dashboard_endpoint_returns_http_200(tmp_path):
    db_path = tmp_path / "audit.db"
    import sqlite3

    with sqlite3.connect(db_path) as connection:
        _populate_audit_db(connection)

    server: ThreadingHTTPServer = create_dashboard_server(port=0, db_path=str(db_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        port = server.server_address[1]
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/") as response:
            body = response.read().decode("utf-8")

        assert response.status == 200
        assert "Aegis Dashboard" in body
        assert "Total Invocations" in body
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_dashboard_metrics_calculation_against_sqlite_logs(tmp_path):
    db_path = tmp_path / "audit.db"
    import sqlite3

    with sqlite3.connect(db_path) as connection:
        _populate_audit_db(connection)

    metrics = calculate_dashboard_metrics(str(db_path))

    assert metrics.total_invocations == 3
    assert metrics.allowed_count == 1
    assert metrics.blocked_count == 2
    assert metrics.top_rules_triggered[0] == ("block_destructive_sql", 2)