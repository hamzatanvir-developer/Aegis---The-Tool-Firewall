import json
import sqlite3
import threading
from urllib.request import urlopen

import aegis.dashboard as dashboard


def _populate_audit_db(connection: sqlite3.Connection) -> None:
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


def test_fetch_audit_data_reads_metrics_and_rows(tmp_path, monkeypatch):
    db_path = tmp_path / "audit.db"
    with sqlite3.connect(db_path) as connection:
        _populate_audit_db(connection)

    monkeypatch.setattr(dashboard, "DB_FILE", str(db_path))

    total, allowed, blocked, rows = dashboard.fetch_audit_data()

    assert total == 3
    assert allowed == 1
    assert blocked == 2
    assert "agent-a" in rows
    assert "block_destructive_sql" in rows


def test_dashboard_bootstrap_and_stream_endpoint(tmp_path):
    db_path = tmp_path / "audit.db"
    with sqlite3.connect(db_path) as connection:
        _populate_audit_db(connection)

    server = dashboard.create_dashboard_server(port=0, db_path=str(db_path))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        base_url = f"http://127.0.0.1:{server.server_address[1]}"

        with urlopen(f"{base_url}/") as response:
            body = response.read().decode("utf-8")
        assert response.status == 200
        assert "Aegis Security Operations" in body
        assert "Policy" in body
        assert "Registry" in body
        assert "Explorer" in body
        assert "stream" in body
        
        with urlopen(f"{base_url}/api/bootstrap?limit=10") as response:
            bootstrap = json.loads(response.read().decode("utf-8"))
        assert bootstrap["metrics"]["total_calls"] == 3
        assert bootstrap["metrics"]["blocked_calls"] == 2
        assert len(bootstrap["logs"]) == 3
        assert bootstrap["policy"]["exists"] in {True, False}

        with urlopen(f"{base_url}/stream?since=0") as response:
            first_line = response.readline().decode("utf-8")
            second_line = response.readline().decode("utf-8")
        assert first_line.startswith("event: snapshot")
        assert second_line.startswith("data:")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
