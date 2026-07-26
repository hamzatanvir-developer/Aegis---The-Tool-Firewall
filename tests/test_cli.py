import sqlite3

import pytest
import yaml

from aegis.cli import main


def test_aegis_init_creates_default_guardrails_yaml(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    exit_code = main(["init"])

    config_path = tmp_path / "guardrails.yaml"
    assert exit_code == 0
    assert config_path.exists()

    document = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert document["version"] == "1.0"
    assert len(document["policies"]) == 3


def test_aegis_check_valid_and_malformed_yaml(tmp_path):
    valid_path = tmp_path / "valid.yaml"
    valid_path.write_text(
        """version: "1.0"\npolicies:\n  - name: block_destructive_sql\n    enabled: true\n""",
        encoding="utf-8",
    )

    invalid_path = tmp_path / "invalid.yaml"
    invalid_path.write_text("version: [broken\n", encoding="utf-8")

    assert main(["check", str(valid_path)]) == 0
    assert main(["check", str(invalid_path)]) != 0


def test_aegis_status_reads_audit_statistics(tmp_path):
    db_path = tmp_path / "audit.db"
    with sqlite3.connect(db_path) as connection:
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
                ("3", "agent-b", "tool_c", "{}", "ALLOW", None, 3.0),
            ],
        )
        connection.commit()

    exit_code = main(["status", "--db", str(db_path)])
    assert exit_code == 0