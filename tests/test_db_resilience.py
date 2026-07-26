import sqlite3

import pytest

import aegis.db as db_module
from aegis.context import execution_context
from aegis.db import init_db, log_audit_event


def test_log_audit_event_persists_normally(tmp_path):
    db_path = tmp_path / "audit.db"
    init_db(db_path=str(db_path))

    with execution_context("agent-normal"):
        result = log_audit_event(
            event_id="evt-normal",
            tool_name="execute_query",
            payload="SELECT 1",
            verdict="ALLOW",
            latency_ms=1.0,
            db_path=str(db_path),
        )

    assert result is True

    with sqlite3.connect(db_path) as connection:
        cursor = connection.cursor()
        cursor.execute("SELECT agent_id, tool_name, verdict FROM audit_logs WHERE id = ?", ("evt-normal",))
        row = cursor.fetchone()

    assert row == ("agent-normal", "execute_query", "ALLOW")


def test_log_audit_event_falls_back_cleanly_on_connection_error(tmp_path, monkeypatch):
    primary_db_path = "postgresql://invalid-host:5432/audit"
    fallback_db_path = tmp_path / "fallback.db"

    monkeypatch.setattr(db_module, "DB_FILE", str(fallback_db_path))

    original_connect = sqlite3.connect

    def connect_stub(database, *args, **kwargs):
        if database == primary_db_path:
            raise sqlite3.OperationalError("simulated primary connection failure")
        return original_connect(database, *args, **kwargs)

    monkeypatch.setattr(db_module.sqlite3, "connect", connect_stub)

    with execution_context("agent-fallback"):
        result = log_audit_event(
            event_id="evt-fallback",
            tool_name="execute_query",
            payload="DROP TABLE users;",
            verdict="BLOCK",
            latency_ms=2.5,
            db_path=primary_db_path,
        )

    assert result is False

    with sqlite3.connect(fallback_db_path) as connection:
        cursor = connection.cursor()
        cursor.execute("SELECT agent_id, tool_name, verdict FROM audit_logs WHERE id = ?", ("evt-fallback",))
        row = cursor.fetchone()

    assert row == ("agent-fallback", "execute_query", "BLOCK")