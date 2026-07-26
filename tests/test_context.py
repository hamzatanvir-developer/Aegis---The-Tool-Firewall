import asyncio
import sqlite3
from concurrent.futures import ThreadPoolExecutor

from aegis.context import (
    execution_context,
    get_execution_context,
    reset_execution_context,
    set_execution_context,
)
from aegis.db import init_db, log_audit_event


def test_execution_context_set_get_and_reset():
    tokens = set_execution_context("agent-123", "org-456", "hash-789")
    try:
        context = get_execution_context()
        assert context.agent_id == "agent-123"
        assert context.org_id == "org-456"
        assert context.api_key_hash == "hash-789"
    finally:
        reset_execution_context(tokens)

    reset_context = get_execution_context()
    assert reset_context.agent_id == "default_agent"
    assert reset_context.org_id is None
    assert reset_context.api_key_hash is None


def test_execution_context_isolated_across_async_tasks_and_threads():
    async def async_worker(agent_id: str) -> str:
        tokens = set_execution_context(agent_id)
        try:
            await asyncio.sleep(0)
            return get_execution_context().agent_id
        finally:
            reset_execution_context(tokens)

    async def run_async_workers() -> None:
        results = await asyncio.gather(async_worker("agent-a"), async_worker("agent-b"))
        assert sorted(results) == ["agent-a", "agent-b"]
        assert get_execution_context().agent_id == "default_agent"

    asyncio.run(run_async_workers())

    def thread_worker(agent_id: str) -> str:
        tokens = set_execution_context(agent_id)
        try:
            return get_execution_context().agent_id
        finally:
            reset_execution_context(tokens)

    with ThreadPoolExecutor(max_workers=1) as executor:
        assert executor.submit(thread_worker, "thread-agent").result() == "thread-agent"

    assert get_execution_context().agent_id == "default_agent"


def test_log_audit_event_uses_active_context_agent_id(tmp_path):
    db_path = tmp_path / "audit.db"
    init_db(db_path=str(db_path))

    with execution_context("tenant-agent", "org-1", "hash-1"):
        log_audit_event(
            event_id="evt-1",
            tool_name="execute_query",
            payload="SELECT 1",
            verdict="ALLOW",
            latency_ms=1.23,
            db_path=str(db_path),
        )

    with sqlite3.connect(db_path) as connection:
        cursor = connection.cursor()
        cursor.execute("SELECT agent_id, tool_name, verdict FROM audit_logs WHERE id = ?", ("evt-1",))
        row = cursor.fetchone()

    assert row == ("tenant-agent", "execute_query", "ALLOW")