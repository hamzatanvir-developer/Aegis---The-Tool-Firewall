"""End-to-end Aegis demo pipeline."""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path
from typing import Callable

import aegis.db as db_module
from aegis.context import execution_context, get_execution_context
from aegis.core import guardrail
from aegis.db import init_db, log_audit_event
from aegis.exceptions import PolicyViolationError


@guardrail
async def execute_sql(query: str) -> str:
    await asyncio.sleep(0)
    return f"Query executed: {query}"


async def demo_async_guardrails() -> None:
    safe_result = await execute_sql(query="SELECT * FROM users WHERE active = 1;")
    print(f"[ALLOW] {safe_result}")

    try:
        await execute_sql(query="DROP TABLE users;")
    except PolicyViolationError as exc:
        print(f"[BLOCK] {exc}")


async def demo_context_isolation() -> None:
    async def capture_agent(agent_id: str) -> str:
        with execution_context(agent_id):
            await asyncio.sleep(0)
            return get_execution_context().agent_id

    agents = await asyncio.gather(capture_agent("agent-a"), capture_agent("agent-b"))
    print(f"[CONTEXT] isolated agents: {agents}")


def _simulate_primary_db_failure() -> Callable[..., sqlite3.Connection]:
    original_connect = sqlite3.connect

    def connect(database: str, *args: object, **kwargs: object) -> sqlite3.Connection:
        if database.startswith("postgresql://"):
            raise sqlite3.OperationalError("simulated PostgreSQL connection drop")
        return original_connect(database, *args, **kwargs)

    return connect


def demo_resilient_audit_logging(fallback_db_path: Path) -> None:
    original_db_file = db_module.DB_FILE
    original_connect = db_module.sqlite3.connect
    db_module.DB_FILE = str(fallback_db_path)
    db_module.sqlite3.connect = _simulate_primary_db_failure()
    try:
        init_db(db_path=str(fallback_db_path))
        with execution_context("demo-agent", "demo-org", "demo-key-hash"):
            success = log_audit_event(
                event_id="demo-fallback-1",
                tool_name="execute_sql",
                payload="SELECT 1",
                verdict="ALLOW",
                latency_ms=1.0,
                db_path="postgresql://demo-primary:5432/audit",
            )
        print(f"[RESILIENCE] persistence success flag: {success}")
    finally:
        db_module.DB_FILE = original_db_file
        db_module.sqlite3.connect = original_connect


def demo_quick_log_readback(db_path: Path) -> None:
    with sqlite3.connect(db_path) as connection:
        cursor = connection.cursor()
        cursor.execute("SELECT agent_id, verdict, tool_name, payload FROM audit_logs ORDER BY created_at DESC")
        rows = cursor.fetchall()

    print("[LOGS] recent audit rows:")
    for agent_id, verdict, tool_name, payload in rows:
        print(f"  - {agent_id} | {verdict} | {tool_name} | {payload}")


async def main() -> None:
    fallback_db_path = Path("demo_audit.db")
    if fallback_db_path.exists():
        fallback_db_path.unlink()

    try:
        await demo_async_guardrails()
        await demo_context_isolation()
        demo_resilient_audit_logging(fallback_db_path)
        demo_quick_log_readback(fallback_db_path)
    finally:
        if fallback_db_path.exists():
            try:
                fallback_db_path.unlink()
            except PermissionError:
                pass


if __name__ == "__main__":
    asyncio.run(main()) 