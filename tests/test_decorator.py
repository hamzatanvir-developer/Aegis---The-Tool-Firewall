import asyncio

import pytest

from aegis.core import guardrail
from aegis.exceptions import PolicyViolationError


def test_guardrail_supports_async_tools(monkeypatch):
    audit_events = []

    def fake_log_audit_event(*, event_id, agent_id, tool_name, payload, verdict, triggered_rule, latency_ms):
        audit_events.append(
            {
                "event_id": event_id,
                "agent_id": agent_id,
                "tool_name": tool_name,
                "payload": payload,
                "verdict": verdict,
                "triggered_rule": triggered_rule,
                "latency_ms": latency_ms,
            }
        )

    monkeypatch.setattr("aegis.core.log_audit_event", fake_log_audit_event)

    @guardrail
    async def execute_query(sql_query: str) -> str:
        await asyncio.sleep(0)
        return f"Query executed: {sql_query}"

    async def run_scenarios() -> None:
        allowed_result = await execute_query(sql_query="SELECT * FROM users WHERE id = 1;")
        assert allowed_result == "Query executed: SELECT * FROM users WHERE id = 1;"

        with pytest.raises(PolicyViolationError):
            await execute_query(sql_query="DROP TABLE users;")

    asyncio.run(run_scenarios())

    assert [event["verdict"] for event in audit_events] == ["ALLOW", "BLOCK"]
    assert audit_events[0]["tool_name"] == "execute_query"
    assert audit_events[1]["triggered_rule"] == "block_destructive_sql"