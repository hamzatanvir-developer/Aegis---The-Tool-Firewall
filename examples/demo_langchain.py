"""End-to-End Demo Script for Aegis LangChain Integration & Firewall Protection."""

import asyncio
from aegis.engine import PolicyEngine
from aegis.integrations.langchain import AegisLangChainCallbackHandler
from aegis.exceptions import PolicyViolationError


class MockLangChainTool:
    """Mock LangChain tool for demonstration purposes."""
    def __init__(self, name: str):
        self.name = name

    def run(self, tool_input: str, callbacks=None):
        # Simulate LangChain callback invocation
        if callbacks:
            for cb in callbacks:
                # Trigger the callback's on_tool_start method
                cb.on_tool_start({"name": self.name}, tool_input, run_id=None)
        return f"Tool '{self.name}' executed successfully with input: {tool_input}"


def run_demo():
    print("=" * 60)
    print("🚀 AEGIS TOOL FIREWALL: LANGCHAIN INTEGRATION DEMO")
    print("=" * 60)

    # 1. Initialize Policy Engine and register valid tools
    engine = PolicyEngine()
    engine.register_tool("safe_search")
    engine.register_tool("db_query")

    # 2. Instantiate the Aegis LangChain callback handler
    aegis_handler = AegisLangChainCallbackHandler(engine=engine, agent_id="demo_agent_007")

    # Scenario A: Safe Tool Execution
    print("\n[Scenario 1] Agent attempts a safe search query...")
    safe_tool = MockLangChainTool(name="safe_search")
    try:
        result = safe_tool.run("latest python features 2026", callbacks=[aegis_handler])
        print(f"✅ Success: {result}")
    except PolicyViolationError as e:
        print(f"❌ Blocked unexpectedly: {e}")

    # Scenario B: Malicious SQL Injection Interception
    print("\n[Scenario 2] Agent hallucinates and attempts a destructive SQL injection...")
    db_tool = MockLangChainTool(name="db_query")
    try:
        db_tool.run("DROP TABLE users; SELECT * FROM credentials;", callbacks=[aegis_handler])
        print("❌ Failed: Attack was NOT blocked!")
    except PolicyViolationError as e:
        print(f"🛡️ Aegis Firewall Intercepted Threat Successfully!")
        print(f"   Reason: {e}")
        print(f"   Triggered Rule: {e.rule_name}")

    print("\n" + "=" * 60)
    print("✨ Demo completed. All threat events logged securely to SQLite database.")
    print("=" * 60)


if __name__ == "__main__":
    run_demo()