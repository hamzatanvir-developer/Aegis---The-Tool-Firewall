from aegis.engine import PolicyEngine

# Initialize the policy engine
engine = PolicyEngine()

# Test evaluating a tool call
result = engine.evaluate(
    tool_name="run_shell",
    kwargs={"command": "rm -rf /"},
    context={"agent_id": "test_agent"}
)

print(f"Is Allowed: {result.is_allowed}")
print(f"Triggered Rule: {result.triggered_rule}")
print(f"Reason: {result.reason}")