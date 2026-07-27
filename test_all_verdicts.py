from aegis.engine import PolicyEngine

engine = PolicyEngine()

def run_test(tool_name, kwargs, agent_id="test_agent"):
    result = engine.evaluate(tool_name, kwargs, context={"agent_id": agent_id})
    print(f"Tool: {tool_name:<15} | Payload: {str(kwargs):<20} | Verdict: {result.verdict:<16} | Rule: {result.triggered_rule}")

print("=== Running Aegis Policy Verdict Tests ===")

# Test 1: Require Approval (High-risk shell execution)
run_test("execute_shell", {"command": "ls -la"})

# Test 2: Hard Block (Destructive shell command)
run_test("run_shell", {"command": "rm -rf /"})

# Test 3: Hard Block (Destructive SQL)
run_test("execute_sql", {"query": "DROP TABLE users;"})

# Test 4: Allow (Safe standard operation)
run_test("read_file", {"path": "config.json"})

print("==========================================")