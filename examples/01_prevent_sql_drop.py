import sys
from aegis.core import guardrail
from aegis.exceptions import PolicyViolationError

# Intercept function calls at runtime
@guardrail
def execute_database_query(sql_statement: str):
    print(f"[DATABASE EXECUTING]: {sql_statement}")
    return "Query executed successfully."

if __name__ == "__main__":
    print("=== AEGIS RUNTIME DEMO ===")
    
    # 1. Safe Query
    print("\n1. Testing safe user lookup...")
    res = execute_database_query(sql_statement="SELECT * FROM users WHERE id = 101;")
    print(f"Result: {res}")

    # 2. Dangerous Mutation Interception
    print("\n2. Simulating rogue LLM tool call ('DROP TABLE')...")
    try:
        execute_database_query(sql_statement="DROP TABLE production_users;")
    except PolicyViolationError as e:
        print(f"SUCCESS: Aegis intercepted destructive action!")
        print(f"Rule Triggered: {e.rule_name}")
        print(f"Blocked Payload: {e.payload}")