import uuid
import time
import sqlite3
from aegis.core import guardrail
from aegis.exceptions import PolicyViolationError
from aegis.db import init_db, log_audit_event

# 1. Initialize local SQLite audit database
init_db()

@guardrail
def execute_query(sql_query: str):
    return f"Query executed: {sql_query}"

def run_demonstration():
    print("--- Running Aegis Database Logging Demo ---")
    
    queries = [
        ("agent-01", "SELECT * FROM users WHERE active = 1;"),
        ("agent-02", "DROP TABLE users;"),
        ("agent-01", "SELECT email FROM subscribers;")
    ]

    for agent_id, query in queries:
        start_time = time.perf_counter()
        event_id = str(uuid.uuid4())
        verdict = "ALLOW"
        triggered_rule = None

        try:
            result = execute_query(sql_query=query)
            print(f"[SUCCESS] Agent '{agent_id}': {result}")
        except PolicyViolationError as e:
            verdict = "BLOCK"
            triggered_rule = str(e)
            print(f"[BLOCKED] Agent '{agent_id}': Attempted hazardous SQL query!")

        latency_ms = round((time.perf_counter() - start_time) * 1000, 3)

        # Log event directly to the audit database
        log_audit_event(
            event_id=event_id,
            agent_id=agent_id,
            tool_name="execute_query",
            payload=query,
            verdict=verdict,
            triggered_rule=triggered_rule,
            latency_ms=latency_ms
        )

    # Print stored records from SQLite DB
    print("\n--- Reading Stored Audit Logs from DB ---")
    conn = sqlite3.connect("aegis_audit.db")
    cursor = conn.cursor()
    cursor.execute("SELECT agent_id, verdict, payload, latency_ms FROM audit_logs")
    logs = cursor.fetchall()
    
    for row in logs:
        print(f"Agent: {row[0]} | Verdict: {row[1]} | Latency: {row[3]}ms | Payload: {row[2]}")
    conn.close()

if __name__ == "__main__":
    run_demonstration()