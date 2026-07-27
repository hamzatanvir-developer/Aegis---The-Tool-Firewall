Markdown
# Aegis Tool Firewall

> An enterprise-grade security middleware, interception engine, and real-time auditing platform built explicitly to govern tool execution calls made by autonomous AI agents and LLM pipelines.

---

## 🚀 Executive Summary

As AI systems gain broader access to local environments, shell execution tools, database connections, and external APIs, the risk of prompt injection and runaway system commands increases exponentially. **Aegis** intercepts tool-dispatching logic at the function boundary, validates each action, assigns security verdicts (`ALLOWED`, `BLOCKED`, or `REQUIRES APPROVAL`), and logs events immutably into a cloud-backed relational database.

---

## 📊 System Architecture

```text
┌─────────────────────────────────┐
│     AI Agent / Workflow         │
└────────────────┬────────────────┘
                 │ 1. Intercepts at function boundary
                 ▼
┌─────────────────────────────────┐
│     Aegis Security Engine       │
├─────────────────────────────────┤
│ • Policy Evaluation             │
│ • Verdict Assignment            │
└────────────────┬────────────────┘
                 │ 2. psycopg2 Connection Pool
                 ▼
┌─────────────────────────────────┐
│ Supabase Cloud PostgreSQL DB    │
│ (Table: firewall_logs)          │
└─────────────────────────────────┘
✨ Key Features
Real-Time Request Interception: Captures tool execution metrics instantaneously at function boundaries.

Granular Security Verdicts: Categorizes operations into strict states (ALLOWED, BLOCKED, or REQUIRES APPROVAL).

Persistent Cloud Auditing: Integrates directly with Supabase PostgreSQL for centralized log management.

Input Schema Protection: Utilizes strict Pydantic data validation models to reject malformed telemetry.

Asynchronous Support: Seamlessly supports async tool functions and tenant-isolated workflows.

🛠️ Technology Stack
Language: Python 3.10+

Framework: FastAPI (v0.110.0)

Server: Uvicorn (v0.28.0)

Validation: Pydantic (v2.6.4)

Database Driver: psycopg2-binary (v2.9.9)

Database Backend: Supabase PostgreSQL Cluster

📦 Installation
Install the package via PyPI for production use:

DOS
pip install aegis-tool-firewall
For development and testing:

DOS
pip install aegis-tool-firewall[dev]
⚙️ Environment Configuration
Create a .env file in your root directory and configure your database connection string securely:

Code snippet
DATABASE_URL=postgresql://postgres.your_project_id:your_database_password@aws-0-region.pooler.supabase.com:5432/postgres
Security Note: Never commit your actual .env file or hardcode database passwords into source code repositories.

🔌 API Reference
1. Health Check Endpoint
Route: /

Method: GET

Response:

JSON
{
  "message": "Aegis Tool Firewall API is running live successfully!"
}
2. Log Firewall Event
Route: /log-event

Method: POST

Payload:

JSON
{
  "event_type": "TOOL_EXECUTION",
  "status": "BLOCKED",
  "details": "Unauthorized shell command execution attempt blocked",
  "source_ip": "192.168.1.50"
}
💻 Code Implementation
Integrate Aegis into your AI agent runtimes using the @guardrail decorator:

Python
import os
from aegis.core import guardrail
from aegis.exceptions import PolicyViolationError

os.environ["DATABASE_URL"] = "postgresql://postgres.your_project_id:your_password@host:5432/postgres"

@guardrail
def execute_agent_tool(query: str) -> str:
    return f"Executed successfully: {query}"
🧪 Testing Suite
Run the database verification scripts to confirm your connection pool and table structures:

DOS
python test_db.py
python test_queries.py