Markdown
# Aegis Tool Firewall

> Enterprise-grade security middleware and real-time interception engine for autonomous AI agents and LLM pipelines.

---

## 🎯 The Problem
As AI agents gain direct access to local shells, database connections, and external APIs, they become vulnerable to prompt injection, unauthorized data manipulation, and runaway system commands. 

## 🛡️ The Solution: How Aegis Works
Aegis interposes a strict inspection checkpoint right at the function execution boundary:
1. **Intercepts:** Catches tool execution payloads before destructive actions run.
2. **Evaluates:** Checks parameters and policies, assigning a strict verdict (`ALLOWED`, `BLOCKED`, or `REQUIRES APPROVAL`).
3. **Audits:** Persists immutable logs directly to a Supabase PostgreSQL backend.

---

## 📦 Quick Installation

Install the package directly via PyPI:

```cmd
pip install aegis-tool-firewall
⚙️ Environment Configuration
Create a .env file in your root folder and set your cloud database connection string:

Code snippet
DATABASE_URL=postgresql://postgres.your_project_id:your_password@aws-0-region.pooler.supabase.com:5432/postgres
💻 Code Implementation & Workflow Usage
Protect your AI tool functions instantly using the @guardrail decorator:

Python
import os
from aegis.core import guardrail
from aegis.exceptions import PolicyViolationError

# Load secure database configuration
os.environ["DATABASE_URL"] = "postgresql://postgres.your_project_id:your_password@host:5432/postgres"

@guardrail
def execute_agent_tool(query: str) -> str:
    # Protected under Aegis security boundaries
    return f"Executed successfully: {query}"
🧪 Real-Time Testing & Verification
Run the built-in validation scripts to confirm your database connection pool and table logging:

DOS
python test_db.py
python test_queries.py