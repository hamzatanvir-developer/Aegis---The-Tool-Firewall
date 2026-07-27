Markdown
# Aegis Tool Firewall

Enterprise-grade security middleware and real-time interception engine for autonomous AI agents and LLM pipelines.

## Overview
Aegis intercepts tool-execution calls at the function boundary, evaluates security policies, assigns verdicts (ALLOWED, BLOCKED, or REQUIRES APPROVAL), and logs events to a Supabase PostgreSQL database.

## Installation
```cmd
pip install aegis-tool-firewall
Environment Setup
Create a .env file in your root folder:

Code snippet
DATABASE_URL=postgresql://postgres.project_id:password@host:5432/postgres
Usage Example
Python
import os
from aegis.core import guardrail

os.environ["DATABASE_URL"] = "postgresql://..."

@guardrail
def execute_agent_tool(query: str) -> str:
    return f"Executed: {query}"
Testing
DOS
python test_db.py
python test_queries.py

4. Save the file (`Ctrl + S`), then run:
```cmd
git add README.md
git commit -m "Fix markdown syntax breaking"
git push origin main