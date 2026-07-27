Markdown
# Aegis Tool Firewall - Complete Technical & Enterprise Reference

Aegis is an enterprise-grade security middleware, interception engine, and real-time auditing platform built explicitly to monitor, inspect, evaluate, and govern tool execution calls made by autonomous AI agents, Large Language Model (LLM) pipelines, and distributed automation services. 

As AI systems gain broader access to local environments, shell execution tools, database connections, and external APIs, the risk of prompt injection, unauthorized data manipulation, and runaway system commands increases exponentially. Aegis solves this by interposing a rigorous inspection checkpoint between tool-dispatching logic and execution environments, validating each action, assigning security verdicts (`ALLOWED`, `BLOCKED`, or `REQUIRES APPROVAL`), and logging every event immutably into a cloud-backed relational database.

---

## Table of Contents
1. [Executive Summary & Core Purpose](#1-executive-summary--core-purpose)
2. [Complete Architecture & System Data Flow](#2-complete-architecture--system-data-flow)
3. [Comprehensive Feature Set](#3-comprehensive-feature-set)
4. [Technology Stack & Exact Component Versions](#4-technology-stack--exact-component-versions)
5. [System Prerequisites & Environment Requirements](#5-system-prerequisites--environment-requirements)
6. [Detailed Project Directory Structure](#6-detailed-project-directory-structure)
7. [Installation & PyPI Deployment Workflow](#7-installation--pypi-deployment-workflow)
8. [Environment Configuration (Secure Setup)](#8-environment-configuration-secure-setup)
9. [Complete API Reference Documentation](#9-complete-api-reference-documentation)
10. [AI Workflow Integration & Code Implementation](#10-ai-workflow-integration--code-implementation)
11. [Database Verification & Testing Suite](#11-database-verification--testing-suite)

---

## 1. Executive Summary & Core Purpose

**Aegis - The Tool Firewall** acts as an invisible, high-security gatekeeper for modern artificial intelligence architectures. When autonomous agents attempt to invoke system commands, SQL queries, or file modifications, Aegis intercepts the function boundary call, evaluates contextual telemetry, checks compliance policies, enforces required human/system approvals, and persists immutable audit records to a Supabase PostgreSQL backend database.

---

## 2. Complete Architecture & System Data Flow

Aegis implements a decoupled architecture combining a Python interceptor package with a cloud-managed PostgreSQL database backend.

```text
┌─────────────────────────────────┐
│     AI Agent / Workflow         │
└────────────────┬────────────────┘
                 │ 1. Intercepts at function boundary / Guardrail execution
                 ▼
┌─────────────────────────────────┐
│     Aegis Security Engine       │
├─────────────────────────────────┤
│ • Policy Evaluation             │
│ • Verdict: ALLOWED / BLOCKED /  │
│   REQUIRES APPROVAL             │
└────────────────┬────────────────┘
                 │ 2. psycopg2 Connection Pool
                 ▼
┌─────────────────────────────────┐
│ Supabase Cloud PostgreSQL DB    │
│ (Table: firewall_logs)          │
└─────────────────────────────────┘
End-to-End Execution Flow:
Trigger Initiation: An automated workflow or AI agent prepares to execute a sensitive tool function.

Payload Interception: Aegis catches the invocation payload at the function boundary before any destructive operation executes.

Policy Evaluation: The engine reviews event metrics, metadata, parameters, and access rights against established rules.

Security Verdict Assignment: The operation is systematically categorized as ALLOWED, BLOCKED, or flagged for explicit approval.

Database Persistence: Using a robust PostgreSQL database adapter (psycopg2), Aegis opens a secure session to the Supabase cloud database instance and executes a parameterized SQL insertion query into the firewall_logs table.

Execution / Rejection: Depending on the policy verdict, the tool either executes normally, triggers an approval workflow, or raises a PolicyViolationError.

3. Comprehensive Feature Set
Real-Time Request Interception: Captures tool execution metrics instantaneously at function execution boundaries.

Granular Security Verdicts: Dynamically categorizes operations into strict states (ALLOWED, BLOCKED, or REQUIRES APPROVAL) based on security policy logic.

Persistent Cloud Auditing: Integrates directly with Supabase PostgreSQL to maintain a centralized, highly available, and queryable log history.

Input Schema Protection: Utilizes strict Pydantic data validation models to reject malformed or contaminated telemetry data.

Asynchronous Support: Built to seamlessly support async tool functions and tenant-isolated execution environments.

Graceful Degradation: Designed to handle storage interruptions cleanly without halting primary operational workflows.

4. Technology Stack & Exact Component Versions
Programming Language: Python (v3.10 or higher)

Web Framework: FastAPI (v0.110.0)

ASGI Server: Uvicorn (v0.28.0)

Data Validation Engine: Pydantic (v2.6.4)

PostgreSQL Database Driver: psycopg2-binary (v2.9.9)

Environment Configuration: python-dotenv (v1.0.1)

Cloud Database Provider: Supabase (Hosted PostgreSQL Cluster)

Distribution Channel: PyPI (Python Package Index)

Version Control: Git & GitHub

5. System Prerequisites & Environment Requirements
Before setting up or deploying Aegis, your development or server environment must meet these specifications:

Python Runtime: Python 3.10+ installed and accessible via system PATH.

Package Manager: pip or Python's built-in module runner (python -m pip).

Database Account: An active Supabase project with an available PostgreSQL connection string.

Version Control: Git installed for repository tracking and versioning.

6. Detailed Project Directory Structure
Plaintext
Aegis - The tool firewall/
│
├── app.py                  # FastAPI backend service and routing logic
├── test_db.py              # Automated database connection verification script
├── test_queries.py         # Schema inspection and query testing suite
├── pyproject.toml          # Package build configuration, metadata, and dependencies
├── requirements.txt        # Production dependency manifest
├── Procfile                # Startup process configuration
├── .env                    # Local environment variables file (git-ignored)
└── README.md               # Comprehensive system documentation
7. Installation & PyPI Deployment Workflow
Aegis is published on the Python Package Index (PyPI) as aegis-tool-firewall.

Installing for Production Use:
Any user or company can download and install Aegis instantly into their workflow using pip:

DOS
pip install aegis-tool-firewall
Installing for Development & Testing:
DOS
pip install aegis-tool-firewall[dev]
8. Environment Configuration (Secure Setup)
To allow Aegis to connect to your Supabase database and log audit trails, create a .env file in your project root and configure your connection string securely using placeholders:

Code snippet
DATABASE_URL=postgresql://postgres.your_project_id:your_database_password@aws-0-region.pooler.supabase.com:5432/postgres
Security Note: Never hardcode actual database passwords or credentials into public documentation, source code files, or repositories. Always load credentials dynamically via environment variables (os.environ).

9. Complete API Reference Documentation
1. Root Health Check Endpoint
Route: /

Method: GET

Description: Verifies that the Aegis backend service is active and operational.

Success Response (JSON):

JSON
{
  "message": "Aegis Tool Firewall API is running live successfully!"
}
2. Log Firewall Event Endpoint
Route: /log-event

Method: POST

Description: Validates incoming tool telemetry payloads and records audit logs directly into Supabase PostgreSQL.

Request Payload Structure (JSON):

JSON
{
  "event_type": "TOOL_EXECUTION",
  "status": "BLOCKED",
  "details": "Unauthorized shell command execution attempt blocked",
  "source_ip": "192.168.1.50"
}
Success Response (JSON):

JSON
{
  "status": "success",
  "message": "Firewall log saved to Supabase!"
}
10. AI Workflow Integration & Code Implementation
Companies and developers integrate Aegis into their AI agent runtimes by applying the @guardrail decorator to sensitive functions, ensuring live interception, policy validation, and approval checks:

Python
import os
from aegis.core import guardrail
from aegis.exceptions import PolicyViolationError

# Configure your secure environment variable dynamically
os.environ["DATABASE_URL"] = "postgresql://postgres.your_project_id:your_database_password@aws-0-region.pooler.supabase.com:5432/postgres"

@guardrail
def execute_agent_tool(query: str) -> str:
    # Tool execution protected under Aegis security boundaries
    return f"Executed successfully: {query}"
11. Database Verification & Testing Suite
To confirm that your database connection pool and table structures are working seamlessly, execute the verification scripts included in the repository:

DOS
python test_db.py
python test_queries.py 