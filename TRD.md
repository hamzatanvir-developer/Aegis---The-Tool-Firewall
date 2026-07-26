2. Technical Requirements Document (TRD)
Tech Stack & Rationale
┌─────────────────────────────────────────────────────────────────────────┐
│                        AGENTGUARD TECH STACK                            │
├─────────────────────────────────────────────────────────────────────────┤
│  • Client Layer:      Python SDK (`agentguard-py`), TypeScript SDK     │
│  • Edge Proxy Core:   Rust / Axum (Low latency policy engine)           │
│  • Control Plane API: FastAPI / Python 3.12                            │
│  • Frontend UI:       Next.js 14 (App Router) + Tailwind CSS + ShadcnUI │
│  • Database Engine:   PostgreSQL 16 (Relational + JSONB Audit Logs)     │
│  • Cache & Stream:    Redis 7.2 (Rate limiting & Policy Caching)        │
│  • Observability:     OpenTelemetry + Prometheus + Grafana              │
└─────────────────────────────────────────────────────────────────────────┘

Rationale
Rust Policy Engine (Proxy Core): Guarantees sub-millisecond policy evaluation, zero garbage collection pauses, and memory safety when parsing thousands of concurrent agent payload streams.
Python SDK: Python is the native language of AI/LLM development (LangChain, CrewAI, LlamaIndex).
PostgreSQL + JSONB: Provides relational structure for user auth/teams while leveraging JSONB indexing for flexible, unstructured agent audit logs.
System Architecture & Data Flow
                                 DATA FLOW DIAGRAM
                                  
  ┌───────────────┐     1. Tool Call      ┌───────────────────────────────┐
  │   AI Agent    │──────────────────────►│    AgentGuard Interceptor     │
  │ (LangChain/   │                       │       (SDK / Proxy)           │
  │ OpenAI App)   │◄──────────────────────│                               │
  └───────────────┘     4. Allow / Block  └───────────────┬───────────────┘
                                                          │
                                            2. Query Rules│ 3. Async Log
                                                          ▼
                                          ┌───────────────────────────────┐
                                          │     Redis / Local Cache       │
                                          └───────────────┬───────────────┘
                                                          │ Sync Cache Miss
                                                          ▼
                                          ┌───────────────────────────────┐
                                          │  PostgreSQL (Control Plane)   │
                                          └───────────────────────────────┘

Subsystems & API Protocols
Rule Evaluation Engine (RE Engine): Evaluates incoming JSON tool-call payloads against active compiled policies. Uses AST parsers (e.g., sqlparser-rs) for deep query analysis rather than naive regex.
Audit & Telemetry Pipeline: Async worker thread buffers events in memory and flushes batches to Redis/Postgres, guaranteeing zero latency impact on the critical path of the agent.
Control Plane API: REST API for managing users, organizations, policy files, and API keys.
Security, Auth & Threat Model
Authentication: HMAC SHA-256 signed API Keys for SDK-to-Control-Plane communication; JWT with short-lived access tokens (15 mins) and HTTP-only refresh cookies for Web Dashboard.
Authorization: Role-Based Access Control (RBAC): Owner, Admin, Security Engineer, Viewer.
Threat Model:
┌─────────────────────────────┬─────────────────────────────────┬──────────────────────────────────────────┐
│ Threat Vector               │ Risk Level                      │ Mitigation Strategy                      │
├─────────────────────────────┼─────────────────────────────────┼──────────────────────────────────────────┤
│ Prompt Injection Bypass     │ High                            │ Multi-stage AST parsing & decoder pipeline│
│ Rogue Agent Replay Attack   │ Medium                          │ Nonce-based signature verification       │
│ Log Storage Tampering       │ High                            │ HMAC-chained append-only audit trail     │
└─────────────────────────────┴─────────────────────────────────┴────────────────────



