5. Workflow.md
Phased Development Roadmap
Phase 1: Open-Source SDK (Weeks 1–2)  ---> Phase 2: Web Dashboard & SaaS (Weeks 3–4) ---> Phase 3: Enterprise Proxy (Weeks 5–6)
Sprint Backlog & Milestones
Phase 1: Open-Source Core SDK (Sprint 1 - Days 1 to 14)
Milestone 1.1: Core Python decorator @guardrail() and tool call wrapper.

Milestone 1.2: YAML parser for local guardrails.yaml configurations.

Milestone 1.3: Built-in SQL AST analyzer (DROP, DELETE detection) and secret scanners.

Milestone 1.4: PyPI package release (pip install agentguard).

Phase 2: Web Control Plane & SaaS (Sprint 2 - Days 15 to 28)
Milestone 2.1: Next.js Dashboard + Authentication (JWT + OAuth2).

Milestone 2.2: Centralized Audit Log Viewer with filtering and JSON inspect.

Milestone 2.3: Webhook alerting pipeline (Slack & Email integration).

Phase 3: Enterprise Gateway & Proxy Sidecar (Sprint 3 - Days 29 to 42)
Milestone 3.1: High-throughput Rust HTTP proxy sidecar docker container.

Milestone 3.2: Human-in-the-Loop Slack approval workflow.

Milestone 3.3: SOC2 Type II compliance controls & audit export.

Definition of Done (DoD)
All unit tests pass with > 90% code coverage.

Latency benchmark confirms < 5ms overhead per interception.

Security review completed (no high or critical vulnerabilities).

Documentation updated with working code examples.