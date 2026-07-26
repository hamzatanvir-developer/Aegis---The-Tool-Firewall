# Aegis — Product Requirements Document

## Problem Statement

AI agents now execute real-world tool calls inside production systems: database queries, shell commands, and application-side actions. Prompt injection and tool misuse happen after the model has already produced a command, so prompt-only defenses are insufficient.

Aegis protects the tool-call execution boundary in Python applications. It intercepts function calls before execution, evaluates them against local guardrails, redacts secrets, logs audit events, and fails closed when policy evaluation or persistence is unsafe.

## Product Goals

- Provide a minimal Python SDK with a single decorator, `@guardrail`.
- Support both synchronous and asynchronous tool functions.
- Load policy definitions from local YAML files.
- Record audit events locally with SQLite and resilient fallback behavior.
- Track agent and tenant context safely with `contextvars`.
- Expose a CLI for initialization, validation, status, and dashboard access.
- Provide a lightweight local dashboard for audit inspection.

## Primary Users

- AI engineers who need a fast, low-friction tool firewall for Python agent workflows.
- Security leads who need auditability and deterministic enforcement for tool execution.
- Platform engineers who need local, production-safe resilience when audit logging fails.

## Core User Journeys

### Local developer workflow

1. Install Aegis into a Python project.
2. Create a default `guardrails.yaml` with `aegis init`.
3. Validate the policy file with `aegis check`.
4. Wrap a tool function with `@guardrail`.
5. Observe blocked destructive payloads, redaction, and audit log writes.

### Operational inspection workflow

1. Launch `aegis dashboard` against the local audit database.
2. Review totals, allowed vs blocked counts, and top triggered rules.
3. Filter audit rows by verdict or agent ID.
4. Inspect payloads and latency directly in the browser.

## Functional Requirements

- Intercept tool calls before execution.
- Detect destructive SQL and shell patterns.
- Redact secrets and sensitive values before audit persistence.
- Record structured audit events locally.
- Recover safely from database failures without crashing the host application.
- Support async tool functions transparently.
- Maintain tenant-scoped context per request or task.
- Provide a CLI and dashboard for local operations.

## Non-Functional Requirements

- Keep the implementation lightweight and standard-library-first.
- Preserve low overhead on the interception path.
- Fail closed for policy evaluation errors.
- Keep context isolation safe across threads and async tasks.
- Keep audit logging durable and non-fatal.

## Success Criteria

- The SDK decorator works for both sync and async tools.
- Audit logging continues even when a primary database path fails.
- Context state does not leak across concurrent tasks or threads.
- The CLI can initialize, validate, and inspect local guardrails.
- The dashboard renders local metrics and filtered audit rows.

## Scope Boundaries

- In scope: Python tool interception, local policy evaluation, local audit logging, context isolation, CLI, and local dashboard.
- Out of scope: Remote control planes, fleet management, API-key orchestration services, sidecar proxies, and model training.

