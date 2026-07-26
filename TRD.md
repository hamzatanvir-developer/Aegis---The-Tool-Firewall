# Aegis — Technical Requirements Document

## Implementation Stack

- Python 3.9+ application package.
- Standard-library-first runtime interception and dashboard server.
- PyYAML for policy file parsing.
- SQLite for local audit storage and fallback persistence.
- `pytest` for the test suite.

## Delivered Architecture

### Interception path

1. A Python function is decorated with `@guardrail`.
2. The decorator captures arguments and evaluates them with `PolicyEngine`.
3. Allowed calls execute normally; blocked calls raise `PolicyViolationError`.
4. Audit events are written through `aegis.db.log_audit_event`.
5. Async functions are awaited transparently.

### Context path

1. Execution context is stored in `contextvars`.
2. `agent_id`, `org_id`, and `api_key_hash` are isolated per task or thread.
3. Audit logging reads the active context when an explicit agent ID is not provided.

### Audit persistence path

1. Local audit events are written to SQLite by default.
2. If the primary database path fails, Aegis attempts a local fallback write.
3. Failures are never allowed to crash the host application.
4. The persistence function returns a boolean status for observability.

### CLI and dashboard path

1. `aegis init` creates a default `guardrails.yaml`.
2. `aegis check` validates YAML syntax and required keys.
3. `aegis status` reports local audit counts.
4. `aegis dashboard` launches a local inspection interface over HTTP.

## Policy Model

The shipped policy engine supports deterministic matching for destructive SQL and shell payloads, plus secret redaction for common credential patterns. It is intentionally small, local, and auditable.

## Data Storage

- Local SQLite audit database: `aegis_audit.db`.
- Audit table fields: event ID, agent ID, tool name, payload, verdict, triggered rule, latency, and timestamp.

## Test Coverage

The repository includes unit coverage for:

- sync and async decorator behavior,
- context isolation,
- audit logging resilience,
- CLI commands,
- dashboard responses and metrics.

## Explicitly Out of Scope

- Rust or sidecar proxy implementations.
- Next.js or other browser SPA control planes.
- Redis, Prometheus, Grafana, or remote fleet infrastructure.
- API key management services and RBAC backends.



