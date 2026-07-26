# Aegis — Execution Flow

## Interception Pipeline

1. A Python tool function is invoked.
2. `@guardrail` captures the positional and keyword arguments.
3. The decorator evaluates the payload with `PolicyEngine`.
4. If blocked, Aegis raises `PolicyViolationError` and writes an audit record.
5. If allowed, Aegis optionally applies redactions and executes the wrapped function.
6. Audit logging records the verdict and latency.

## Async Path

The same flow applies to async functions. The wrapped coroutine is awaited only after the policy decision is made.

## Context Flow

1. Request or task code sets execution context with `set_execution_context` or `execution_context(...)`.
2. Audit logging resolves the active `agent_id` from `contextvars` when needed.
3. The context is reset cleanly at the end of the scope.

## Resilience Flow

1. `log_audit_event` tries the configured database path.
2. If that fails, it attempts a local SQLite fallback write.
3. If fallback also fails, it logs the issue to stderr and returns `False`.

## CLI and Dashboard Flow

- `aegis init` creates a default guardrails file.
- `aegis check` validates YAML syntax and structure.
- `aegis status` summarizes local audit counts.
- `aegis dashboard` serves the local inspection UI.

## Operational Filters

The dashboard supports filtering audit rows by verdict and agent ID through query parameters.