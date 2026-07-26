# Aegis — Security Model

## Security Goals

Aegis is a local security boundary for Python tool execution. It must remain simple, auditable, and fail-safe.

## Core Guarantees

### Fail closed on evaluation failure

If policy evaluation fails unexpectedly, Aegis blocks execution rather than letting an uninspected tool call proceed.

### Pre-execution interception

Argument inspection occurs before the wrapped function runs. This is the primary security boundary.

### Async-safe and thread-safe context isolation

Tenant and agent context is stored in `contextvars`, so concurrent tasks and threads do not leak state into each other.

### Resilient local audit logging

Audit logging should never crash the host application. If the configured database path fails, Aegis attempts a local fallback write and degrades gracefully to stderr logging if needed.

### Minimal dependency surface

The core runtime uses the Python standard library plus PyYAML for configuration parsing.

## Threats and Mitigations

| Threat | Mitigation |
| --- | --- |
| Destructive SQL or shell commands | Deterministic pattern checks in `PolicyEngine` |
| Secret leakage in tool arguments | Inline redaction before function invocation and audit persistence |
| Context leakage across concurrent requests | `contextvars`-based execution context |
| Audit store outage | Local fallback path and non-fatal logging |

## Operational Notes

- The dashboard is local and inspectable.
- The CLI is intended for project bootstrap, policy validation, status inspection, and dashboard launch.
- The package does not rely on remote evaluation services.

## Disclosure

Report security issues privately rather than through public issues when possible.