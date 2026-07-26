# Aegis Tool Firewall

Aegis is a lightweight security firewall for AI agent tool calls. It intercepts tool execution at the function boundary, blocks destructive actions, redacts sensitive payloads, persists audit trails, supports async tool functions, tracks tenant context safely, and degrades gracefully when audit storage fails.

## Installation

```bash
pip install -e .
```

For development and tests:

```bash
pip install -e .[dev]
```

## Quickstart

```python
from aegis.core import guardrail
from aegis.exceptions import PolicyViolationError

@guardrail
def execute_query(query: str) -> str:
    return f"Executing: {query}"

print(execute_query(query="SELECT * FROM users WHERE id = 1;"))

try:
    execute_query(query="DROP TABLE users;")
except PolicyViolationError as exc:
    print(f"Blocked by Aegis: {exc}")
```

## CLI

Initialize a default policy file:

```bash
aegis init
```

Validate a policy file:

```bash
aegis check guardrails.yaml
```

Show local audit status:

```bash
aegis status --db aegis_audit.db
```

Launch the inspection dashboard:

```bash
aegis dashboard --port 8000 --db aegis_audit.db
```

## Architecture Overview

1. `aegis/core.py` intercepts sync or async tool calls with `@guardrail`.
2. `aegis/engine.py` evaluates payloads against destructive-command and redaction policies.
3. `aegis/context.py` maintains task-safe and thread-safe execution context.
4. `aegis/db.py` persists audit events and falls back safely if the primary store fails.
5. `aegis/cli.py` exposes `init`, `check`, `status`, and `dashboard` entry points.
6. `aegis/dashboard.py` serves a local inspection UI for audit logs, top rules, and filters.

The dashboard follows the design direction in `Design.md` and `UI_UX.md`: dark-mode first, high-contrast verdict colors, a fixed sidebar, summary metrics, and a responsive audit table.

## Demo Pipeline

Run the end-to-end demo:

```bash
python examples/demo_full_pipeline.py
```

The demo shows async guardrail enforcement, multi-tenant context isolation, resilient audit logging with fallback, and quick audit log readback.