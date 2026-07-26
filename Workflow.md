5. Workflow.md
# Aegis — Workflow

## Delivered User Workflow

1. Install the package in a Python project.
2. Run `aegis init` to generate a baseline `guardrails.yaml`.
3. Validate the policy file with `aegis check`.
4. Decorate tool functions with `@guardrail`.
5. Inspect local audit state with `aegis status` or `aegis dashboard`.

## Runtime Sequence

### Phase 1: Interception

- Capture function arguments.
- Evaluate against policy rules.
- Block destructive payloads.

### Phase 2: Context

- Scope agent and tenant metadata per request or async task.
- Restore context after the request finishes.

### Phase 3: Persistence

- Persist the audit event to the local database.
- Fall back safely if the primary path fails.

### Phase 4: Inspection

- Use the CLI to initialize, validate, and inspect local state.
- Use the dashboard for visual inspection of audit rows and triggered rules.

### Phase 5: Demo and Verification

- Run the end-to-end demo script.
- Run the test suite before release.

## Definition of Done

- All shipped tests pass.
- The CLI and dashboard behave as documented.
- The docs match the current Python implementation.