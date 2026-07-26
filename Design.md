# Aegis — Design Specification

## Product Direction

Aegis is a compact Python security layer for AI tool calls. The product is optimized for clarity, low friction, and deterministic behavior rather than broad control-plane scope.

## Visual Language

- Dark-mode first with deep slate surfaces.
- High-contrast verdict colors for fast security scanning.
- Minimal chrome, dense operational data, and monospace payload rendering.
- Fixed sidebar navigation and responsive main content.

## Core UI Surfaces

### 1. Local Inspection Dashboard

The dashboard is served by the built-in HTTP server in `aegis/dashboard.py`. It renders:

- total invocations,
- allowed count,
- blocked count,
- top triggered rules,
- a responsive audit log table,
- verdict and agent filters.

### 2. Policy File Validation

The CLI validates `guardrails.yaml` structure and syntax before a project uses it. This keeps policy setup simple and local.

### 3. Runtime Interception

`@guardrail` intercepts Python function calls before execution, preserving the host application’s control over the tool surface.

## Interaction Principles

- Show only the data required to understand enforcement and audit status.
- Keep filters obvious and reversible.
- Make allow/block status immediately scannable.
- Treat payload and rule data as operational records, not marketing visuals.

## Layout Notes

- Sidebar width: 240px.
- Main content: responsive 12-column grid.
- Status chips use green for ALLOW, red for BLOCK, and amber for warning states.
- Payload text uses a monospace font for readability.

## Design Constraints

- No dependency on a browser SPA framework for the shipped dashboard.
- No enterprise fleet map, agent registry, or external control-plane assumptions.
- Keep the dashboard local and inspectable.



