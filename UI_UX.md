# Aegis — UI / UX

## Dashboard Information Architecture

The shipped dashboard is intentionally small and local.

- Dashboard root
- Summary metrics
- Top triggered rules
- Audit logs table
- Verdict and agent filters

## Layout

- Fixed 240px dark sidebar.
- Responsive main area with a 12-column grid.
- Dark header section with operational status text.
- Dense table layout for audit inspection.

## Visual Treatment

- Allowed status uses green.
- Blocked status uses red.
- Warnings and human-approval style labels use amber.
- Payload text uses a monospace font.

## Interaction Model

- Filter audit rows by verdict.
- Filter audit rows by agent ID.
- Keep the interface readable on smaller screens.

## Notes

The implementation follows the design direction in `Design.md` while remaining a standard-library HTTP application rather than a browser SPA.



