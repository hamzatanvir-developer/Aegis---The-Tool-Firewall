3. Design.md
High-Fidelity Design Principles
AgentGuard's visual identity reflects precision, clarity, and control. Inspired by premium security and developer platforms like Vercel, Linear, and CrowdStrike.
Dark-Mode First: Deep slate backgrounds (#09090B) reduce eye fatigue for security operators monitoring live streams.
High Contrast Status Signals:
Emerald Green (#10B981): Action Allowed / Safe.
Rose Red (#F43F5E): Action Blocked / Violation Prevented.
Amber Yellow (#F59E0B): Warning / Human Approval Required.
Cyan Blue (#06B6D4): Agent Activity / Active Session.
Color Palette & Typography
CSS
:root {
  --bg-primary: #09090b;       /* Zinc 950 */
  --bg-secondary: #18181b;     /* Zinc 900 */
  --border-color: #27272a;     /* Zinc 800 */
  --text-primary: #f4f4f5;     /* Zinc 100 */
  --text-muted: #a1a1aa;       /* Zinc 400 */
  
  --accent-emerald: #10b981;  /* Success / Allowed */
  --accent-rose: #f43f5e;     /* Blocked / Threat */
  --accent-amber: #f59e0b;    /* Warning */
  --accent-cyan: #06b6d4;     /* Info / Action */
}

Typography:
Primary UI Font: Inter, -apple-system, sans-serif.
Code & Log Font: JetBrains Mono, Fira Code, monospace.
UI Components
1. Live Interception Stream Widget
Displays a real-time, scrolling feed of intercepted agent calls with syntax-highlighted JSON inputs, policy match tags, and response latencies.
2. Policy Rule Builder (Visual + YAML Mode)
Toggleable interface allowing security leads to either visually drag-and-drop rule blocks or directly edit guardrails.yaml with real-time linting.



