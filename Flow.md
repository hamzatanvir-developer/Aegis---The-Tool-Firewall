4. Flow.md
Primary End-to-End User Flow: Interception Pipeline
[Agent Invokes Tool Call]
          │
          ▼
[AgentGuard SDK Intercepts Arguments]
          │
          ├────────► [Stage 1: Input Normalization & Decoders]
          │                │
          │                ▼
          ├────────► [Stage 2: PII / Secret Redaction Check]
          │                │
          │                ▼
          ├────────► [Stage 3: AST / Policy Rule Evaluation]
          │                │
          │                ├───► (Violation Detected?)
          │                │          │
          │                │          ├─── YES ───► [Action: BLOCK]
          │                │          │                 │
          │                │          │                 ├──► Log Event to Audit Store
          │                │          │                 └──► Raise GuardrailException
          │                │          │
          │                │          └─── NO ────► [Action: ALLOW]
          │                │                            │
          │                │                            ├──► Execute Tool Call
          │                │                            └──► Async Log Event
Edge Cases & Retry Behaviors
Policy Store Unavailable:

Behavior: Fall back to local embedded cached copy of guardrail.yaml. If cache is missing, apply global fallback policy (Fail-Closed for production environments, Fail-Open with Warning for development).

Infinite Agent Loop Detected:

Behavior: If the same agent attempts the same tool call with identical arguments > 5 times in 10 seconds, trigger a rate-limit exception and terminate the execution context.