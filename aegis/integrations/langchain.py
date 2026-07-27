"""Aegis Firewall Integration for LangChain Agents."""

import time
import uuid
from typing import Any, Dict, List, Optional
from langchain_core.callbacks import BaseCallbackHandler
from aegis.engine import PolicyEngine, EvaluationResult
from aegis.db import log_audit_event
from aegis.exceptions import PolicyViolationError


class AegisLangChainCallbackHandler(BaseCallbackHandler):
    """Intercepts LangChain tool calls and evaluates them against Aegis security guardrails."""

    def __init__(self, engine: Optional[PolicyEngine] = None, agent_id: str = "langchain_agent"):
        self.engine = engine or PolicyEngine()
        self.agent_id = agent_id

    def on_tool_start(
        self,
        serialized: Dict[str, Any],
        input_str: str,
        *,
        run_id: uuid.UUID,
        parent_run_id: Optional[uuid.UUID] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ) -> Any:
        """Called right before a LangChain tool runs."""
        tool_name = serialized.get("name", "unknown_tool")
        start_time = time.time()
        event_id = str(uuid.uuid4())
        
        # Parse payload arguments
        payload = {"input": input_str, **kwargs}
        context = {"agent_id": self.agent_id, "is_authenticated": True}

        # Evaluate against Aegis Policy Engine
        result: EvaluationResult = self.engine.evaluate(tool_name, payload, context=context)
        latency_ms = (time.time() - start_time) * 1000

        verdict = "ALLOW" if result.is_allowed else "BLOCK"

        # Log audit trail to persistent database
        try:
            log_audit_event(
                event_id=event_id,
                agent_id=self.agent_id,
                tool_name=tool_name,
                payload=str(payload),
                verdict=verdict,
                triggered_rule=result.triggered_rule,
                latency_ms=latency_ms
            )
        except Exception: # nosec B110
            pass # Fallback cleanly if DB fails

        # Enforce firewall block
        if not result.is_allowed:
            raise PolicyViolationError(
                message=f"Aegis Firewall blocked LangChain tool '{tool_name}': rule '{result.triggered_rule}' triggered ({result.reason}).",
                rule_name=result.triggered_rule or "unknown",
                payload=payload,
            )