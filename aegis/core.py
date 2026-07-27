import functools
import asyncio
from typing import Callable, Any
from aegis.engine import evaluate_tool_call
from aegis.db import log_audit_event
from aegis.exceptions import PolicyViolationError
import time
import uuid

def guard(tool_name: str, agent_id: str = "default_agent"):
    """
    Enterprise guard decorator supporting both synchronous and asynchronous agent tools.
    """
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        if asyncio.iscoroutinefunction(func):
            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                start_time = time.time()
                event_id = str(uuid.uuid4())
                payload = {"args": args, "kwargs": kwargs}
                
                # Evaluate policy engine
                verdict, triggered_rule = evaluate_tool_call(tool_name, payload)
                latency_ms = (time.time() - start_time) * 1000
                
                # Log audit event
                log_audit_event(
                    event_id=event_id,
                    tool_name=tool_name,
                    payload=str(payload),
                    verdict=verdict,
                    latency_ms=latency_ms,
                    triggered_rule=triggered_rule,
                    agent_id=agent_id
                )
                
                if verdict == "BLOCK":
                    raise PolicyViolationError(
                        message=f"Aegis Firewall blocked tool '{tool_name}': rule '{triggered_rule}' triggered.",
                        rule_name=triggered_rule or "unknown",
                        payload=payload,
                    )
                
                return await func(*args, **kwargs)
            return async_wrapper
        else:
            @functools.wraps(func)
            def sync_wrapper(*args, **kwargs):
                start_time = time.time()
                event_id = str(uuid.uuid4())
                payload = {"args": args, "kwargs": kwargs}
                
                # Evaluate policy engine
                verdict, triggered_rule = evaluate_tool_call(tool_name, payload)
                latency_ms = (time.time() - start_time) * 1000
                
                # Log audit event
                log_audit_event(
                    event_id=event_id,
                    tool_name=tool_name,
                    payload=str(payload),
                    verdict=verdict,
                    latency_ms=latency_ms,
                    triggered_rule=triggered_rule,
                    agent_id=agent_id
                )
                
                if verdict == "BLOCK":
                    raise PolicyViolationError(
                        message=f"Aegis Firewall blocked tool '{tool_name}': rule '{triggered_rule}' triggered.",
                        rule_name=triggered_rule or "unknown",
                        payload=payload,
                    )
                
                return func(*args, **kwargs)
            return sync_wrapper
    return decorator

def guardrail(
    func: Callable[..., Any] | None = None,
    *,
    tool_name: str | None = None,
    agent_id: str = "default_agent",
):
    """Decorator entry point compatible with direct use or legacy factory-style use.

    - `@guardrail` uses the wrapped function name as the tool name.
    - `@guardrail(tool_name="...")` or `guardrail(tool_name="...")` also work.
    """

    if func is not None and callable(func):
        return guard(tool_name or func.__name__, agent_id=agent_id)(func)

    def decorator(inner_func: Callable[..., Any]) -> Callable[..., Any]:
        return guard(tool_name or inner_func.__name__, agent_id=agent_id)(inner_func)

    return decorator