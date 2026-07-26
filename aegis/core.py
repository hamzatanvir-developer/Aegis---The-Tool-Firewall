"""Decorator interface for intercepting Python tool execution."""

import asyncio
import functools
import inspect
import time
import uuid
from typing import Any, Awaitable, Callable, TypeVar, overload

from aegis.engine import PolicyEngine
from aegis.db import log_audit_event
from aegis.exceptions import PolicyViolationError

_ENGINE = PolicyEngine()

R = TypeVar("R")


def _build_payload(func: Callable[..., Any], args: tuple[Any, ...], kwargs: dict[str, Any]) -> dict[str, Any]:
    signature = inspect.signature(func)
    bound_arguments = signature.bind_partial(*args, **kwargs)
    return dict(bound_arguments.arguments)


def _raise_policy_violation(result: Any, payload: dict[str, Any]) -> None:
    raise PolicyViolationError(
        message=f"[{result.triggered_rule}] {result.reason}",
        rule_name=result.triggered_rule or "unknown",
        payload=payload,
    )


def _log_audit_event(
    *,
    event_id: str,
    tool_name: str,
    payload: dict[str, Any],
    verdict: str,
    triggered_rule: str | None,
    latency_ms: float,
) -> None:
    log_audit_event(
        event_id=event_id,
        agent_id="unknown",
        tool_name=tool_name,
        payload=str(payload),
        verdict=verdict,
        triggered_rule=triggered_rule,
        latency_ms=latency_ms,
    )


@overload
def guardrail(func: Callable[..., Awaitable[R]]) -> Callable[..., Awaitable[R]]:
    ...


@overload
def guardrail(func: Callable[..., R]) -> Callable[..., R]:
    ...

def guardrail(func: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator to enforce security policies before tool execution."""
    signature = inspect.signature(func)
    is_async = inspect.iscoroutinefunction(func) or asyncio.iscoroutinefunction(func)

    if is_async:

        @functools.wraps(func)
        async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
            payload = _build_payload(func, args, kwargs)
            start_time = time.perf_counter()
            result = await asyncio.to_thread(_ENGINE.evaluate, func.__name__, payload)
            verdict = "ALLOW" if result.is_allowed else "BLOCK"
            latency_ms = round((time.perf_counter() - start_time) * 1000, 3)

            await asyncio.to_thread(
                _log_audit_event,
                event_id=str(uuid.uuid4()),
                tool_name=func.__name__,
                payload=result.sanitized_args or payload,
                verdict=verdict,
                triggered_rule=result.triggered_rule,
                latency_ms=latency_ms,
            )

            if not result.is_allowed:
                _raise_policy_violation(result, payload)

            if result.sanitized_args:
                bound_arguments = signature.bind_partial(*args, **kwargs)
                bound_arguments.arguments.update(result.sanitized_args)
                return await func(*bound_arguments.args, **bound_arguments.kwargs)

            return await func(*args, **kwargs)

        return async_wrapper

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        payload = _build_payload(func, args, kwargs)
        start_time = time.perf_counter()
        result = _ENGINE.evaluate(func.__name__, payload)
        verdict = "ALLOW" if result.is_allowed else "BLOCK"
        latency_ms = round((time.perf_counter() - start_time) * 1000, 3)

        _log_audit_event(
            event_id=str(uuid.uuid4()),
            tool_name=func.__name__,
            payload=result.sanitized_args or payload,
            verdict=verdict,
            triggered_rule=result.triggered_rule,
            latency_ms=latency_ms,
        )

        if not result.is_allowed:
            _raise_policy_violation(result, payload)

        if result.sanitized_args:
            bound_arguments = signature.bind_partial(*args, **kwargs)
            bound_arguments.arguments.update(result.sanitized_args)
            return func(*bound_arguments.args, **bound_arguments.kwargs)

        return func(*args, **kwargs)

    return wrapper