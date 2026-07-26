"""Decorator interface for intercepting Python tool execution."""

import functools
from typing import Callable
from aegis.engine import PolicyEngine
from aegis.exceptions import PolicyViolationError

_ENGINE = PolicyEngine()

def guardrail(func: Callable):
    """Decorator to enforce security policies before tool execution."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        res = _ENGINE.evaluate(func.__name__, kwargs)
        if not res.is_allowed:
            raise PolicyViolationError(
                message=f"[{res.triggered_rule}] {res.reason}",
                rule_name=res.triggered_rule or "unknown",
                payload=kwargs
            )
        if res.sanitized_args:
            kwargs.update(res.sanitized_args)
        return func(*args, **kwargs)
    return wrapper