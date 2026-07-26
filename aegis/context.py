"""Execution context helpers for tenant-isolated audit logging."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass
from typing import Iterator, Optional


@dataclass(frozen=True)
class ExecutionContext:
    """Active execution context for an agent request."""

    agent_id: str = "default_agent"
    org_id: Optional[str] = None
    api_key_hash: Optional[str] = None


@dataclass(frozen=True)
class ExecutionContextTokens:
    """ContextVar tokens used to restore a previous execution context."""

    agent_id: Token[Optional[str]]
    org_id: Token[Optional[str]]
    api_key_hash: Token[Optional[str]]


_agent_id_var: ContextVar[Optional[str]] = ContextVar("aegis_agent_id", default=None)
_org_id_var: ContextVar[Optional[str]] = ContextVar("aegis_org_id", default=None)
_api_key_hash_var: ContextVar[Optional[str]] = ContextVar("aegis_api_key_hash", default=None)


def get_execution_context() -> ExecutionContext:
    """Return the active execution context for the current task or thread."""

    agent_id = _agent_id_var.get() or "default_agent"
    return ExecutionContext(
        agent_id=agent_id,
        org_id=_org_id_var.get(),
        api_key_hash=_api_key_hash_var.get(),
    )


def set_execution_context(
    agent_id: str,
    org_id: Optional[str] = None,
    api_key_hash: Optional[str] = None,
) -> ExecutionContextTokens:
    """Set the active execution context and return tokens for restoration."""

    return ExecutionContextTokens(
        agent_id=_agent_id_var.set(agent_id),
        org_id=_org_id_var.set(org_id),
        api_key_hash=_api_key_hash_var.set(api_key_hash),
    )


def reset_execution_context(tokens: ExecutionContextTokens) -> None:
    """Restore the execution context that was active before set_execution_context."""

    _api_key_hash_var.reset(tokens.api_key_hash)
    _org_id_var.reset(tokens.org_id)
    _agent_id_var.reset(tokens.agent_id)


@contextmanager
def execution_context(
    agent_id: str,
    org_id: Optional[str] = None,
    api_key_hash: Optional[str] = None,
) -> Iterator[ExecutionContext]:
    """Context manager for per-request execution context."""

    tokens = set_execution_context(agent_id=agent_id, org_id=org_id, api_key_hash=api_key_hash)
    try:
        yield get_execution_context()
    finally:
        reset_execution_context(tokens)