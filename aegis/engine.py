"""Policy Engine for Aegis with Multi-Turn Tracking, Rate Limiting, and MCP Governance."""

import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, List


@dataclass
class EvaluationResult:
    is_allowed: bool
    verdict: str = "ALLOW"  # "ALLOW", "BLOCK", or "REQUIRE_APPROVAL"
    triggered_rule: Optional[str] = None
    reason: Optional[str] = None
    sanitized_args: Optional[Dict[str, Any]] = None


class PolicyEngine:
    """Enterprise-grade policy engine solving context drift, shadow tools, and latency."""

    DESTRUCTIVE_SQL = [
        r"\bDROP\s+TABLE\b",
        r"\bTRUNCATE\s+TABLE\b",
        r"\bDELETE\s+FROM\b(?!\s+WHERE\b)",
        r"'\s*OR\s*'?[0-9a-zA-Z]+'?\s*=\s*'?",
        r"--",
    ]

    DESTRUCTIVE_SHELL = [
        r"\brm\s+-rf\b",
        r"\bsudo\b",
        r"\bchmod\s+777\b",
        r":\(\)\{\s*:\|:&\s*\};:",
    ]

    PATH_TRAVERSAL = [
        r"\.\.[\\\/]",
        r"\/etc\/passwd",
        r"\/etc\/shadow",
        r"C:\\Windows\\System32",
    ]

    SSRF_BLOCKLIST = [
        r"169\.254\.169\.254",
        r"127\.0\.0\.1",
        r"localhost",
        r"0\.0\.0\.0",
    ]

    PII_PATTERNS = {
        "aws_access_key": r"AKIA[0-9A-Z]{16,20}",
        "openai_api_key": r"sk-[a-zA-Z0-9]{32,}",
        "bearer_token": r"Bearer\s+[a-zA-Z0-9\-\._~\+\/]+=*",
    }

    def __init__(self, policy_config: Optional[Dict[str, Any]] = None):
        self.config = policy_config or {}
        self.request_timestamps: Dict[str, List[float]] = {}
        self.session_histories: Dict[str, List[str]] = {}
        self.registered_tools: set = {
            "read_file",
            "run_shell",
            "execute_sql",
            "deploy_service",
            "web_search",
            "safe_tool",
            "execute_query",
            "db_query",
            "deploy_cloud",
            "execute_shell",
            "db_write",
        }
        self.rate_limit_max = 5
        self.rate_limit_window = 10.0

    def register_tool(self, tool_name: str):
        self.registered_tools.add(tool_name)

    def evaluate(
        self,
        tool_name: str,
        kwargs: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None,
    ) -> EvaluationResult:
        context = context or {}
        agent_id = context.get("agent_id", "default_agent")

        # 0. Shadow Tool / MCP Sprawl Check
        if tool_name not in self.registered_tools:
            return EvaluationResult(
                is_allowed=False,
                verdict="BLOCK",
                triggered_rule="unregistered_mcp_tool",
                reason=f"Blocked unmanaged shadow tool or MCP endpoint '{tool_name}'",
                sanitized_args=kwargs,
            )

        # 1. Rate Limiting Check
        if self._is_rate_limited(agent_id):
            return EvaluationResult(
                is_allowed=False,
                verdict="BLOCK",
                triggered_rule="rate_limit_exceeded",
                reason=f"Rate limit exceeded for agent '{agent_id}'",
                sanitized_args=kwargs,
            )

        # 2. Multi-Turn Intent Drift Check
        self._track_session_history(agent_id, tool_name)
        if self._detect_intent_drift(agent_id):
            return EvaluationResult(
                is_allowed=False,
                verdict="BLOCK",
                triggered_rule="block_intent_drift",
                reason="Blocked due to suspicious multi-turn privilege escalation sequence",
                sanitized_args=kwargs,
            )

        # 3. Authorization Check
        if context.get("is_authenticated") is False:
            return EvaluationResult(
                is_allowed=False,
                verdict="BLOCK",
                triggered_rule="unauthorized_tool_access",
                reason=f"Unauthenticated agent access to tool '{tool_name}'",
                sanitized_args=kwargs,
            )

        payload_str = str(kwargs)

        # 4. Deterministic Vector Checks (Zero-Latency Regex) - MUST come before approval
        for pattern in self.DESTRUCTIVE_SHELL:
            if re.search(pattern, payload_str, re.IGNORECASE):
                return EvaluationResult(is_allowed=False, verdict="BLOCK", triggered_rule="block_destructive_shell", reason=f"Shell injection matched '{pattern}'", sanitized_args=kwargs)

        for pattern in self.DESTRUCTIVE_SQL:
            if re.search(pattern, payload_str, re.IGNORECASE):
                return EvaluationResult(is_allowed=False, verdict="BLOCK", triggered_rule="block_destructive_sql", reason=f"SQL pattern matched '{pattern}'", sanitized_args=kwargs)

        for pattern in self.PATH_TRAVERSAL:
            if re.search(pattern, payload_str, re.IGNORECASE):
                return EvaluationResult(is_allowed=False, verdict="BLOCK", triggered_rule="block_path_traversal", reason=f"Traversal pattern matched '{pattern}'", sanitized_args=kwargs)

        for pattern in self.SSRF_BLOCKLIST:
            if re.search(pattern, payload_str, re.IGNORECASE):
                return EvaluationResult(is_allowed=False, verdict="BLOCK", triggered_rule="block_ssrf_risk", reason=f"SSRF target matched '{pattern}'", sanitized_args=kwargs)

        # 5. Human Approval Interception Triggers
        if tool_name in ["execute_shell", "run_shell"]:
            return EvaluationResult(
                is_allowed=False,
                verdict="REQUIRE_APPROVAL",
                triggered_rule="require_approval_for_shell",
                reason="High-risk execution requires human-in-the-loop verification sign-off.",
                sanitized_args=kwargs,
            )

        # 6. Secret Redaction Pipeline & Allow
        sanitized_kwargs = self._redact_secrets(kwargs)

        return EvaluationResult(
            is_allowed=True,
            verdict="ALLOW",
            sanitized_args=sanitized_kwargs,
        )

    def _is_rate_limited(self, agent_id: str) -> bool:
        current_time = time.time()
        
        # Periodic cleanup of old keys to prevent memory leaks (DoS mitigation)
        if len(self.request_timestamps) > 10000:
            stale_keys = [k for k, v in self.request_timestamps.items() if not v or current_time - v[-1] > 60]
            for k in stale_keys:
                self.request_timestamps.pop(k, None)

        timestamps = self.request_timestamps.get(agent_id, [])
        valid_timestamps = [t for t in timestamps if current_time - t < self.rate_limit_window]
        if len(valid_timestamps) >= self.rate_limit_max:
            return True
        valid_timestamps.append(current_time)
        self.request_timestamps[agent_id] = valid_timestamps
        return False

    def _track_session_history(self, agent_id: str, tool_name: str):
        if agent_id not in self.session_histories:
            self.session_histories[agent_id] = []
        history = self.session_histories[agent_id]
        history.append(tool_name)
        if len(history) > 10:
            history.pop(0)

    def _detect_intent_drift(self, agent_id: str) -> bool:
        history = self.session_histories.get(agent_id, [])
        if len(history) >= 2 and history[-2] == "read_file" and history[-1] == "run_shell":
            return True
        return False

    def _redact_secrets(self, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        sanitized = kwargs.copy()
        for key, val in sanitized.items():
            if isinstance(val, str):
                for secret_type, pattern in self.PII_PATTERNS.items():
                    sanitized[key] = re.sub(pattern, f"[REDACTED_{secret_type.upper()}]", sanitized[key])
        return sanitized


_ENGINE = PolicyEngine()


def evaluate_tool_call(tool_name: str, kwargs: Dict[str, Any]) -> tuple[str, Optional[str]]:
    result = _ENGINE.evaluate(tool_name, kwargs)
    return result.verdict, result.triggered_rule


class ToolFirewall:
    def guard(self, tool_name: str, agent_id: str = "default_agent"):
        from aegis.core import guard
        return guard(tool_name=tool_name, agent_id=agent_id)