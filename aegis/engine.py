"""Policy Engine for inspecting tool parameters and enforcing security guardrails."""

import re
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class EvaluationResult:
    is_allowed: bool
    triggered_rule: Optional[str] = None
    reason: Optional[str] = None
    sanitized_args: Optional[Dict[str, Any]] = None


class PolicyEngine:
    """Evaluates agent tool arguments against security rules."""

    DESTRUCTIVE_SQL = [
        r"\bDROP\s+TABLE\b",
        r"\bTRUNCATE\s+TABLE\b",
        r"\bDELETE\s+FROM\b(?!\s+WHERE\b)",
    ]

    DESTRUCTIVE_SHELL = [
        r"\brm\s+-rf\b",
        r"\bsudo\b",
        r"\bchmod\s+777\b",
        r":\(\)\{\s*:\|:&\s*\};:",
    ]

   # Secret and PII patterns for automatic redaction
    PII_PATTERNS = {
        "aws_access_key": r"AKIA[0-9A-Z]{16,20}",
        "openai_api_key": r"sk-[a-zA-Z0-9]{32,}",
        "bearer_token": r"Bearer\s+[a-zA-Z0-9\-\._~\+\/]+=*",
    }

    def __init__(self, policy_config: Optional[Dict[str, Any]] = None):
        self.config = policy_config or {}

    def evaluate(self, tool_name: str, kwargs: Dict[str, Any]) -> EvaluationResult:
        payload_str = str(kwargs)

        for pattern in self.DESTRUCTIVE_SHELL:
            if re.search(pattern, payload_str, re.IGNORECASE):
                return EvaluationResult(
                    is_allowed=False,
                    triggered_rule="block_destructive_shell",
                    reason=f"Blocked dangerous shell command matching '{pattern}'",
                )

        for pattern in self.DESTRUCTIVE_SQL:
            if re.search(pattern, payload_str, re.IGNORECASE):
                return EvaluationResult(
                    is_allowed=False,
                    triggered_rule="block_destructive_sql",
                    reason=f"Blocked dangerous SQL pattern matching '{pattern}'",
                )

        sanitized_kwargs = self._redact_secrets(kwargs)

        return EvaluationResult(
            is_allowed=True,
            sanitized_args=sanitized_kwargs
        )

    def _redact_secrets(self, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        """Redacts sensitive credentials and keys from tool arguments."""
        sanitized = kwargs.copy()
        for key, val in sanitized.items():
            if isinstance(val, str):
                for secret_type, pattern in self.PII_PATTERNS.items():
                    # Fix: pass sanitized[key] instead of val so subsequent regex replacements chain properly
                    sanitized[key] = re.sub(pattern, f"[REDACTED_{secret_type.upper()}]", sanitized[key])
        return sanitized    