"""Custom exceptions for Aegis runtime guardrails."""

class AegisError(Exception):
    """Base exception class for Aegis."""
    pass


class PolicyViolationError(AegisError):
    """Raised when an agent tool call violates a security rule."""

    def __init__(self, message: str, rule_name: str, payload: dict):
        super().__init__(message)
        self.rule_name = rule_name
        self.payload = payload


class ConfigurationError(AegisError):
    """Raised when guardrail configurations are missing or invalid."""
    pass