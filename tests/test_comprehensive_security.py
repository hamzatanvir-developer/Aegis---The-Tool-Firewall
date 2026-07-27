import pytest
from aegis.engine import PolicyEngine

def test_sql_injection_variants():
    engine = PolicyEngine()
    res = engine.evaluate("execute_sql", {"query": "SELECT * FROM users; DROP TABLE users;"})
    assert res.is_allowed is False
    assert res.triggered_rule == "block_destructive_sql"

def test_shell_command_injection():
    engine = PolicyEngine()
    res = engine.evaluate("run_shell", {"command": "rm -rf / --no-preserve-root"})
    assert res.is_allowed is False
    assert res.triggered_rule == "block_destructive_shell"

def test_path_traversal_and_file_upload_attacks():
    engine = PolicyEngine()
    # Test directory traversal sequence injection in file operations / uploads
    res = engine.evaluate("read_file", {"filepath": "../../../etc/shadow"})
    assert res.is_allowed is False
    assert res.triggered_rule == "block_path_traversal"

def test_ssrf_cloud_metadata():
    engine = PolicyEngine()
    res = engine.evaluate("web_search", {"query": "http://169.254.169.254/latest/meta-data/"})
    assert res.is_allowed is False
    assert res.triggered_rule == "block_ssrf_risk"

def test_credential_redaction_pipeline():
    engine = PolicyEngine()
    payload = {
        "api_key": "AKIAIOSFODNN7EXAMPLE",
        "secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    }
    res = engine.evaluate("deploy_service", payload)
    assert res.is_allowed is True
    assert res.sanitized_args["api_key"] == "[REDACTED_AWS_ACCESS_KEY]"

def test_rate_limiting_enforcement():
    engine = PolicyEngine()
    # Spam requests rapidly to trigger rate limiter
    for _ in range(5):
        res = engine.evaluate("safe_tool", {"data": "test"}, context={"agent_id": "test_agent"})
        assert res.is_allowed is True
        
    # The 6th request within the window should be blocked
    res_blocked = engine.evaluate("safe_tool", {"data": "test"}, context={"agent_id": "test_agent"})
    assert res_blocked.is_allowed is False
    assert res_blocked.triggered_rule == "rate_limit_exceeded"

def test_authorization_and_authentication():
    engine = PolicyEngine()
    # Unauthenticated agent attempting to run a privileged shell tool
    res = engine.evaluate("run_shell", {"command": "echo hello"}, context={"is_authenticated": False})
    assert res.is_allowed is False
    assert res.triggered_rule == "unauthorized_tool_access"