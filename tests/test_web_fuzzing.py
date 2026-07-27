import threading
import time
import pytest
import requests
from aegis import dashboard
from aegis.dashboard import DB_FILE

@pytest.fixture(scope="module", autouse=True)
def web_server_fixture():
    server = dashboard.create_dashboard_server(host="127.0.0.1", port=8002, db_path=DB_FILE)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.5)
    yield
    server.shutdown()
    server.server_close()

def test_security_headers_enforced():
    """Verify standard security and anti-clickjacking headers are present on all responses."""
    response = requests.get("http://127.0.0.1:8002/", timeout=5)
    assert response.status_code == 200
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"

def test_api_endpoint_fuzzing_malformed_inputs():
    """Fuzz API parameters with bad types and malicious scripts to ensure proper error handling."""
    fuzz_payloads = [
        {"rowid": "not_an_integer", "action": "ALLOW"},
        {"rowid": "-1", "action": "<script>alert(1)</script>"},
        {"rowid": "999999", "action": "DROP TABLE audit_logs;"}
    ]
    for params in fuzz_payloads:
        response = requests.get("http://127.0.0.1:8002/api/approve", params=params, timeout=5)
        # Server must handle gracefully (200 JSON failure or 400/404 client error), never crash with 500
        assert response.status_code in [200, 400, 404]
        if response.status_code == 200:
            data = response.json()
            assert data.get("success") is False

def test_path_traversal_web_fuzzing():
    """Attempt path traversal attacks against static resource or log routes."""
    traversal_paths = [
        "../../../../etc/passwd",
        "..\\..\\..\\Windows\\win.ini"
    ]
    for path in traversal_paths:
        # Target the static asset route to properly test path traversal defense
        response = requests.get(f"http://127.0.0.1:8002/static/{path}", timeout=5)
        assert response.status_code in [400, 404, 403]