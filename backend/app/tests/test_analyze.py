"""
Integration tests for the /analyze endpoint.
Tests all input types and verifies strict API contract compliance.
"""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


class TestHealthEndpoints:
    """Tests for health and root endpoints."""

    def test_health(self):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"

    def test_root(self):
        resp = client.get("/")
        assert resp.status_code == 200
        data = resp.json()
        assert "name" in data
        assert "endpoints" in data


class TestAnalyzeTextInput:
    """Tests for text input type."""

    def test_simple_text_with_email(self):
        resp = client.post("/analyze", json={
            "input_type": "text",
            "content": "Contact me at admin@example.com for details",
            "options": {"mask": False, "block_high_risk": False}
        })
        assert resp.status_code == 200
        data = resp.json()
        # Verify strict schema
        assert "summary" in data
        assert "content_type" in data
        assert "findings" in data
        assert "risk_score" in data
        assert "risk_level" in data
        assert "action" in data
        assert "insights" in data
        assert data["content_type"] == "text"
        # Verify findings structure
        for finding in data["findings"]:
            assert set(finding.keys()) == {"type", "risk", "line"}

    def test_text_with_api_key(self):
        resp = client.post("/analyze", json={
            "input_type": "text",
            "content": "api_key = sk-1234567890abcdef1234567890",
            "options": {"mask": True, "block_high_risk": True}
        })
        assert resp.status_code == 200
        data = resp.json()
        api_key_findings = [f for f in data["findings"] if f["type"] == "api_key"]
        assert len(api_key_findings) > 0
        assert api_key_findings[0]["risk"] == "high"

    def test_text_with_password(self):
        resp = client.post("/analyze", json={
            "input_type": "text",
            "content": "password=SuperSecret123!",
            "options": {"mask": True, "block_high_risk": True}
        })
        assert resp.status_code == 200
        data = resp.json()
        pwd_findings = [f for f in data["findings"] if f["type"] == "password"]
        assert len(pwd_findings) > 0
        assert pwd_findings[0]["risk"] == "critical"
        assert data["action"] in ("blocked", "masked")

    def test_clean_text(self):
        resp = client.post("/analyze", json={
            "input_type": "text",
            "content": "This is a perfectly clean text with no issues.",
            "options": {}
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_score"] == 0
        assert data["risk_level"] == "low"


class TestAnalyzeLogInput:
    """Tests for log input type."""

    SAMPLE_LOG = """2024-01-15 10:23:01 INFO Server started on port 8080
2024-01-15 10:23:45 ERROR Failed login attempt from 192.168.1.100 user=admin
2024-01-15 10:23:46 ERROR Failed login attempt from 192.168.1.100 user=admin
2024-01-15 10:23:47 ERROR Failed login attempt from 192.168.1.100 user=admin
2024-01-15 10:23:48 ERROR Failed login attempt from 192.168.1.100 user=admin
2024-01-15 10:23:49 ERROR Failed login attempt from 192.168.1.100 user=admin
2024-01-15 10:24:00 WARNING api_key = AKIA1234567890ABCDEF
2024-01-15 10:24:01 DEBUG password=admin123
2024-01-15 10:24:02 ERROR Traceback (most recent call last):
2024-01-15 10:24:03 DEBUG token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature
2024-01-15 10:24:04 INFO Request from user@company.com completed"""

    def test_log_analysis_full(self):
        resp = client.post("/analyze", json={
            "input_type": "log",
            "content": self.SAMPLE_LOG,
            "options": {"mask": True, "block_high_risk": True, "log_analysis": True}
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["content_type"] == "logs"
        assert len(data["findings"]) > 0
        assert data["risk_score"] > 0
        # Should detect brute force (5+ failed logins)
        brute_force = [f for f in data["findings"] if f["type"] == "brute_force"]
        assert len(brute_force) > 0

    def test_log_findings_structure(self):
        resp = client.post("/analyze", json={
            "input_type": "log",
            "content": self.SAMPLE_LOG,
            "options": {}
        })
        data = resp.json()
        for finding in data["findings"]:
            # Strict: only type, risk, line
            assert set(finding.keys()) == {"type", "risk", "line"}
            assert isinstance(finding["type"], str)
            assert isinstance(finding["risk"], str)
            assert isinstance(finding["line"], int)


class TestAnalyzeSQLInput:
    """Tests for SQL input type."""

    def test_sql_injection_detection(self):
        resp = client.post("/analyze", json={
            "input_type": "sql",
            "content": "SELECT * FROM users WHERE id = '1' OR '1'='1'; DROP TABLE users;",
            "options": {"block_high_risk": True}
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["content_type"] == "sql_query"
        sql_findings = [f for f in data["findings"] if f["type"] == "sql_injection"]
        assert len(sql_findings) > 0


class TestAnalyzeChatInput:
    """Tests for chat input type."""

    def test_chat_with_secret(self):
        resp = client.post("/analyze", json={
            "input_type": "chat",
            "content": "Hey, my password=mysecretpass123 can you help?",
            "options": {"mask": True}
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["content_type"] == "chat_message"
        assert len(data["findings"]) > 0


class TestPolicyEngine:
    """Tests for masking and blocking behavior."""

    def test_mask_action(self):
        resp = client.post("/analyze", json={
            "input_type": "text",
            "content": "My email is test@example.com",
            "options": {"mask": True, "block_high_risk": False}
        })
        data = resp.json()
        assert data["action"] == "masked"

    def test_block_action(self):
        resp = client.post("/analyze", json={
            "input_type": "text",
            "content": "password=SuperSecret123",
            "options": {"mask": False, "block_high_risk": True}
        })
        data = resp.json()
        assert data["action"] == "blocked"

    def test_allowed_action(self):
        resp = client.post("/analyze", json={
            "input_type": "text",
            "content": "Hello world, no secrets here at all.",
            "options": {"mask": False, "block_high_risk": False}
        })
        data = resp.json()
        assert data["action"] == "allowed"


class TestValidation:
    """Tests for input validation."""

    def test_invalid_input_type(self):
        resp = client.post("/analyze", json={
            "input_type": "video",
            "content": "test",
            "options": {}
        })
        assert resp.status_code == 422

    def test_empty_content(self):
        resp = client.post("/analyze", json={
            "input_type": "text",
            "content": "",
            "options": {}
        })
        assert resp.status_code == 422
