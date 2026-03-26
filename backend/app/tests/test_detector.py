"""
Unit tests for the detector service.
"""

from app.services.detector import Detector


class TestDetector:
    """Tests for the deterministic detector."""

    def setup_method(self):
        self.detector = Detector()

    def test_detect_email(self):
        findings = self.detector.detect("contact us at test@example.com")
        types = [f.type for f in findings]
        assert "email" in types

    def test_detect_api_key(self):
        findings = self.detector.detect("api_key = sk-abcdefghijklmnopqrstuvwx")
        types = [f.type for f in findings]
        assert "api_key" in types

    def test_detect_password(self):
        findings = self.detector.detect("password=MySecret123")
        types = [f.type for f in findings]
        assert "password" in types

    def test_detect_token(self):
        findings = self.detector.detect(
            "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sig"
        )
        types = [f.type for f in findings]
        assert "token" in types

    def test_detect_stack_trace(self):
        content = "Traceback (most recent call last):\n  File 'test.py', line 1"
        findings = self.detector.detect(content)
        types = [f.type for f in findings]
        assert "stack_trace" in types

    def test_clean_content(self):
        findings = self.detector.detect("Hello world, nothing to see here.")
        assert len(findings) == 0

    def test_line_numbers(self):
        content = "line one\npassword=secret123\nline three"
        findings = self.detector.detect(content)
        pwd_findings = [f for f in findings if f.type == "password"]
        assert len(pwd_findings) == 1
        assert pwd_findings[0].line == 2

    def test_multiple_findings_same_line(self):
        content = "api_key=sk-abc123456789012345 password=test123"
        findings = self.detector.detect(content)
        assert len(findings) >= 2

    def test_risk_mapping(self):
        findings = self.detector.detect("password=secret")
        pwd = [f for f in findings if f.type == "password"]
        assert pwd[0].risk == "critical"

        findings = self.detector.detect("api_key=sk-12345678901234567890")
        keys = [f for f in findings if f.type == "api_key"]
        assert keys[0].risk == "high"
