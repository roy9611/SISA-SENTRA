"""
Unit tests for the parser service.
"""

from app.services.parser import Parser


class TestParser:
    """Tests for the content parser."""

    def setup_method(self):
        self.parser = Parser()

    def test_parse_text(self):
        result = self.parser.parse("text", "  hello world  ")
        assert result == "hello world"

    def test_parse_sql(self):
        result = self.parser.parse("sql", "SELECT * FROM users")
        assert result == "SELECT * FROM users"

    def test_parse_chat(self):
        result = self.parser.parse("chat", "Hey, how are you?")
        assert result == "Hey, how are you?"

    def test_parse_log(self):
        log = "2024-01-01 INFO Started\n2024-01-01 ERROR Failed"
        result = self.parser.parse("log", log)
        assert "Started" in result
        assert "Failed" in result

    def test_parse_invalid_type(self):
        try:
            self.parser.parse("video", "content")
            assert False, "Should have raised ValueError"
        except ValueError:
            pass

    def test_sanitization(self):
        result = self.parser.parse("text", "clean\x00text")
        assert "\x00" not in result
