"""
Content parser service — extracts analyzable text from all input types.
Supports: text, file, sql, chat, log.
"""

from app.core.logging_config import logger
from app.utils.file_handling import decode_base64_content, extract_text_from_file
from app.utils.validators import sanitize_content, validate_content_length


class Parser:
    """Multi-source content parser with validation and sanitization."""

    def parse(self, input_type: str, content: str, file_name: str | None = None) -> str:
        """
        Parse content based on input type.
        Returns cleaned, analyzable text.
        """
        logger.info(f"Parsing input_type={input_type}, content_length={len(content)}")

        # Validate content length
        if not validate_content_length(content):
            raise ValueError(
                "Content exceeds maximum allowed length. "
                "Please reduce the input size."
            )

        from typing import Callable, Dict
        parser_map: Dict[str, Callable[[str], str]] = {
            "text": self._parse_text,
            "file": self._parse_file,
            "sql": self._parse_sql,
            "chat": self._parse_chat,
            "log": self._parse_log,
        }

        parser_fn = parser_map.get(input_type.lower())
        if not parser_fn:
            raise ValueError(f"Unsupported input type: {input_type}")

        if input_type.lower() == "file":
            parsed = self._parse_file(content, file_name)
        else:
            parsed = parser_fn(content)

        sanitized = sanitize_content(parsed)

        logger.info(f"Parsed successfully: {len(sanitized)} characters")
        return sanitized

    def _parse_text(self, content: str) -> str:
        """Parse plain text input."""
        return content.strip()

    def _parse_file(self, content: str, file_name: str | None = None) -> str:
        """
        Parse file input. Expects base64-encoded content.
        Falls back to treating as raw text if base64 decoding fails.
        """
        try:
            # Try base64 decode first (for uploaded files)
            file_bytes = decode_base64_content(content)
            # Attempt to detect file type from content
            # For simplicity, try UTF-8 text first, then PDF/DOCX
            try:
                text = file_bytes.decode("utf-8")
                return text.strip()
            except UnicodeDecodeError:
                # Use actual filename to let extract_text_from_file dictate parser
                safe_name = file_name if file_name else "uploaded.pdf"
                return extract_text_from_file(file_bytes, safe_name)
        except ValueError:
            # Not base64 — treat as raw text content
            logger.info("File content not base64-encoded, treating as raw text")
            return content.strip()

    def _parse_sql(self, content: str) -> str:
        """Parse SQL/structured data input."""
        return self._try_base64_decode(content)

    def _parse_chat(self, content: str) -> str:
        """Parse chat message input."""
        return content.strip()

    def _parse_log(self, content: str) -> str:
        """Parse log input — preserves line structure for line-by-line analysis."""
        return self._try_base64_decode(content)

    def _try_base64_decode(self, content: str) -> str:
        """Helper to decode base64 if detected, else return as is."""
        try:
            # Check for data URL header if sent from frontend
            # Only split if it looks like a real Data URL (e.g. data:text/plain;base64,...)
            if content.startswith("data:") and ";base64," in content:
                content = content.split(";base64,")[1]
            
            decoded = decode_base64_content(content)
            try:
                return decoded.decode("utf-8").strip()
            except UnicodeDecodeError:
                # If binary, it's probably better handled in _parse_file, 
                # but we'll try to return it or at least not crash
                return content.strip()
        except Exception:
            # Not base64
            return content.strip()
