"""Input validation and sanitization utilities."""

import re

from app.core.config import settings
from app.core.logging_config import logger


def sanitize_content(content: str) -> str:
    """
    Sanitize input content to prevent processing issues.
    Removes null bytes and control characters (except newlines/tabs).
    """
    # Remove null bytes
    sanitized = content.replace("\x00", "")
    # Remove other control characters except \n, \r, \t
    sanitized = re.sub(r"[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]", "", sanitized)
    return sanitized


def validate_content_length(content: str) -> bool:
    """Check content is within the maximum allowed length."""
    return len(content) <= settings.MAX_CONTENT_LENGTH


def validate_input_type(input_type: str) -> bool:
    """Validate the input type is one of the supported types."""
    return input_type.lower() in {"text", "file", "sql", "chat", "log"}


def detect_content_type(input_type: str, content: str) -> str:
    """
    Determine the content_type for the response based on input.
    Maps input_type to a human-readable content type string.
    """
    type_map = {
        "text": "text",
        "file": "document",
        "sql": "sql_query",
        "chat": "chat_message",
        "log": "logs",
    }
    return type_map.get(input_type.lower(), "text")


def is_potentially_malicious(content: str) -> list[str]:
    """
    Check for injection-like patterns in content.
    Returns a list of detected suspicious patterns.
    """
    warnings = []

    # Check for script injection
    if re.search(r"<script[^>]*>", content, re.IGNORECASE):
        warnings.append("Potential XSS script injection detected")

    # Check for SQL injection attempts
    if re.search(
        r"(?:'\s*(?:OR|AND)\s+['\d]|;\s*DROP\s+TABLE|UNION\s+SELECT)",
        content,
        re.IGNORECASE,
    ):
        warnings.append("Potential SQL injection pattern detected")

    # Check for command injection
    if re.search(r"(?:;\s*(?:rm|cat|wget|curl)\s|`[^`]+`|\$\([^)]+\))", content):
        warnings.append("Potential command injection detected")

    if warnings:
        logger.warning(f"Malicious pattern warnings: {warnings}")

    return warnings
