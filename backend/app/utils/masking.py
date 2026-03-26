"""Content masking and redaction utilities."""

import re

from app.utils.patterns import SENSITIVE_PATTERNS


def mask_value(value: str, visible_chars: int = 4) -> str:
    """Mask a sensitive value, keeping only the last few characters visible."""
    if len(value) <= visible_chars:
        return "*" * len(value)
    return "*" * (len(value) - visible_chars) + value[-visible_chars:]


def mask_content(content: str) -> str:
    """
    Redact all detected sensitive data in the content.
    Replaces matches with masked versions.
    """
    masked = content

    for pattern_name, pattern in SENSITIVE_PATTERNS.items():
        def _replacer(match: re.Match) -> str:
            original = match.group(0)
            # For key=value patterns, mask only the value part
            if "=" in original or ":" in original:
                sep = "=" if "=" in original else ":"
                parts = original.split(sep, 1)
                if len(parts) == 2:
                    key_part = parts[0] + sep
                    val_part = parts[1].strip().strip("'\"")
                    return key_part + " " + mask_value(val_part)
            return mask_value(original)

        masked = pattern.sub(_replacer, masked)

    return masked


def redact_line(line: str, finding_types: list[str]) -> str:
    """Redact a specific line based on the types of findings detected."""
    redacted = line
    for ftype in finding_types:
        pattern = SENSITIVE_PATTERNS.get(ftype)
        if pattern:
            redacted = pattern.sub("[REDACTED]", redacted)
    return redacted
