"""File handling utilities with security-first design."""

import base64
from pathlib import Path

from app.core.config import settings
from app.core.logging_config import logger


def validate_file_extension(filename: str) -> bool:
    """Check if the file extension is allowed."""
    ext = Path(filename).suffix.lower()
    return ext in settings.ALLOWED_FILE_EXTENSIONS


def validate_file_size(content_b64: str) -> bool:
    """Check if the decoded file size is within limits."""
    try:
        decoded = base64.b64decode(content_b64)
        size_mb = len(decoded) / (1024 * 1024)
        return size_mb <= settings.MAX_FILE_SIZE_MB
    except Exception:
        return False


def decode_base64_content(content_b64: str) -> bytes:
    """Safely decode base64-encoded file content."""
    try:
        return base64.b64decode(content_b64)
    except Exception as e:
        logger.error(f"Base64 decode error: {e}")
        raise ValueError("Invalid base64-encoded content")


def extract_text_from_pdf(file_bytes: bytes) -> str:
    """Extract text content from a PDF file."""
    try:
        import io
        from PyPDF2 import PdfReader

        reader = PdfReader(io.BytesIO(file_bytes))
        text_parts = []
        for page in reader.pages:
            page_text = page.extract_text()
            if page_text:
                text_parts.append(page_text)
        return "\n".join(text_parts)
    except Exception as e:
        logger.error(f"PDF extraction error: {e}")
        return f"[PDF extraction failed: {str(e)}]"


def extract_text_from_docx(file_bytes: bytes) -> str:
    """Extract text content from a DOCX file."""
    try:
        import io
        from docx import Document

        doc = Document(io.BytesIO(file_bytes))
        return "\n".join(para.text for para in doc.paragraphs if para.text)
    except Exception as e:
        logger.error(f"DOCX extraction error: {e}")
        return f"[DOCX extraction failed: {str(e)}]"


def extract_text_from_file(file_bytes: bytes, filename: str) -> str:
    """Route file extraction based on extension."""
    ext = Path(filename).suffix.lower()

    if ext in (".txt", ".log"):
        try:
            return file_bytes.decode("utf-8", errors="replace")
        except Exception:
            return file_bytes.decode("latin-1", errors="replace")
    elif ext == ".pdf":
        return extract_text_from_pdf(file_bytes)
    elif ext in (".doc", ".docx"):
        return extract_text_from_docx(file_bytes)
    else:
        raise ValueError(f"Unsupported file type: {ext}")
