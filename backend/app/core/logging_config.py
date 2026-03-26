"""Structured logging configuration for observability."""

import logging
import sys
import uuid
from contextvars import ContextVar

# Context variable for request tracing
request_id_var: ContextVar[str] = ContextVar("request_id", default="no-request")


class RequestFormatter(logging.Formatter):
    """Custom formatter that includes request ID for tracing."""

    def format(self, record: logging.LogRecord) -> str:
        record.request_id = request_id_var.get("no-request")
        return super().format(record)


def setup_logging() -> logging.Logger:
    """Configure and return the application logger."""
    logger = logging.getLogger("kynetic_sentra")
    logger.setLevel(logging.DEBUG)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)

    formatter = RequestFormatter(
        fmt="%(asctime)s | %(levelname)-8s | %(request_id)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)

    if not logger.handlers:
        logger.addHandler(handler)

    return logger


def generate_request_id() -> str:
    """Generate a unique request ID for tracing."""
    return str(uuid.uuid4())[:8]


logger = setup_logging()
