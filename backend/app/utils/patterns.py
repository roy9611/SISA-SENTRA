"""
Compiled regex patterns for deterministic sensitive data detection.
All detection is pattern-based — no AI dependency for security-critical detections.
"""

import re

# ── Sensitive Data Patterns ──────────────────────────────────────────────────

EMAIL_PATTERN = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    re.IGNORECASE,
)

PHONE_PATTERN = re.compile(
    r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{4}",
)

# API keys: AWS, generic sk-*, AKIA, Bearer tokens, etc.
API_KEY_PATTERN = re.compile(
    r"(?:"
    r"(?:api[_\-]?key|apikey|api_secret|access[_\-]?key)\s*[:=]\s*['\"]?[a-zA-Z0-9\-_]{16,}['\"]?"
    r"|AKIA[0-9A-Z]{16}"
    r"|sk-[a-zA-Z0-9]{20,}"
    r"|key-[a-zA-Z0-9]{20,}"
    r")",
    re.IGNORECASE,
)

PASSWORD_PATTERN = re.compile(
    r"(?:password|passwd|pwd|pass)\s*[:=]\s*['\"]?[^\s'\"]{4,}['\"]?",
    re.IGNORECASE,
)

TOKEN_PATTERN = re.compile(
    r"(?:"
    r"(?:token|auth_token|access_token|bearer|jwt)\s*[:=]\s*['\"]?[a-zA-Z0-9\-_.]{16,}['\"]?"
    r"|Bearer\s+[a-zA-Z0-9\-_.]+(?:\.[a-zA-Z0-9\-_.]+){1,}"
    r")",
    re.IGNORECASE,
)

SECRET_PATTERN = re.compile(
    r"(?:secret|client_secret|app_secret|private_key)\s*[:=]\s*['\"]?[a-zA-Z0-9\-_/+=]{8,}['\"]?",
    re.IGNORECASE,
)

# ── Security Issue Patterns ──────────────────────────────────────────────────

STACK_TRACE_PATTERN = re.compile(
    r"(?:Traceback \(most recent call last\)|at\s+\S+\.\S+\(.*:\d+\)|Exception in thread|"
    r"^\s+File\s+\".*\",\s+line\s+\d+|java\.\w+\..*Exception|"
    r"panic:|runtime error:)",
    re.MULTILINE,
)

DEBUG_MODE_PATTERN = re.compile(
    r"(?:DEBUG\s*[:=]\s*(?:true|1|on|yes|enabled)|debug\s+mode\s+(?:is\s+)?(?:on|enabled|active))",
    re.IGNORECASE,
)

HARDCODED_CREDENTIAL_PATTERN = re.compile(
    r"(?:root:.*@|admin:.*@|mysql://\w+:\w+@|postgres://\w+:\w+@|mongodb://\w+:\w+@|"
    r"redis://:\w+@|ftp://\w+:\w+@)",
    re.IGNORECASE,
)

# ── Log Analysis Patterns ────────────────────────────────────────────────────

FAILED_LOGIN_PATTERN = re.compile(
    r"(?:failed\s+(?:login|auth(?:entication)?|sign[\s-]?in)|"
    r"invalid\s+(?:credentials?|password|username)|"
    r"(?:login|auth)\s+(?:fail(?:ure|ed)?|denied|rejected)|"
    r"access\s+denied|unauthorized\s+access|"
    r"401\s+unauthorized)",
    re.IGNORECASE,
)

IP_ADDRESS_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
)

SUSPICIOUS_IP_INDICATORS = re.compile(
    r"(?:blocked|banned|blacklisted|malicious|suspicious)\s+(?:ip|address|host)",
    re.IGNORECASE,
)

ERROR_LEAK_PATTERN = re.compile(
    r"(?:internal\s+server\s+error|sql\s+syntax\s+error|"
    r"undefined\s+(?:variable|method|function)|"
    r"null\s*pointer|segmentation\s+fault|"
    r"unhandled\s+exception|fatal\s+error|"
    r"errno|stacktrace|core\s+dump)",
    re.IGNORECASE,
)

SQL_INJECTION_PATTERN = re.compile(
    r"(?:'\s*(?:OR|AND)\s+['\d]|--\s*$|;\s*DROP\s+TABLE|"
    r"UNION\s+(?:ALL\s+)?SELECT|/\*.*\*/|"
    r"(?:exec|execute)\s*\(|xp_cmdshell)",
    re.IGNORECASE,
)

XSS_PATTERN = re.compile(
    r"(?:<script.*?>|onclick\s*=|onerror\s*=|alert\s*\(|javascript:|eval\s*\()",
    re.IGNORECASE,
)

# ── Network Entity Extraction Patterns ───────────────────────────────────────

TIMESTAMP_PATTERN = re.compile(
    r"\b(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?|"
    r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b",
)

# Extraction helper for various network attributes
LOG_TYPE_VECTORS = ["firewall", "auth", "syslog", "application", "kernel", "http"]
DEVICE_TYPE_VECTORS = ["edge router", "core switch", "endpoint", "server", "gateway"]

# Match ports explicitly following 'port' or following an IP address with a colon.
# Uses non-capturing group for the prefix and captures the digits.
PORT_PATTERN = re.compile(r"(?:\b(?:port|src_port|dest_port|sport|dport|spt|dpt|udp|tcp)\s*[:=]?\s*|(?:\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):)(\d{1,5})\b", re.IGNORECASE)
URI_PATTERN = re.compile(r"\s(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)?\s*(/[a-zA-Z0-9.\-_/%?=&]+)\s?")

# ── Detection Registry ──────────────────────────────────────────────────────

SENSITIVE_PATTERNS = {
    "email": EMAIL_PATTERN,
    "phone": PHONE_PATTERN,
    "api_key": API_KEY_PATTERN,
    "password": PASSWORD_PATTERN,
    "token": TOKEN_PATTERN,
    "secret": SECRET_PATTERN,
}

SECURITY_PATTERNS = {
    "stack_trace": STACK_TRACE_PATTERN,
    "debug_mode": DEBUG_MODE_PATTERN,
    "hardcoded_credential": HARDCODED_CREDENTIAL_PATTERN,
    "error_leak": ERROR_LEAK_PATTERN,
    "sql_injection": SQL_INJECTION_PATTERN,
    "xss": XSS_PATTERN,
}

LOG_PATTERNS = {
    "failed_login": FAILED_LOGIN_PATTERN,
    "suspicious_ip": SUSPICIOUS_IP_INDICATORS,
}

# ── Risk Mapping ─────────────────────────────────────────────────────────────

RISK_MAP: dict[str, str] = {
    "api_key": "high",
    "password": "critical",
    "token": "high",
    "email": "low",
    "phone": "low",
    "secret": "critical",
    "stack_trace": "medium",
    "debug_mode": "medium",
    "hardcoded_credential": "critical",
    "error_leak": "medium",
    "sql_injection": "high",
    "xss": "high",
    "failed_login": "medium",
    "suspicious_ip": "high",
    "brute_force": "critical",
}
