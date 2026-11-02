"""Security utilities for input validation, sanitization, and rate limiting."""

import ipaddress
import re
import threading
import time
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional

# Pre-compiled security patterns for attack detection
BLOCKED_PATTERNS: List[re.Pattern] = [
    # SQL Injection patterns
    re.compile(r"(\bUNION\b\s+\bSELECT\b)", re.IGNORECASE),
    re.compile(r"(\bOR\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)", re.IGNORECASE),
    re.compile(r"(';\s*DROP\s+TABLE\b)", re.IGNORECASE),
    re.compile(r"(\bEXEC\b\s*\(|\bEXECUTE\b\s*\()", re.IGNORECASE),
    # Path Traversal patterns
    re.compile(r"(\.\./|\.\.\\){2,}"),
    re.compile(r"(%2e%2e%2f|%2e%2e\/|\.\.%2f)", re.IGNORECASE),
    re.compile(r"(/etc/passwd|c:\\windows\\system32)", re.IGNORECASE),
    # Command Injection / Shell metacharacters
    re.compile(r"(;\s*(?:cat|ls|rm|nc|curl|wget|bash|sh|powershell)\b)", re.IGNORECASE),
    re.compile(r"(\|\s*(?:cat|ls|rm|nc|curl|wget|bash|sh)\b)", re.IGNORECASE),
    re.compile(r"(`.*`|\$\(.*\))"),
    # Cross-Site Scripting (XSS)
    re.compile(r"(<script\b[^>]*>.*?</script>)", re.IGNORECASE),
    re.compile(r"(javascript\s*:\s*[^\s]+)", re.IGNORECASE),
    re.compile(r"(onerror\s*=|onload\s*=|onclick\s*=)", re.IGNORECASE),
]

PROMPT_INJECTION_PATTERNS: List[re.Pattern] = [
    re.compile(r"ignore\s+(all\s+)?(previous|above)\s+instructions", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(previous|above)\s+(instructions|prompts)", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(a\s+)?(DAN|unrestricted|jailbroken|an\s+evil|a\s+helpful\s+hacker)", re.IGNORECASE),
    re.compile(r"system\s*prompt\s*:\s*", re.IGNORECASE),
    re.compile(r"output\s+the\s+system\s+prompt", re.IGNORECASE),
    re.compile(r"(print|show|reveal|display|output)\s+(your\s+)?(system\s+prompt|instructions|initial\s+prompt)", re.IGNORECASE),
    re.compile(r"reveal\s+(your\s+)?instructions", re.IGNORECASE),
    re.compile(r"bypass\s+all\s+(safety|content)\s+filters", re.IGNORECASE),
    re.compile(r"new\s+rule\s*:\s*", re.IGNORECASE),
    re.compile(r"<\|im_start\|>|<\|im_end\|>|<\|endoftext\|>", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+a\s+helpful", re.IGNORECASE),
]

_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]")
_ANSI_ESCAPE_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

# Thread-safe in-memory rate limiter tracker
_RATE_LIMITER_LOCK = threading.Lock()
_RATE_LIMIT_BUCKETS: Dict[str, deque] = defaultdict(deque)


def sanitize_log_input(text: Optional[str]) -> str:
    """Sanitize log text input by removing control characters, ANSI codes, and normalizing.

    Args:
        text: Raw log text string.

    Returns:
        Cleaned text string.
    """
    if not text:
        return ""

    # Remove null bytes and ANSI terminal sequences
    sanitized = text.replace("\x00", "")
    sanitized = _ANSI_ESCAPE_RE.sub("", sanitized)

    # Strip dangerous non-printable control characters, preserving standard whitespace (\t, \n, \r)
    sanitized = _CONTROL_CHAR_RE.sub("", sanitized)

    return sanitized.strip()


def is_prompt_injection(text: Optional[str]) -> bool:
    """Check if the provided text exhibits prompt injection characteristics.

    Args:
        text: Input string to test.

    Returns:
        True if suspect injection patterns are detected, False otherwise.
    """
    if not text:
        return False

    for pattern in PROMPT_INJECTION_PATTERNS:
        if pattern.search(text):
            return True

    return False


def validate_ip(ip_str: Optional[str]) -> bool:
    """Validate whether an input string is a valid IPv4 or IPv6 address.

    Args:
        ip_str: Candidate IP string.

    Returns:
        True if valid IPv4 or IPv6, False otherwise.
    """
    if not ip_str or not isinstance(ip_str, str):
        return False

    clean_ip = ip_str.strip()
    try:
        ipaddress.ip_address(clean_ip)
        return True
    except ValueError:
        return False


def validate_port(port: Any) -> bool:
    """Validate whether a value is an integer within the valid network port range (0-65535).

    Args:
        port: Candidate port number.

    Returns:
        True if within 0..65535, False otherwise.
    """
    if port is None:
        return False

    try:
        port_int = int(port)
        return 0 <= port_int <= 65535
    except (ValueError, TypeError):
        return False


def rate_limit_check(key: str, max_calls: int, window_seconds: float) -> bool:
    """In-memory thread-safe sliding window rate limiter.

    Args:
        key: Identifier key (e.g. IP address or client ID).
        max_calls: Maximum permitted invocations within window.
        window_seconds: Window length in seconds.

    Returns:
        True if request is permitted, False if rate limit is exceeded.
    """
    if max_calls <= 0 or window_seconds <= 0:
        return False

    now = time.time()
    cutoff = now - window_seconds

    with _RATE_LIMITER_LOCK:
        dq = _RATE_LIMIT_BUCKETS[key]

        # Evict timestamps outside the window
        while dq and dq[0] <= cutoff:
            dq.popleft()

        if len(dq) >= max_calls:
            return False

        dq.append(now)
        return True


def clear_rate_limits() -> None:
    """Reset rate limiter state (useful in test suites)."""
    with _RATE_LIMITER_LOCK:
        _RATE_LIMIT_BUCKETS.clear()
