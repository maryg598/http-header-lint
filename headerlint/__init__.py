from .parser import ParsedHeader, detect_message_type, parse_headers
from .rules import Finding, run_rules

__version__ = "0.1.0"


def lint_text(text: str):
    """Parse a raw HTTP header block and return findings sorted by line."""
    headers = parse_headers(text)
    message_type = detect_message_type(text)
    return run_rules(headers, message_type)


__all__ = [
    "lint_text",
    "parse_headers",
    "detect_message_type",
    "run_rules",
    "Finding",
    "ParsedHeader",
]
