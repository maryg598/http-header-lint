from .parser import ParsedHeader, parse_headers
from .rules import Finding, run_rules

__version__ = "0.1.0"


def lint_text(text: str):
    """Parse a raw HTTP header block and return findings sorted by line."""
    headers = parse_headers(text)
    return run_rules(headers)


__all__ = ["lint_text", "parse_headers", "run_rules", "Finding", "ParsedHeader"]
