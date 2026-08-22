"""Checks that run over a parsed header list.

Each rule is a plain function: headers in, Finding objects out. Add a
new rule by writing the function and dropping it into RULES.
"""

from dataclasses import dataclass
from typing import Iterable, List

from .parser import ParsedHeader

# Headers the spec (or long-standing practice) expects to see repeated,
# so they're excluded from the duplicate check.
REPEATABLE = {"set-cookie", "www-authenticate", "proxy-authenticate", "link", "via", "warning"}


@dataclass
class Finding:
    line: int
    severity: str  # "error" or "warning"
    code: str
    message: str


def check_malformed(headers: List[ParsedHeader]) -> Iterable[Finding]:
    for h in headers:
        if h.malformed:
            yield Finding(
                h.line, "error", "E001",
                f"line is not a valid header (missing colon): {h.raw!r}",
            )


def check_empty_name(headers: List[ParsedHeader]) -> Iterable[Finding]:
    for h in headers:
        if not h.malformed and h.name.strip() == "":
            yield Finding(h.line, "error", "E002", "header name is empty")


def check_whitespace_before_colon(headers: List[ParsedHeader]) -> Iterable[Finding]:
    for h in headers:
        if h.malformed:
            continue
        if h.name != h.name.rstrip():
            yield Finding(
                h.line, "warning", "W001",
                f"whitespace before colon in {h.name.strip()!r}; some servers "
                "treat this as a request smuggling vector",
            )


def check_duplicates(headers: List[ParsedHeader]) -> Iterable[Finding]:
    seen = {}
    for h in headers:
        if h.malformed or not h.name.strip():
            continue
        key = h.name.strip().lower()
        if key in REPEATABLE:
            continue
        if key in seen:
            yield Finding(
                h.line, "warning", "W002",
                f"{h.name.strip()!r} duplicates header first seen on line {seen[key]}",
            )
        else:
            seen[key] = h.line


def check_line_folding(headers: List[ParsedHeader]) -> Iterable[Finding]:
    for h in headers:
        for line_no in h.folded_lines:
            yield Finding(
                line_no, "warning", "W003",
                f"line folding continuation of {h.name.strip()!r} "
                "(RFC 7230 3.2.4 marks this obsolete)",
            )


RULES = [
    check_malformed,
    check_empty_name,
    check_whitespace_before_colon,
    check_duplicates,
    check_line_folding,
]


def run_rules(headers: List[ParsedHeader]) -> List[Finding]:
    findings: List[Finding] = []
    for rule in RULES:
        findings.extend(rule(headers))
    findings.sort(key=lambda f: (f.line, f.code))
    return findings
