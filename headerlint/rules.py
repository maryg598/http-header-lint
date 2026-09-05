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


def check_conflicting_framing(headers: List[ParsedHeader]) -> Iterable[Finding]:
    # Content-Length and Transfer-Encoding disagreeing about message
    # framing is the classic CL.TE / TE.CL request smuggling setup:
    # RFC 7230 3.3.3 says a recipient must treat this as an error rather
    # than guess which one to believe.
    content_length = [
        h for h in headers if not h.malformed and h.name.strip().lower() == "content-length"
    ]
    transfer_encoding = [
        h for h in headers if not h.malformed and h.name.strip().lower() == "transfer-encoding"
    ]

    if content_length and transfer_encoding:
        for h in content_length + transfer_encoding:
            yield Finding(
                h.line, "error", "E003",
                "Content-Length and Transfer-Encoding both present; RFC 7230 3.3.3 "
                "requires rejecting this rather than picking one (CL.TE / TE.CL smuggling)",
            )

    if len(content_length) > 1 and len({h.value.strip() for h in content_length}) > 1:
        for h in content_length:
            yield Finding(
                h.line, "error", "E004",
                f"Content-Length values disagree ({h.value.strip()!r} here); RFC 7230 "
                "3.3.3 requires the message be rejected rather than framed by either value",
            )


# Canonical capitalization for headers that show up in practice. Header
# names are case-insensitive per RFC 7230 3.2, so this is a style nit,
# not a correctness one - but mixed case in logs and diffs makes it
# easy to miss that two headers are actually the same one.
CANONICAL_HEADER_NAMES = {
    "accept": "Accept",
    "accept-encoding": "Accept-Encoding",
    "accept-language": "Accept-Language",
    "accept-ranges": "Accept-Ranges",
    "age": "Age",
    "allow": "Allow",
    "authorization": "Authorization",
    "cache-control": "Cache-Control",
    "connection": "Connection",
    "content-disposition": "Content-Disposition",
    "content-encoding": "Content-Encoding",
    "content-length": "Content-Length",
    "content-md5": "Content-MD5",
    "content-security-policy": "Content-Security-Policy",
    "content-type": "Content-Type",
    "cookie": "Cookie",
    "date": "Date",
    "dnt": "DNT",
    "etag": "ETag",
    "expires": "Expires",
    "host": "Host",
    "if-match": "If-Match",
    "if-modified-since": "If-Modified-Since",
    "if-none-match": "If-None-Match",
    "if-range": "If-Range",
    "if-unmodified-since": "If-Unmodified-Since",
    "last-modified": "Last-Modified",
    "link": "Link",
    "location": "Location",
    "origin": "Origin",
    "pragma": "Pragma",
    "proxy-authenticate": "Proxy-Authenticate",
    "proxy-authorization": "Proxy-Authorization",
    "referer": "Referer",
    "retry-after": "Retry-After",
    "server": "Server",
    "set-cookie": "Set-Cookie",
    "strict-transport-security": "Strict-Transport-Security",
    "te": "TE",
    "transfer-encoding": "Transfer-Encoding",
    "upgrade": "Upgrade",
    "upgrade-insecure-requests": "Upgrade-Insecure-Requests",
    "user-agent": "User-Agent",
    "vary": "Vary",
    "via": "Via",
    "warning": "Warning",
    "www-authenticate": "WWW-Authenticate",
    "x-content-type-options": "X-Content-Type-Options",
    "x-forwarded-for": "X-Forwarded-For",
    "x-forwarded-host": "X-Forwarded-Host",
    "x-forwarded-proto": "X-Forwarded-Proto",
    "x-frame-options": "X-Frame-Options",
    "x-request-id": "X-Request-Id",
    "x-xss-protection": "X-XSS-Protection",
}


def check_header_case(headers: List[ParsedHeader]) -> Iterable[Finding]:
    # Only checked against known header names; a custom header with
    # unusual casing (X-MyApp-Token vs x-myapp-token) isn't wrong, so
    # guessing a "canonical" form for it would just be noise.
    for h in headers:
        if h.malformed or not h.name.strip():
            continue
        name = h.name.strip()
        canonical = CANONICAL_HEADER_NAMES.get(name.lower())
        if canonical is not None and name != canonical:
            yield Finding(
                h.line, "warning", "W007",
                f"{name!r} should be written as {canonical!r}",
            )


# header name -> (code, description) for security headers whose mere
# absence is worth flagging on a response.
SECURITY_HEADERS = {
    "strict-transport-security": ("W004", "HSTS"),
    "content-security-policy": ("W005", "CSP"),
    "x-content-type-options": ("W006", "X-Content-Type-Options"),
}


def check_security_headers(headers: List[ParsedHeader], message_type: str) -> Iterable[Finding]:
    # Presence checks only mean something for a response: a request
    # dump has no business setting these, so flagging it there is noise.
    if message_type == "request":
        return

    present = {
        h.name.strip().lower() for h in headers if not h.malformed and h.name.strip()
    }
    for key, (code, label) in SECURITY_HEADERS.items():
        if key not in present:
            yield Finding(0, "warning", code, f"{label} header is missing")


RULES = [
    check_malformed,
    check_empty_name,
    check_whitespace_before_colon,
    check_duplicates,
    check_line_folding,
    check_conflicting_framing,
    check_header_case,
]


def run_rules(headers: List[ParsedHeader], message_type: str = "unknown") -> List[Finding]:
    findings: List[Finding] = []
    for rule in RULES:
        findings.extend(rule(headers))
    findings.extend(check_security_headers(headers, message_type))
    findings.sort(key=lambda f: (f.line, f.code))
    return findings
