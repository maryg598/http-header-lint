"""Turn raw HTTP header text into a list of ParsedHeader records.

The input can be a full request or response dump (start line, headers,
blank line, body) or just a bare header block, since that's what you
get from things like `curl -I` with the status line trimmed off.
"""

from dataclasses import dataclass, field
from typing import List, Optional
import re

# Matches a request line ("GET /path HTTP/1.1") or a status line
# ("HTTP/1.1 200 OK"). Only checked against the first line, so a stray
# header that happens to look like this later on is left alone.
REQUEST_LINE_RE = re.compile(r"^[A-Za-z]+ \S+ HTTP/\d\.\d\s*$")
STATUS_LINE_RE = re.compile(r"^HTTP/\d\.\d \d{3}(?: .*)?\s*$")
START_LINE_RE = re.compile(
    r"^(?:[A-Za-z]+ \S+ HTTP/\d\.\d|HTTP/\d\.\d \d{3}(?: .*)?)\s*$"
)


@dataclass
class ParsedHeader:
    line: int
    name: str
    value: str
    raw: str
    malformed: bool = False
    folded_lines: List[int] = field(default_factory=list)


def detect_message_type(text: str) -> str:
    """Classify the dump's first line as a request, a response, or neither.

    Security-header presence checks only make sense for responses, so
    callers use this to skip them on request dumps. A bare header block
    with no start line at all returns "unknown" and is treated like a
    response, since that's the common case (curl -I output, devtools
    copies) for this tool.
    """
    for line in text.splitlines():
        if line.strip() == "":
            return "unknown"
        if REQUEST_LINE_RE.match(line):
            return "request"
        if STATUS_LINE_RE.match(line):
            return "response"
        return "unknown"
    return "unknown"


def parse_headers(text: str) -> List[ParsedHeader]:
    headers: List[ParsedHeader] = []
    current: Optional[ParsedHeader] = None

    for i, raw in enumerate(text.splitlines()):
        line_no = i + 1

        if raw.strip() == "":
            # blank line ends the header section; anything after is body
            break

        if i == 0 and START_LINE_RE.match(raw):
            continue

        if raw[:1] in (" ", "\t") and current is not None:
            # obsolete line folding, RFC 7230 section 3.2.4
            current.value += " " + raw.strip()
            current.folded_lines.append(line_no)
            continue

        name, sep, value = raw.partition(":")
        if not sep:
            headers.append(
                ParsedHeader(line=line_no, name="", value="", raw=raw, malformed=True)
            )
            current = None
            continue

        current = ParsedHeader(line=line_no, name=name, value=value.strip(), raw=raw)
        headers.append(current)

    return headers
