# headerlint

Raw HTTP header dumps show up everywhere - saved from browser devtools,
piped out of `curl -I`, checked into `.http` files for API docs - and
they rot quietly. A header gets pasted twice, a colon picks up a
leading space from a copy-paste, someone "fixes" a long value by
wrapping it onto the next line the old RFC 2616 way. None of that
throws an error anywhere. It just sits there until it causes a cache
poisoning bug or a request smuggling report six months later.

headerlint reads a header block (with or without the request/status
line in front of it) and reports what's wrong with it, one line number
per finding, so you can see exactly which header to fix.

## Usage

From a file:

```
$ headerlint response.txt
response.txt:3: warning W002 'Content-Type' duplicates header first seen on line 2
response.txt:6: warning W001 whitespace before colon in 'X-Frame-Options'; some servers treat this as a request smuggling vector
response.txt:8: warning W003 line folding continuation of 'X-Long-Header' (RFC 7230 3.2.4 marks this obsolete)
response.txt:9: error E001 line is not a valid header (missing colon): 'BadLineNoColon'
```

From stdin, which is the point - pipe `curl -I` straight in:

```
$ curl -sI https://example.com | headerlint -
$ curl -sI https://example.com | headerlint
```

(with no file arguments at all, headerlint reads stdin by default)

Given this input:

```
HTTP/1.1 200 OK
Content-Type: text/html
Content-Type: text/html
Set-Cookie: a=1
Set-Cookie: b=2
X-Frame-Options : DENY
X-Long-Header: first part
 second part folded in
BadLineNoColon
```

`Set-Cookie` is allowed to repeat (that's normal), the duplicate
`Content-Type` is not, the space before the colon on `X-Frame-Options`
is the kind of thing some proxies and origins disagree about parsing,
and the folded continuation line is syntax that RFC 7230 explicitly
deprecated because it's been a source of smuggling bugs.

Exit status is 0 if nothing at error severity was found, 1 if an error
finding turned up, and 2 if a file couldn't be read at all.

Pass `--format json` to get machine-readable output instead - one JSON
array with one object per file, each holding that file's findings:

```
$ headerlint --format json response.txt
[
  {
    "file": "response.txt",
    "findings": [
      {"line": 3, "severity": "warning", "code": "W002", "message": "..."}
    ]
  }
]
```

## Install

No dependencies beyond the standard library. Run directly:

```
python -m headerlint.cli path/to/headers.txt
```

or install it so the `headerlint` command is on your PATH:

```
pip install -e .
```

## Findings

| Code | Meaning |
| ---- | ------- |
| E001 | line has no colon, so it can't be a header |
| E002 | header name is empty |
| W001 | whitespace between the header name and the colon |
| W002 | header repeated where repetition isn't expected |
| W003 | obsolete line-folding continuation |
| E003 | Content-Length and Transfer-Encoding both present (request smuggling) |
| E004 | Content-Length repeated with disagreeing values |
| W004 | Strict-Transport-Security header is missing |
| W005 | Content-Security-Policy header is missing |
| W006 | X-Content-Type-Options header is missing |

W004-W006 only fire on a response (a status line up front, or no
start line at all, which is the common case for a bare header dump).
A request dump - detected from a request line like `GET /path
HTTP/1.1` - skips them, since a request has no reason to carry those
headers. They report on line 0 since they're about something absent
rather than a specific line.
