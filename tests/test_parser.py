import unittest

from headerlint.parser import detect_message_type, parse_headers


class ParseHeadersTests(unittest.TestCase):
    def test_basic_headers_keep_their_line_numbers(self):
        text = "Content-Type: text/html\nX-Request-Id: abc123\n"
        headers = parse_headers(text)
        self.assertEqual([h.line for h in headers], [1, 2])
        self.assertEqual(headers[0].name, "Content-Type")
        self.assertEqual(headers[0].value, "text/html")
        self.assertEqual(headers[1].name, "X-Request-Id")
        self.assertEqual(headers[1].value, "abc123")

    def test_request_line_is_skipped_and_line_numbers_stay_1_based(self):
        text = "GET /path HTTP/1.1\nHost: example.com\n"
        headers = parse_headers(text)
        self.assertEqual(len(headers), 1)
        self.assertEqual(headers[0].line, 2)
        self.assertEqual(headers[0].name, "Host")

    def test_status_line_is_skipped(self):
        text = "HTTP/1.1 200 OK\nContent-Length: 0\n"
        headers = parse_headers(text)
        self.assertEqual(len(headers), 1)
        self.assertEqual(headers[0].line, 2)
        self.assertEqual(headers[0].name, "Content-Length")

    def test_bare_header_block_has_no_start_line_to_skip(self):
        text = "Content-Type: text/html\nContent-Length: 12\n"
        headers = parse_headers(text)
        self.assertEqual(len(headers), 2)
        self.assertEqual(headers[0].line, 1)

    def test_blank_line_ends_the_header_section(self):
        text = "Content-Type: text/html\n\n<html>ignored body</html>\n"
        headers = parse_headers(text)
        self.assertEqual(len(headers), 1)

    def test_missing_colon_is_malformed(self):
        text = "Content-Type: text/html\nBadLineNoColon\n"
        headers = parse_headers(text)
        self.assertEqual(len(headers), 2)
        bad = headers[1]
        self.assertTrue(bad.malformed)
        self.assertEqual(bad.line, 2)
        self.assertEqual(bad.raw, "BadLineNoColon")

    def test_line_folding_is_merged_into_the_previous_header(self):
        text = "X-Long-Header: first part\n second part folded in\n"
        headers = parse_headers(text)
        self.assertEqual(len(headers), 1)
        h = headers[0]
        self.assertEqual(h.value, "first part second part folded in")
        self.assertEqual(h.folded_lines, [2])

    def test_line_folding_with_tab_indent(self):
        text = "X-Long-Header: first part\n\tsecond part\n"
        headers = parse_headers(text)
        self.assertEqual(len(headers), 1)
        self.assertEqual(headers[0].value, "first part second part")

    def test_indented_line_with_no_preceding_header_is_malformed(self):
        # An indented line before any real header has nothing to fold
        # into, so it's parsed as its own (colon-less) line instead.
        text = " stray indented line\nContent-Type: text/html\n"
        headers = parse_headers(text)
        self.assertEqual(len(headers), 2)
        self.assertTrue(headers[0].malformed)
        self.assertEqual(headers[1].name, "Content-Type")

    def test_empty_header_name(self):
        text = ": no name here\n"
        headers = parse_headers(text)
        self.assertEqual(len(headers), 1)
        self.assertFalse(headers[0].malformed)
        self.assertEqual(headers[0].name, "")

    def test_empty_input(self):
        self.assertEqual(parse_headers(""), [])


class DetectMessageTypeTests(unittest.TestCase):
    def test_request_line(self):
        self.assertEqual(detect_message_type("GET / HTTP/1.1\nHost: x\n"), "request")

    def test_status_line(self):
        self.assertEqual(detect_message_type("HTTP/1.1 200 OK\nContent-Length: 0\n"), "response")

    def test_status_line_without_reason_phrase(self):
        self.assertEqual(detect_message_type("HTTP/1.1 200\n"), "response")

    def test_bare_header_block_is_unknown(self):
        self.assertEqual(detect_message_type("Content-Type: text/html\n"), "unknown")

    def test_empty_text_is_unknown(self):
        self.assertEqual(detect_message_type(""), "unknown")

    def test_leading_blank_line_is_unknown(self):
        self.assertEqual(detect_message_type("\nContent-Type: text/html\n"), "unknown")


if __name__ == "__main__":
    unittest.main()
