import unittest

from headerlint.parser import parse_headers
from headerlint.rules import (
    check_conflicting_framing,
    check_duplicates,
    check_empty_name,
    check_header_case,
    check_line_folding,
    check_malformed,
    check_security_headers,
    check_whitespace_before_colon,
    run_rules,
)


def codes(findings):
    return [f.code for f in findings]


class CheckMalformedTests(unittest.TestCase):
    def test_flags_line_with_no_colon(self):
        headers = parse_headers("Content-Type: text/html\nBadLine\n")
        findings = list(check_malformed(headers))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].code, "E001")
        self.assertEqual(findings[0].line, 2)

    def test_no_findings_when_all_well_formed(self):
        headers = parse_headers("Content-Type: text/html\n")
        self.assertEqual(list(check_malformed(headers)), [])


class CheckEmptyNameTests(unittest.TestCase):
    def test_flags_empty_name(self):
        headers = parse_headers(": no name here\n")
        findings = list(check_empty_name(headers))
        self.assertEqual(codes(findings), ["E002"])

    def test_malformed_lines_are_not_double_flagged(self):
        headers = parse_headers("BadLine\n")
        self.assertEqual(list(check_empty_name(headers)), [])


class CheckWhitespaceBeforeColonTests(unittest.TestCase):
    def test_flags_space_before_colon(self):
        headers = parse_headers("X-Frame-Options : DENY\n")
        findings = list(check_whitespace_before_colon(headers))
        self.assertEqual(codes(findings), ["W001"])
        self.assertIn("X-Frame-Options", findings[0].message)

    def test_no_finding_without_leading_whitespace(self):
        headers = parse_headers("X-Frame-Options: DENY\n")
        self.assertEqual(list(check_whitespace_before_colon(headers)), [])


class CheckDuplicatesTests(unittest.TestCase):
    def test_flags_second_occurrence_only(self):
        headers = parse_headers("Content-Type: a\nContent-Type: b\n")
        findings = list(check_duplicates(headers))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].line, 2)
        self.assertIn("line 1", findings[0].message)

    def test_case_insensitive_match(self):
        headers = parse_headers("Content-Type: a\ncontent-type: b\n")
        self.assertEqual(len(list(check_duplicates(headers))), 1)

    def test_repeatable_headers_are_exempt(self):
        headers = parse_headers("Set-Cookie: a=1\nSet-Cookie: b=2\n")
        self.assertEqual(list(check_duplicates(headers)), [])


class CheckLineFoldingTests(unittest.TestCase):
    def test_flags_each_folded_continuation_line(self):
        headers = parse_headers("X-Long: a\n b\n c\n")
        findings = list(check_line_folding(headers))
        self.assertEqual([f.line for f in findings], [2, 3])
        self.assertTrue(all(f.code == "W003" for f in findings))

    def test_no_finding_without_folding(self):
        headers = parse_headers("X-Long: a\n")
        self.assertEqual(list(check_line_folding(headers)), [])


class CheckConflictingFramingTests(unittest.TestCase):
    def test_content_length_and_transfer_encoding_together(self):
        headers = parse_headers("Content-Length: 10\nTransfer-Encoding: chunked\n")
        findings = list(check_conflicting_framing(headers))
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(f.code == "E003" for f in findings))

    def test_disagreeing_content_length_values(self):
        headers = parse_headers("Content-Length: 10\nContent-Length: 20\n")
        findings = list(check_conflicting_framing(headers))
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(f.code == "E004" for f in findings))

    def test_repeated_content_length_with_same_value_is_fine(self):
        headers = parse_headers("Content-Length: 10\nContent-Length: 10\n")
        self.assertEqual(list(check_conflicting_framing(headers)), [])

    def test_neither_header_present_is_fine(self):
        headers = parse_headers("Content-Type: text/html\n")
        self.assertEqual(list(check_conflicting_framing(headers)), [])


class CheckHeaderCaseTests(unittest.TestCase):
    def test_flags_non_canonical_case(self):
        headers = parse_headers("content-type: text/html\n")
        findings = list(check_header_case(headers))
        self.assertEqual(codes(findings), ["W007"])
        self.assertIn("Content-Type", findings[0].message)

    def test_canonical_case_is_fine(self):
        headers = parse_headers("Content-Type: text/html\n")
        self.assertEqual(list(check_header_case(headers)), [])

    def test_unknown_header_is_never_flagged(self):
        headers = parse_headers("X-MyApp-Token: abc\n")
        self.assertEqual(list(check_header_case(headers)), [])


class CheckSecurityHeadersTests(unittest.TestCase):
    def test_missing_headers_flagged_on_response(self):
        headers = parse_headers("Content-Type: text/html\n")
        findings = list(check_security_headers(headers, "response"))
        self.assertEqual(sorted(codes(findings)), ["W004", "W005", "W006"])
        self.assertTrue(all(f.line == 0 for f in findings))

    def test_missing_headers_flagged_when_type_unknown(self):
        headers = parse_headers("Content-Type: text/html\n")
        findings = list(check_security_headers(headers, "unknown"))
        self.assertEqual(len(findings), 3)

    def test_present_headers_are_not_flagged(self):
        headers = parse_headers(
            "Strict-Transport-Security: max-age=1\n"
            "Content-Security-Policy: default-src 'self'\n"
            "X-Content-Type-Options: nosniff\n"
        )
        self.assertEqual(list(check_security_headers(headers, "response")), [])

    def test_requests_are_skipped_entirely(self):
        headers = parse_headers("Host: example.com\n")
        self.assertEqual(list(check_security_headers(headers, "request")), [])


class RunRulesTests(unittest.TestCase):
    def test_findings_are_sorted_by_line_then_code(self):
        text = (
            "HTTP/1.1 200 OK\n"
            "Content-Type: text/html\n"
            "Content-Type: text/html\n"
            "Set-Cookie: a=1\n"
            "Set-Cookie: b=2\n"
            "X-Frame-Options : DENY\n"
            "X-Long-Header: first part\n"
            " second part folded in\n"
            "BadLineNoColon\n"
        )
        headers = parse_headers(text)
        findings = run_rules(headers, "response")
        self.assertEqual(
            [(f.line, f.code) for f in findings],
            [
                (0, "W004"),
                (0, "W005"),
                (0, "W006"),
                (3, "W002"),
                (6, "W001"),
                (8, "W003"),
                (9, "E001"),
            ],
        )

    def test_clean_input_has_no_findings(self):
        text = (
            "HTTP/1.1 200 OK\n"
            "Content-Type: text/html\n"
            "Strict-Transport-Security: max-age=1\n"
            "Content-Security-Policy: default-src 'self'\n"
            "X-Content-Type-Options: nosniff\n"
        )
        headers = parse_headers(text)
        self.assertEqual(run_rules(headers, "response"), [])


if __name__ == "__main__":
    unittest.main()
