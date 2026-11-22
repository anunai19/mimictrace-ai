import json
import socket
import unittest
from unittest.mock import patch

from detection.evidence import EvidenceRecord
from detection.html_analyzer import (
    MAX_ACTIVE_FORMS,
    MAX_ANALYZED_TARGETS,
    MAX_HTML_TAG_EVENTS,
    analyze_html_document,
)


class TestHTMLAnalyzer(unittest.TestCase):

    def test_extracts_static_indicators_without_retaining_page_content(self):
        html = b"""
        <html>
          <form action="https://collect.example.org/submit">
            <input type="password" name="password">
            <input type="hidden" name="csrf" value="sensitive-value">
            <div hidden>private text</div>
          </form>
          <script src="https://cdn.example.net/app.js"></script>
          <iframe src="https://frame.example.org/"></iframe>
          <meta http-equiv="refresh" content="0;url=https://redirect.example.org/">
          <a href="https://links.example.org/path?token=secret">outbound</a>
          <a href="javascript:alert(1)">unsafe</a>
        </html>
        """

        record = analyze_html_document(
            html,
            "https://shop.example.com/account",
            final_url="https://shop.example.com/account",
            redirect_count=1,
        )

        self.assertIsInstance(record, EvidenceRecord)
        self.assertEqual(record.status, "observed")
        self.assertEqual(record.observation["counts"]["password_inputs"], 1)
        self.assertEqual(record.observation["counts"]["external_form_actions"], 1)
        self.assertEqual(record.observation["counts"]["cross_domain_form_actions"], 1)
        self.assertEqual(record.observation["counts"]["hidden_elements"], 1)
        self.assertEqual(record.observation["counts"]["external_scripts"], 1)
        self.assertEqual(record.observation["counts"]["iframes"], 1)
        self.assertEqual(record.observation["counts"]["meta_refreshes"], 1)
        encoded = record.to_json()
        self.assertNotIn("sensitive-value", encoded)
        self.assertNotIn("private text", encoded)
        self.assertNotIn("token=secret", encoded)
        json.loads(encoded)

    def test_form_action_on_same_registrable_domain_is_not_cross_domain(self):
        record = analyze_html_document(
            b'<form action="https://login.example.com/submit"></form>',
            "https://www.example.com/",
        )

        self.assertEqual(record.observation["counts"]["external_form_actions"], 1)
        self.assertEqual(record.observation["counts"]["cross_domain_form_actions"], 0)

    def test_unsupported_link_schemes_are_observations_not_requests(self):
        record = analyze_html_document(
            b'<a href="javascript:run()">one</a><a href="data:text/html,x">two</a>',
            "https://example.com/",
        )

        self.assertEqual(record.observation["counts"]["suspicious_link_schemes"], 2)

    def test_invalid_and_oversized_input_return_safe_evidence(self):
        invalid = analyze_html_document(b"", "https://example.com/")
        oversized = analyze_html_document(
            b"x" * (1024 * 1024 + 1),
            "https://example.com/",
        )

        self.assertEqual(invalid.status, "error")
        self.assertEqual(oversized.observation["availability"], "response_too_large")
        self.assertEqual(oversized.observation["indicators"], [])

    def test_parser_does_not_make_network_requests(self):
        with patch("socket.getaddrinfo", side_effect=AssertionError("DNS access")), \
             patch(
                 "dns.resolver.Resolver",
                 side_effect=AssertionError("DNS access"),
             ):
            record = analyze_html_document(
                b'<form><input type="password"></form>',
                "https://example.com/",
            )

        self.assertEqual(record.status, "observed")
        record.to_json()

    def test_base_href_applies_to_links_even_when_it_appears_later(self):
        record = analyze_html_document(
            b'<a href="/continue">continue</a>'
            b'<base href="https://other.example.org/root/">',
            "https://example.com/",
        )

        self.assertEqual(record.observation["counts"]["external_links"], 1)

    def test_dense_document_stops_at_tag_budget_with_bounded_evidence(self):
        html = (
            b'<a href="https://outside.example.org/path">link</a>'
            * (MAX_HTML_TAG_EVENTS // 2 + 100)
        )

        record = analyze_html_document(html, "https://example.com/")

        self.assertEqual(record.status, "observed")
        self.assertTrue(record.observation["analysis_truncated"])
        self.assertLessEqual(len(record.observation["external_links"]), 20)
        self.assertLess(len(record.to_json()), 20_000)

    def test_many_targets_stop_at_analysis_budget(self):
        html = (
            b'<a href="https://outside.example.org/path">link</a>'
            * (MAX_ANALYZED_TARGETS + 10)
        )

        record = analyze_html_document(html, "https://example.com/")

        self.assertTrue(record.observation["analysis_truncated"])
        self.assertEqual(
            record.observation["counts"]["external_links"],
            MAX_ANALYZED_TARGETS,
        )
        self.assertLessEqual(len(record.observation["external_links"]), 20)

    def test_excessively_nested_forms_stop_within_fixed_state_limit(self):
        html = (
            b"<form>" * (MAX_ACTIVE_FORMS + 10)
            + b'<input type="password">'
            + b"</form>" * (MAX_ACTIVE_FORMS + 10)
        )

        record = analyze_html_document(html, "https://example.com/")

        self.assertTrue(record.observation["analysis_truncated"])
        self.assertEqual(record.observation["counts"]["password_inputs"], 0)
        self.assertLess(len(record.to_json()), 20_000)

    def test_overlong_target_is_not_retained_in_evidence(self):
        long_target = b"https://outside.example.org/" + b"a" * 5_000
        html = b'<a href="' + long_target + b'">link</a>'

        record = analyze_html_document(html, "https://example.com/")

        self.assertTrue(record.observation["analysis_truncated"])
        self.assertEqual(
            record.observation["counts"]["suspicious_link_schemes"],
            1,
        )
        self.assertNotIn("a" * 100, record.to_json())


if __name__ == "__main__":
    unittest.main()
