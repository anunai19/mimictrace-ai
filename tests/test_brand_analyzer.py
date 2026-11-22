import unittest
from unittest.mock import patch

import dns.resolver
import requests

from detection.brand_analyzer import (
    BRAND_CATALOG,
    _TLD_EXTRACTOR,
    analyze_brand_impersonation,
)
from detection.evidence import EvidenceRecord


class TestBrandAnalyzer(unittest.TestCase):

    def test_catalog_contains_only_approved_canonical_domains(self):
        self.assertEqual(
            BRAND_CATALOG,
            (
                ("Google", "google.com"),
                ("Microsoft", "microsoft.com"),
                ("Apple", "apple.com"),
                ("Amazon", "amazon.com"),
                ("PayPal", "paypal.com"),
            ),
        )

    def test_exact_canonical_domain_and_subdomain_are_catalog_references(self):
        for url in (
            "https://google.com/",
            "https://accounts.google.com/",
        ):
            with self.subTest(url=url):
                record = analyze_brand_impersonation(url)

                self.assertIsInstance(record, EvidenceRecord)
                self.assertEqual(record.status, "observed")
                self.assertEqual(
                    record.observation["matches"][0]["method"],
                    "canonical_domain_or_subdomain",
                )
                self.assertEqual(
                    record.observation["matches"][0]["strength"],
                    "catalog_reference",
                )

    def test_brand_like_subdomain_is_weak_and_boundary_aware(self):
        record = analyze_brand_impersonation("https://google.attacker.com/")

        self.assertEqual(
            record.observation["matches"],
            [{
                "brand": "Google",
                "canonical_domain": "google.com",
                "method": "brand_token_in_subdomain",
                "strength": "weak",
            }],
        )

    def test_supported_confusable_brand_token_in_subdomain_is_weak(self):
        record = analyze_brand_impersonation("https://gοogle.attacker.com/")

        self.assertEqual(
            record.observation["matches"],
            [{
                "brand": "Google",
                "canonical_domain": "google.com",
                "method": "unicode_confusable_token_in_subdomain",
                "strength": "weak",
            }],
        )

    def test_confusable_subdomain_matching_respects_label_boundaries(self):
        record = analyze_brand_impersonation("https://notgοogle.attacker.com/")

        self.assertEqual(record.observation["matches"], [])

    def test_exact_brand_label_on_other_suffix_is_only_a_candidate(self):
        record = analyze_brand_impersonation("https://google.net/")

        self.assertEqual(
            record.observation["matches"][0]["method"],
            "exact_brand_label_different_domain",
        )
        self.assertEqual(
            record.observation["matches"][0]["strength"],
            "moderate",
        )
        self.assertTrue(any("does not prove" in item for item in record.uncertainty))

    def test_single_substitution_and_adjacent_transposition_are_detected(self):
        substitution = analyze_brand_impersonation("https://goog1e.com/")
        transposition = analyze_brand_impersonation("https://goolge.com/")

        self.assertEqual(
            substitution.observation["matches"][0]["method"],
            "single_character_substitution",
        )
        self.assertEqual(
            transposition.observation["matches"][0]["method"],
            "adjacent_transposition",
        )

    def test_one_edit_is_accepted_and_two_edits_are_rejected(self):
        one_edit = analyze_brand_impersonation("https://gooogle.com/")
        two_edits = analyze_brand_impersonation("https://g00gle.com/")

        self.assertEqual(
            one_edit.observation["matches"][0]["method"],
            "single_character_insertion_or_deletion",
        )
        self.assertEqual(two_edits.observation["matches"], [])

    def test_short_brand_names_do_not_use_fuzzy_matching(self):
        record = analyze_brand_impersonation("https://applf.com/")

        self.assertEqual(record.observation["matches"], [])

    def test_unicode_confusable_is_flagged_with_uncertainty(self):
        record = analyze_brand_impersonation("https://gοogle.com/")

        self.assertTrue(record.observation["unicode_present"])
        self.assertTrue(
            record.observation["mixed_scripts_in_registrable_label"]
        )
        self.assertEqual(
            record.observation["matches"][0]["method"],
            "unicode_confusable_skeleton",
        )
        self.assertTrue(any("limited set" in item for item in record.uncertainty))

    def test_unicode_and_punycode_hostnames_normalize_consistently(self):
        unicode_record = analyze_brand_impersonation("https://café.com/")
        punycode_record = analyze_brand_impersonation(
            "https://xn--caf-dma.com/"
        )

        self.assertEqual(
            unicode_record.observation["hostname_ascii"],
            punycode_record.observation["hostname_ascii"],
        )
        self.assertEqual(
            unicode_record.observation["hostname_unicode"],
            punycode_record.observation["hostname_unicode"],
        )
        self.assertTrue(unicode_record.observation["unicode_present"])
        self.assertTrue(punycode_record.observation["unicode_present"])
        self.assertEqual(unicode_record.observation["matches"], [])

    def test_original_unicode_hostname_is_preserved_through_compatibility_mapping(self):
        url = "https://ｇoogle.attacker.com/"
        record = analyze_brand_impersonation(url)

        self.assertEqual(
            record.observation["hostname_submitted"],
            "ｇoogle.attacker.com",
        )
        self.assertEqual(record.observation["hostname_ascii"], "google.attacker.com")
        self.assertTrue(record.observation["unicode_present"])
        self.assertEqual(
            record.observation["matches"][0]["method"],
            "brand_token_in_subdomain",
        )

    def test_nfkc_only_compatibility_character_is_folded_deterministically(self):
        record = analyze_brand_impersonation("https://ℊoogle.attacker.com/")

        self.assertEqual(
            record.observation["hostname_submitted"],
            "ℊoogle.attacker.com",
        )
        self.assertEqual(record.observation["hostname_ascii"], "google.attacker.com")
        self.assertTrue(record.observation["unicode_present"])
        self.assertEqual(
            record.observation["matches"][0]["method"],
            "brand_token_in_subdomain",
        )

    def test_unsupported_confusable_character_is_not_mapped(self):
        record = analyze_brand_impersonation("https://gօogle.attacker.com/")

        self.assertEqual(record.observation["matches"], [])
        self.assertTrue(record.observation["unicode_present"])

    def test_suffix_extractor_failure_returns_safe_error_evidence(self):
        with patch(
            "detection.brand_analyzer._TLD_EXTRACTOR",
            side_effect=RuntimeError("private parser details"),
        ):
            record = analyze_brand_impersonation("https://google.com/")

        self.assertEqual(record.status, "error")
        self.assertEqual(
            record.observation["availability"],
            "registrable_domain_error",
        )
        self.assertEqual(record.observation["matches"], [])
        self.assertNotIn(
            "private parser details",
            str(record.to_dict()),
        )

    def test_ip_literal_and_invalid_input_are_not_brand_matches(self):
        ip_record = analyze_brand_impersonation("https://8.8.8.8/")
        invalid_record = analyze_brand_impersonation("https://")

        self.assertEqual(ip_record.status, "unavailable")
        self.assertEqual(ip_record.observation["availability"], "ip_literal")
        self.assertEqual(invalid_record.status, "error")
        self.assertEqual(
            invalid_record.observation["availability"],
            "invalid_input",
        )
        self.assertEqual(invalid_record.observation["matches"], [])

    def test_serialization_and_analysis_do_not_make_network_requests(self):
        with patch("socket.getaddrinfo", side_effect=AssertionError("DNS access")), \
             patch(
                 "dns.resolver.Resolver",
                 side_effect=AssertionError("DNS access"),
             ), patch(
                 "requests.get",
                 side_effect=AssertionError("HTTP access"),
             ), patch(
                 "requests.sessions.Session.request",
                 side_effect=AssertionError("HTTP access"),
             ):
            record = analyze_brand_impersonation("https://google.com/")

        self.assertEqual(_TLD_EXTRACTOR.suffix_list_urls, ())
        record.to_json()
        self.assertEqual(
            set(record.to_dict()),
            {"source", "observation", "status", "uncertainty"},
        )


if __name__ == "__main__":
    unittest.main()
