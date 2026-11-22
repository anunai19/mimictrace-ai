import json
import unittest
from unittest.mock import patch

from detection.evidence import EvidenceRecord
from intelligence.relationship_graph import (
    MAX_GRAPH_EDGES,
    MAX_GRAPH_NODES,
    analyze_relationship_graph,
)


def _record(source, observation, status="observed", uncertainty=None):
    return EvidenceRecord(
        source=source,
        observation=observation,
        status=status,
        uncertainty=uncertainty or ["Synthetic source observation."],
    ).to_dict()


def _evidence():
    return {
        "dns": {
            "A": _record(
                "dns.a",
                {"addresses": ["8.8.8.8"]},
                uncertainty=["DNS A answers can change over time."],
            ),
            "AAAA": _record(
                "dns.aaaa",
                {"addresses": ["2001:4860:4860::8888"]},
            ),
            "MX": _record("dns.mx", {}, status="unavailable"),
            "NS": _record("dns.ns", {}, status="unavailable"),
            "TXT": _record("dns.txt", {}, status="unavailable"),
        },
        "html": _record(
            "html.static",
            {
                "original_host": "example.com",
                "page_host": "final.example.net",
                "redirect_count": 1,
                "external_form_actions": [
                    {"kind": "web", "host": "forms.example.org"},
                ],
                "external_scripts": [
                    {"kind": "web", "host": "cdn.example.net"},
                ],
                "iframes": [
                    {"kind": "web", "host": "frame.example.net"},
                ],
                "external_links": [
                    {"kind": "web", "host": "links.example.net"},
                ],
                "raw_html": "<form>raw page content</form>",
                "form_value": "sensitive form value",
            },
            uncertainty=["Static references do not establish navigation."],
        ),
        "domain": _record(
            "domain.whois",
            {"registrar": "DO_NOT_EXPOSE_REGISTRAR"},
        ),
        "tls": _record(
            "tls.certificate",
            {
                "hostname": "example.com",
                "verification": "verified",
                "subject_alt_names": {
                    "dns": ["DO_NOT_EXPOSE_CERTIFICATE_DETAIL.example"],
                },
                "not_before": "DO_NOT_EXPOSE_CERTIFICATE_DATE",
            },
        ),
        "brand": _record(
            "brand.impersonation",
            {
                "hostname_ascii": "example.com",
                "registrable_domain": "example.com",
                "matches": [
                    {
                        "brand": "Google",
                        "canonical_domain": "google.com",
                        "method": "single_character_substitution",
                        "strength": "moderate",
                    },
                ],
            },
            uncertainty=["Similarity does not establish affiliation."],
        ),
    }


class TestRelationshipGraph(unittest.TestCase):

    def test_builds_observed_relationships_with_sources_and_uncertainty(self):
        record = analyze_relationship_graph(_evidence())

        self.assertIsInstance(record, EvidenceRecord)
        self.assertEqual(record.status, "observed")
        edges = record.observation["edges"]
        relationship_types = {edge["type"] for edge in edges}
        self.assertEqual(
            relationship_types,
            {
                "resolves_to",
                "form_submits_to",
                "loads_script_from",
                "embeds_host",
                "links_to",
                "redirected_to",
                "resembles_brand_domain",
            },
        )
        for edge in edges:
            self.assertTrue(edge["evidence_refs"])
            self.assertTrue(edge["uncertainty"])
        dns_edge = next(
            edge
            for edge in edges
            if edge["type"] == "resolves_to"
            and edge["target"] == "ip:8.8.8.8"
        )
        self.assertIn(
            {"key": "dns.A", "source": "dns.a"},
            dns_edge["evidence_refs"],
        )
        self.assertTrue(any(
            "DNS A answers can change" in item
            for item in dns_edge["uncertainty"]
        ))
        brand_edge = next(
            edge for edge in edges if edge["type"] == "resembles_brand_domain"
        )
        self.assertEqual(brand_edge["strength"], "moderate")
        self.assertTrue(any(
            "does not establish affiliation" in item
            for item in brand_edge["uncertainty"]
        ))
        serialized = record.to_json()
        json.loads(serialized)
        self.assertNotIn("raw page content", serialized)
        self.assertNotIn("sensitive form value", serialized)
        self.assertNotIn("DO_NOT_EXPOSE_REGISTRAR", serialized)
        self.assertNotIn("DO_NOT_EXPOSE_CERTIFICATE", serialized)
        self.assertNotIn("https://", serialized)

    def test_unavailable_error_and_not_run_sources_create_no_edges(self):
        evidence = {
            "dns": {
                "A": _record(
                    "dns.a",
                    {"addresses": ["8.8.8.8"]},
                    status="unavailable",
                ),
            },
            "html": _record(
                "html.static",
                {"page_host": "example.com"},
                status="error",
            ),
            "brand": _record(
                "brand.impersonation",
                {
                    "registrable_domain": "example.com",
                    "matches": [{
                        "brand": "Google",
                        "canonical_domain": "google.com",
                        "method": "single_character_substitution",
                        "strength": "moderate",
                    }],
                },
                status="not_run",
            ),
        }

        record = analyze_relationship_graph(evidence)

        self.assertEqual(record.status, "unavailable")
        self.assertEqual(record.observation["availability"], "no_relationships")
        self.assertEqual(record.observation["nodes"], [])
        self.assertEqual(record.observation["edges"], [])

    def test_graph_is_deterministic_and_enforces_size_limits(self):
        evidence = _evidence()
        evidence["html"]["observation"]["external_links"] = [
            {"kind": "web", "host": f"link-{index}.example.net"}
            for index in range(250)
        ]

        first = analyze_relationship_graph(evidence)
        second = analyze_relationship_graph(evidence)

        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertLessEqual(len(first.observation["nodes"]), MAX_GRAPH_NODES)
        self.assertLessEqual(len(first.observation["edges"]), MAX_GRAPH_EDGES)
        self.assertTrue(first.observation["truncated"])
        self.assertTrue(any("size limit" in item for item in first.uncertainty))

    def test_oversized_html_targets_are_order_independent(self):
        hosts = [f"link-{index:03d}.example.net" for index in range(250)]
        first_evidence = _evidence()
        second_evidence = _evidence()
        first_evidence["html"]["observation"]["external_links"] = [
            {"kind": "web", "host": host} for host in hosts
        ]
        second_evidence["html"]["observation"]["external_links"] = [
            {"kind": "web", "host": host} for host in reversed(hosts)
        ]

        first = analyze_relationship_graph(first_evidence)
        second = analyze_relationship_graph(second_evidence)

        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertTrue(first.observation["truncated"])

    def test_oversized_dns_addresses_are_order_independent(self):
        addresses = [f"8.8.8.{index}" for index in range(1, 251)]
        first_evidence = _evidence()
        second_evidence = _evidence()
        first_evidence["dns"]["A"]["observation"]["addresses"] = addresses
        second_evidence["dns"]["A"]["observation"]["addresses"] = list(
            reversed(addresses)
        )

        first = analyze_relationship_graph(first_evidence)
        second = analyze_relationship_graph(second_evidence)

        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertTrue(first.observation["truncated"])

    def test_oversized_brand_matches_are_order_independent(self):
        matches = [
            {
                "brand": f"Brand {index:03d}",
                "canonical_domain": f"brand-{index:03d}.example",
                "method": "exact_brand_label_different_domain",
                "strength": "weak",
            }
            for index in range(250)
        ]
        first_evidence = _evidence()
        second_evidence = _evidence()
        first_evidence["brand"]["observation"]["matches"] = matches
        second_evidence["brand"]["observation"]["matches"] = list(
            reversed(matches)
        )

        first = analyze_relationship_graph(first_evidence)
        second = analyze_relationship_graph(second_evidence)

        self.assertEqual(first.to_dict(), second.to_dict())
        self.assertTrue(first.observation["truncated"])

    def test_graph_builder_performs_no_network_operations(self):
        with patch(
            "socket.getaddrinfo",
            side_effect=AssertionError("DNS access"),
        ), patch(
            "dns.resolver.Resolver",
            side_effect=AssertionError("DNS access"),
        ), patch(
            "socket.socket",
            side_effect=AssertionError("Socket access"),
        ):
            record = analyze_relationship_graph(_evidence())

        self.assertEqual(record.status, "observed")
        record.to_json()

    def test_invalid_input_returns_json_safe_error_evidence(self):
        record = analyze_relationship_graph(None)

        self.assertEqual(record.status, "error")
        self.assertEqual(record.observation["availability"], "invalid_input")
        self.assertEqual(record.observation["nodes"], [])
        self.assertEqual(record.observation["edges"], [])
        json.loads(record.to_json())


if __name__ == "__main__":
    unittest.main()


def _visual_observed(brand="ExampleBrand", canonical_domain="example.com",
                     match_result=None, calibration_state="calibrated",
                     evaluations=None):
    """Return a serialized visual evidence record for test use."""
    if evaluations is None:
        evaluations = [
            {
                "brand": brand,
                "canonical_domain": canonical_domain,
                "variant_id": "v1",
                "phash_distance": 4,
                "dhash_distance": 3,
            }
        ]
    return EvidenceRecord(
        source="visual.logo_crop",
        observation={
            "availability": "available",
            "calibration_state": calibration_state,
            "candidate_brand": brand if match_result is not None else None,
            "reference_variant": "v1" if match_result is not None else None,
            "match_result": match_result,
            "evaluations": evaluations,
        },
        status="observed",
        uncertainty=["Synthetic visual observation."],
    ).to_dict()


def _evidence_with_visual(**kwargs):
    """Return a full evidence dict containing visual evidence."""
    ev = _evidence()
    ev["visual"] = _visual_observed(**kwargs)
    return ev


class TestVisualRelationships(unittest.TestCase):

    def test_visual_edge_added_when_calibrated_and_matched(self):
        evidence = _evidence_with_visual(
            brand="ExampleBrand",
            canonical_domain="example.com",
            match_result={"verdict": "match"},
            calibration_state="calibrated",
        )
        record = analyze_relationship_graph(evidence)

        self.assertEqual(record.status, "observed")
        edges = record.observation["edges"]
        visual_edges = [e for e in edges if e["type"] == "visually_resembles_brand"]
        self.assertEqual(len(visual_edges), 1)
        edge = visual_edges[0]
        self.assertTrue(edge["source"].startswith("host:"))
        self.assertEqual(edge["target"], "brand-domain:example.com")

    def test_visual_edge_uncertainty_text_exact(self):
        evidence = _evidence_with_visual(
            brand="ExampleBrand",
            canonical_domain="example.com",
            match_result={"verdict": "match"},
            calibration_state="calibrated",
        )
        record = analyze_relationship_graph(evidence)
        edges = record.observation["edges"]
        visual_edge = next(e for e in edges if e["type"] == "visually_resembles_brand")

        expected = (
            "Visual similarity is independent structural evidence only. "
            "It does not establish phishing, impersonation, ownership, "
            "authorization, or malicious intent."
        )
        self.assertIn(expected, visual_edge["uncertainty"])

    def test_visual_uncertainty_text_within_length_limit(self):
        from intelligence.relationship_graph import MAX_GRAPH_TEXT_LENGTH
        text = (
            "Visual similarity is independent structural evidence only. "
            "It does not establish phishing, impersonation, ownership, "
            "authorization, or malicious intent."
        )
        self.assertLessEqual(len(text), MAX_GRAPH_TEXT_LENGTH)

    def test_visual_uncalibrated_no_edge(self):
        evidence = _evidence_with_visual(
            brand="ExampleBrand",
            canonical_domain="example.com",
            match_result={"verdict": "match"},
            calibration_state="uncalibrated",
        )
        record = analyze_relationship_graph(evidence)
        edges = record.observation["edges"]
        self.assertFalse(any(e["type"] == "visually_resembles_brand" for e in edges))

    def test_visual_none_match_result_no_edge(self):
        evidence = _evidence_with_visual(
            brand="ExampleBrand",
            canonical_domain="example.com",
            match_result=None,
            calibration_state="calibrated",
        )
        record = analyze_relationship_graph(evidence)
        edges = record.observation["edges"]
        self.assertFalse(any(e["type"] == "visually_resembles_brand" for e in edges))

    def test_visual_unavailable_status_no_edge(self):
        ev = _evidence()
        ev["visual"] = EvidenceRecord(
            source="visual.logo_crop",
            observation={"availability": "empty_catalog", "calibration_state": None,
                         "candidate_brand": None, "match_result": None, "evaluations": []},
            status="unavailable",
            uncertainty=["No catalog entries configured."],
        ).to_dict()
        record = analyze_relationship_graph(ev)
        edges = record.observation["edges"]
        self.assertFalse(any(e["type"] == "visually_resembles_brand" for e in edges))

    def test_visual_not_run_status_no_edge(self):
        ev = _evidence()
        ev["visual"] = EvidenceRecord(
            source="visual.logo_crop",
            observation={"availability": "no_image_uploaded"},
            status="not_run",
            uncertainty=["No image supplied."],
        ).to_dict()
        record = analyze_relationship_graph(ev)
        edges = record.observation["edges"]
        self.assertFalse(any(e["type"] == "visually_resembles_brand" for e in edges))

    def test_visual_error_status_no_edge(self):
        ev = _evidence()
        ev["visual"] = EvidenceRecord(
            source="visual.logo_crop",
            observation={"availability": "error"},
            status="error",
            uncertainty=["Processing error."],
        ).to_dict()
        record = analyze_relationship_graph(ev)
        edges = record.observation["edges"]
        self.assertFalse(any(e["type"] == "visually_resembles_brand" for e in edges))

    def test_visual_empty_evaluations_no_edge(self):
        evidence = _evidence_with_visual(
            brand="ExampleBrand",
            canonical_domain="example.com",
            match_result={"verdict": "match"},
            calibration_state="calibrated",
            evaluations=[],
        )
        record = analyze_relationship_graph(evidence)
        edges = record.observation["edges"]
        self.assertFalse(any(e["type"] == "visually_resembles_brand" for e in edges))

    def test_visual_bad_canonical_domain_no_edge_no_exception(self):
        evidence = _evidence_with_visual(
            brand="ExampleBrand",
            canonical_domain="not a valid domain!@#",
            match_result={"verdict": "match"},
            calibration_state="calibrated",
        )
        record = analyze_relationship_graph(evidence)
        self.assertIn(record.status, {"observed", "unavailable"})
        edges = record.observation["edges"]
        self.assertFalse(any(e["type"] == "visually_resembles_brand" for e in edges))

    def test_visual_no_hash_or_score_in_graph(self):
        evidence = _evidence_with_visual(
            brand="ExampleBrand",
            canonical_domain="example.com",
            match_result={"verdict": "match"},
            calibration_state="calibrated",
        )
        serialized = analyze_relationship_graph(evidence).to_json()
        for forbidden in ("phash_64", "dhash_64"):
            self.assertNotIn(forbidden, serialized)

    def test_visual_dual_edge_coexistence(self):
        evidence = _evidence_with_visual(
            brand="Google",
            canonical_domain="google.com",
            match_result={"verdict": "match"},
            calibration_state="calibrated",
        )
        record = analyze_relationship_graph(evidence)
        edges = record.observation["edges"]
        edge_types = {e["type"] for e in edges}
        self.assertIn("resembles_brand_domain", edge_types)
        self.assertIn("visually_resembles_brand", edge_types)

    def test_visual_no_edge_when_visual_key_absent(self):
        record = analyze_relationship_graph(_evidence())
        edges = record.observation["edges"]
        self.assertFalse(any(e["type"] == "visually_resembles_brand" for e in edges))

    def test_visual_handler_exception_does_not_suppress_existing_edges(self):
        """An unexpected exception in visual processing must not remove existing edges."""
        ev = _evidence()
        ev["visual"] = EvidenceRecord(
            source="visual.logo_crop",
            observation={
                "availability": "available",
                "calibration_state": "calibrated",
                "candidate_brand": "ExampleBrand",
                "match_result": {"verdict": "match"},
                "evaluations": [None],
            },
            status="observed",
            uncertainty=["Synthetic."],
        ).to_dict()
        record = analyze_relationship_graph(ev)
        edges = record.observation["edges"]
        edge_types = {e["type"] for e in edges}
        self.assertIn("resolves_to", edge_types)
        self.assertIn("resembles_brand_domain", edge_types)
        self.assertFalse(any(e["type"] == "visually_resembles_brand" for e in edges))
