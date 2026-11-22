"""
Tests for detection/evidence_fusion.py — Stage 7

Covers:
- Legitimate websites (low score)
- Suspicious websites (moderate/high signals)
- High-risk impersonation (critical signals)
- Missing / partial evidence
- Contradictory evidence
- Invalid evidence input types
- Empty input
- Duplicate signal deduplication
- ML disagreement with structural signals
- Relationship graph findings
- Output schema completeness
- Score clamping
- Risk level boundaries
- Recommended actions
- Evidence sufficiency levels
"""
import datetime
import unittest

from detection.evidence_fusion import (
    RISK_THRESHOLDS,
    fuse_evidence,
    _extract_brand_signals,
    _extract_html_signals,
    _extract_url_signals,
    _extract_domain_signals,
    _extract_tls_signals,
    _extract_graph_signals,
    _days_since,
    _risk_level,
    _score_signals,
)


# ---------------------------------------------------------------------------
# Helpers — build minimal serialised evidence records
# ---------------------------------------------------------------------------

def _brand_obs(matches=None, mixed_scripts=False, unicode_present=False):
    return {
        "source": "brand.impersonation",
        "status": "observed",
        "observation": {
            "availability": "available",
            "hostname_ascii": "example.com",
            "registrable_domain": "example.com",
            "matches": matches or [],
            "mixed_scripts_in_registrable_label": mixed_scripts,
            "unicode_present": unicode_present,
        },
        "uncertainty": ["Heuristic only."],
    }


def _html_obs(counts=None, redirect_changed_host=False, redirect_count=0):
    c = {
        "password_inputs": 0,
        "login_like_forms": 0,
        "external_form_actions": 0,
        "cross_domain_form_actions": 0,
        "invalid_form_actions": 0,
        "hidden_elements": 0,
        "external_scripts": 0,
        "iframes": 0,
        "meta_refreshes": 0,
        "external_links": 0,
        "suspicious_link_schemes": 0,
    }
    if counts:
        c.update(counts)
    return {
        "source": "html.static",
        "status": "observed",
        "observation": {
            "availability": "available",
            "original_host": "example.com",
            "page_host": "example.com",
            "redirect_changed_host": redirect_changed_host,
            "redirect_count": redirect_count,
            "analysis_truncated": False,
            "counts": c,
            "indicators": [],
        },
        "uncertainty": ["Static HTML only."],
    }


def _tls_verified():
    return {
        "source": "tls.certificate",
        "status": "observed",
        "observation": {
            "availability": "verified",
            "hostname": "example.com",
            "verification": "verified",
            "subject_alt_names": {"dns": ["example.com"], "ip": []},
        },
        "uncertainty": ["Certificate metadata describes observed endpoint."],
    }


def _tls_failed():
    return {
        "source": "tls.certificate",
        "status": "error",
        "observation": {
            "availability": "verification_failed",
            "hostname": "evil.com",
            "verification": "failed",
        },
        "uncertainty": ["Certificate verification failed."],
    }


def _domain_obs(creation_date=None):
    obs = {
        "availability": "available",
        "domain": "example.com",
        "creation_date": creation_date,
        "creation_date_timezone": "offset_known",
        "expiration_date": None,
        "expiration_date_timezone": None,
        "registrar": "Example Registrar",
        "field_issues": [],
    }
    return {
        "source": "domain.whois",
        "status": "observed",
        "observation": obs,
        "uncertainty": ["Registration data may be stale."],
    }


def _graph_obs(edge_types=None):
    edges = [{"type": t, "source": "host:a", "target": "brand-domain:b",
               "evidence_refs": [], "uncertainty": []}
             for t in (edge_types or [])]
    return {
        "source": "relationship.graph",
        "status": "observed",
        "observation": {
            "availability": "available",
            "nodes": [],
            "edges": edges,
            "truncated": False,
        },
        "uncertainty": ["Graph is bounded."],
    }


def _prediction(is_phishing: bool):
    return {
        "status": "available",
        "label": "phishing" if is_phishing else "legitimate",
        "is_phishing": is_phishing,
        "disclaimer": "Estimate only.",
    }


def _full_evidence(
    brand_matches=None,
    html_counts=None,
    tls="verified",
    creation_date=None,
    prediction=None,
    edge_types=None,
    features=None,
    mixed_scripts=False,
    redirect_changed_host=False,
):
    today = datetime.date.today()
    _default_old = (today - datetime.timedelta(days=800)).isoformat()
    ev = {
        "brand": _brand_obs(
            matches=brand_matches or [],
            mixed_scripts=mixed_scripts,
        ),
        "html": _html_obs(
            counts=html_counts,
            redirect_changed_host=redirect_changed_host,
        ),
        "tls": _tls_verified() if tls == "verified" else _tls_failed(),
        "domain": _domain_obs(creation_date=creation_date or _default_old),
        "relationships": _graph_obs(edge_types=edge_types),
        "visual": {
            "source": "visual.logo_crop",
            "status": "unavailable",
            "observation": {"availability": "empty_catalog"},
            "uncertainty": ["No catalog entries."],
        },
    }
    if prediction is not None or features is not None:
        ev["analysis"] = {
            "features": features or {
                "url_length": 25, "hostname_length": 11, "path_length": 1,
                "dot_count": 1, "hyphen_count": 0, "at_symbol_count": 0,
                "digit_count": 0, "uses_https": 1, "uses_ip_address": 0,
                "suspicious_keyword_count": 0,
            },
            "prediction": prediction,
        }
    return ev


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

class TestFuseEvidenceSchema(unittest.TestCase):
    """Every result must have all required keys with correct types."""

    REQUIRED_KEYS = {
        "risk_score", "risk_level", "verdict", "evidence_sufficiency",
        "contributing_indicators", "negative_indicators",
        "evidence_summary", "recommended_actions", "limitations",
    }

    def _check_schema(self, result):
        self.assertIsInstance(result, dict)
        self.assertEqual(self.REQUIRED_KEYS, set(result) & self.REQUIRED_KEYS,
                         "Missing required keys in fusion output")
        self.assertIsInstance(result["risk_score"], int)
        self.assertGreaterEqual(result["risk_score"], 0)
        self.assertLessEqual(result["risk_score"], 100)
        self.assertIn(result["risk_level"],
                      {"low", "moderate", "high", "critical", "inconclusive"})
        self.assertIn(result["verdict"],
                      {"likely_safe", "low_concern", "suspicious", "high_risk", "inconclusive"})
        self.assertIn(result["evidence_sufficiency"],
                      {"sufficient", "partial", "limited"})
        self.assertIsInstance(result["contributing_indicators"], list)
        self.assertIsInstance(result["negative_indicators"], list)
        self.assertIsInstance(result["recommended_actions"], list)
        self.assertIsInstance(result["limitations"], list)
        for ind in result["contributing_indicators"]:
            self.assertIn("signal_id", ind)
            self.assertIn("description", ind)
        return result

    def test_schema_legitimate_site(self):
        self._check_schema(fuse_evidence(_full_evidence()))

    def test_schema_impersonation_site(self):
        matches = [{"brand": "Google", "canonical_domain": "google.com",
                    "method": "single_character_substitution", "strength": "moderate"}]
        self._check_schema(fuse_evidence(_full_evidence(brand_matches=matches)))

    def test_schema_empty_dict(self):
        self._check_schema(fuse_evidence({}))

    def test_schema_invalid_input(self):
        self._check_schema(fuse_evidence(None))

    def test_schema_all_missing(self):
        self._check_schema(fuse_evidence({"brand": None, "html": None}))


class TestLegitimateWebsite(unittest.TestCase):
    """A clean, old domain with valid TLS should produce a low score."""

    def setUp(self):
        today = datetime.date.today()
        old_date = (today - datetime.timedelta(days=1000)).isoformat()
        self.result = fuse_evidence(_full_evidence(creation_date=old_date))

    def test_risk_score_is_low(self):
        self.assertLessEqual(self.result["risk_score"], 24)

    def test_risk_level_is_low(self):
        self.assertEqual(self.result["risk_level"], "low")

    def test_verdict_is_likely_safe(self):
        self.assertEqual(self.result["verdict"], "likely_safe")

    def test_no_contributing_indicators(self):
        self.assertEqual(self.result["contributing_indicators"], [])

    def test_negative_indicators_present(self):
        neg_ids = {n["signal_id"] for n in self.result["negative_indicators"]}
        self.assertIn("tls_verified", neg_ids)
        self.assertIn("domain_established", neg_ids)


class TestHighRiskImpersonation(unittest.TestCase):
    """
    A domain with Unicode confusable characters, a cross-domain login form,
    a new domain, and a failed TLS certificate should score critically.
    """

    def setUp(self):
        today = datetime.date.today()
        new_date = (today - datetime.timedelta(days=10)).isoformat()
        matches = [{
            "brand": "Google",
            "canonical_domain": "google.com",
            "method": "unicode_confusable_skeleton",
            "strength": "strong_candidate",
        }]
        self.result = fuse_evidence(_full_evidence(
            brand_matches=matches,
            mixed_scripts=True,
            html_counts={
                "password_inputs": 1,
                "login_like_forms": 1,
                "cross_domain_form_actions": 1,
                "external_form_actions": 1,
                "invalid_form_actions": 0,
                "hidden_elements": 0,
                "external_scripts": 0,
                "iframes": 0,
                "meta_refreshes": 1,
                "external_links": 0,
                "suspicious_link_schemes": 0,
            },
            tls="failed",
            creation_date=new_date,
            prediction=_prediction(True),
            features={
                "url_length": 120,
                "hostname_length": 20,
                "path_length": 50,
                "dot_count": 5,
                "hyphen_count": 4,
                "at_symbol_count": 0,
                "digit_count": 3,
                "uses_https": 0,
                "uses_ip_address": 0,
                "suspicious_keyword_count": 3,
            },
        ))

    def test_risk_score_is_high(self):
        self.assertGreaterEqual(self.result["risk_score"], 50)

    def test_risk_level_is_not_low(self):
        self.assertNotEqual(self.result["risk_level"], "low")

    def test_verdict_is_suspicious_or_high(self):
        self.assertIn(self.result["verdict"],
                      {"suspicious", "high_risk"})

    def test_brand_signal_present(self):
        ids = {i["signal_id"] for i in self.result["contributing_indicators"]}
        self.assertIn("brand_unicode_confusable", ids)
        self.assertIn("brand_mixed_scripts", ids)

    def test_html_signal_present(self):
        ids = {i["signal_id"] for i in self.result["contributing_indicators"]}
        self.assertIn("html_cross_domain_form", ids)

    def test_domain_age_signal_present(self):
        ids = {i["signal_id"] for i in self.result["contributing_indicators"]}
        self.assertIn("domain_very_new", ids)

    def test_tls_signal_present(self):
        ids = {i["signal_id"] for i in self.result["contributing_indicators"]}
        self.assertIn("tls_verification_failed", ids)

    def test_recommended_actions_non_empty(self):
        self.assertTrue(len(self.result["recommended_actions"]) >= 2)


class TestSuspiciousWebsite(unittest.TestCase):
    """Moderate signals: brand token in subdomain + login form."""

    def setUp(self):
        today = datetime.date.today()
        date_60 = (today - datetime.timedelta(days=60)).isoformat()
        matches = [{
            "brand": "PayPal",
            "canonical_domain": "paypal.com",
            "method": "brand_token_in_subdomain",
            "strength": "weak",
        }]
        self.result = fuse_evidence(_full_evidence(
            brand_matches=matches,
            html_counts={"login_like_forms": 1, "password_inputs": 1},
            creation_date=date_60,
        ))

    def test_score_above_low_threshold(self):
        self.assertGreater(self.result["risk_score"], 10)

    def test_has_contributing_indicators(self):
        self.assertTrue(len(self.result["contributing_indicators"]) > 0)


class TestMissingEvidence(unittest.TestCase):
    """When all evidence is None, should not crash and return limited sufficiency."""

    def setUp(self):
        self.result = fuse_evidence({
            "brand": None,
            "html": None,
            "tls": None,
            "domain": None,
            "relationships": None,
            "visual": None,
        })

    def test_no_crash(self):
        self.assertIsInstance(self.result, dict)

    def test_evidence_sufficiency_limited(self):
        self.assertEqual(self.result["evidence_sufficiency"], "limited")

    def test_score_bounded(self):
        self.assertGreaterEqual(self.result["risk_score"], 0)
        self.assertLessEqual(self.result["risk_score"], 100)


class TestPartialEvidence(unittest.TestCase):
    """Brand record present but TLS/HTML not observed."""

    def setUp(self):
        matches = [{
            "brand": "Microsoft",
            "canonical_domain": "microsoft.com",
            "method": "exact_brand_label_different_domain",
            "strength": "moderate",
        }]
        self.result = fuse_evidence({
            "brand": _brand_obs(matches=matches),
            "html": {"source": "html.static", "status": "unavailable",
                     "observation": {"availability": "https_required"}, "uncertainty": []},
            "tls": None,
            "domain": None,
        })

    def test_has_brand_signal(self):
        ids = {i["signal_id"] for i in self.result["contributing_indicators"]}
        self.assertIn("brand_exact_label_different_tld", ids)

    def test_evidence_sufficiency_partial_or_limited(self):
        self.assertIn(self.result["evidence_sufficiency"], {"partial", "limited"})


class TestContradictoryEvidence(unittest.TestCase):
    """
    ML says legitimate, but structural signals say suspicious.
    The structural signals should still raise the score meaningfully.
    """

    def setUp(self):
        matches = [{
            "brand": "Amazon",
            "canonical_domain": "amazon.com",
            "method": "single_character_substitution",
            "strength": "moderate",
        }]
        self.result = fuse_evidence(_full_evidence(
            brand_matches=matches,
            prediction=_prediction(False),  # ML says legitimate
            features={
                "url_length": 80,
                "hostname_length": 15,
                "path_length": 20,
                "dot_count": 3,
                "hyphen_count": 2,
                "at_symbol_count": 0,
                "digit_count": 1,
                "uses_https": 1,
                "uses_ip_address": 0,
                "suspicious_keyword_count": 1,
            },
        ))

    def test_ml_negative_indicator_present(self):
        neg_ids = {n["signal_id"] for n in self.result["negative_indicators"]}
        self.assertIn("ml_predicts_legitimate", neg_ids)

    def test_brand_signal_still_present(self):
        ids = {i["signal_id"] for i in self.result["contributing_indicators"]}
        self.assertIn("brand_single_char_substitution", ids)

    def test_score_above_zero(self):
        # Brand signal should contribute despite ML saying legitimate
        self.assertGreater(self.result["risk_score"], 0)


class TestInvalidEvidenceInput(unittest.TestCase):

    def test_none_input_returns_valid_dict(self):
        result = fuse_evidence(None)
        self.assertIsInstance(result, dict)
        self.assertIn("risk_score", result)

    def test_string_input_returns_valid_dict(self):
        result = fuse_evidence("not a dict")
        self.assertIsInstance(result, dict)

    def test_list_input_returns_valid_dict(self):
        result = fuse_evidence([1, 2, 3])
        self.assertIsInstance(result, dict)

    def test_int_input_returns_valid_dict(self):
        result = fuse_evidence(42)
        self.assertIsInstance(result, dict)

    def test_invalid_brand_record_no_crash(self):
        result = fuse_evidence({"brand": "not a dict"})
        self.assertIsInstance(result, dict)

    def test_invalid_html_counts_no_crash(self):
        result = fuse_evidence({
            "html": {
                "source": "html.static",
                "status": "observed",
                "observation": {"availability": "available", "counts": "wrong type"},
                "uncertainty": [],
            }
        })
        self.assertIsInstance(result, dict)


class TestEmptyInput(unittest.TestCase):

    def test_empty_dict_returns_valid_assessment(self):
        result = fuse_evidence({})
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["risk_level"], "inconclusive")
        self.assertEqual(result["verdict"], "inconclusive")
        self.assertEqual(result["assessment_state"], "inconclusive")


class TestDuplicateIndicators(unittest.TestCase):
    """
    Passing the same brand match twice should not double-count the signal.
    """

    def test_same_method_does_not_double_count(self):
        matches = [
            {"brand": "Google", "canonical_domain": "google.com",
             "method": "single_character_substitution", "strength": "moderate"},
            {"brand": "Google", "canonical_domain": "google.com",
             "method": "single_character_substitution", "strength": "moderate"},
        ]
        result = fuse_evidence(_full_evidence(brand_matches=matches))
        ids = [i["signal_id"] for i in result["contributing_indicators"]]
        self.assertEqual(ids.count("brand_single_char_substitution"), 1,
                         "Same signal should not appear more than once")


class TestMLDisagreement(unittest.TestCase):
    """ML predicting phishing should add a signal even with no structural signals."""

    def test_ml_phishing_adds_signal(self):
        result = fuse_evidence(_full_evidence(
            prediction=_prediction(True),
            features={
                "url_length": 25, "hostname_length": 11, "path_length": 1,
                "dot_count": 1, "hyphen_count": 0, "at_symbol_count": 0,
                "digit_count": 0, "uses_https": 1, "uses_ip_address": 0,
                "suspicious_keyword_count": 0,
            },
        ))
        ids = {i["signal_id"] for i in result["contributing_indicators"]}
        self.assertIn("ml_predicts_phishing", ids)

    def test_ml_legitimate_adds_negative(self):
        result = fuse_evidence(_full_evidence(
            prediction=_prediction(False),
        ))
        neg_ids = {n["signal_id"] for n in result["negative_indicators"]}
        self.assertIn("ml_predicts_legitimate", neg_ids)

    def test_ml_unavailable_does_not_add_signal(self):
        result = fuse_evidence(_full_evidence(
            prediction={"status": "unavailable", "error": "Model missing."},
        ))
        ids = {i["signal_id"] for i in result["contributing_indicators"]}
        self.assertNotIn("ml_predicts_phishing", ids)


class TestRelationshipGraphSignals(unittest.TestCase):

    def test_resembles_brand_domain_edge_adds_signal(self):
        result = fuse_evidence(_full_evidence(
            edge_types=["resembles_brand_domain"]
        ))
        ids = {i["signal_id"] for i in result["contributing_indicators"]}
        self.assertIn("graph_resembles_brand_domain", ids)

    def test_no_brand_edge_no_graph_signal(self):
        result = fuse_evidence(_full_evidence(edge_types=["resolves_to"]))
        ids = {i["signal_id"] for i in result["contributing_indicators"]}
        self.assertNotIn("graph_resembles_brand_domain", ids)

    def test_empty_edges_no_graph_signal(self):
        result = fuse_evidence(_full_evidence(edge_types=[]))
        ids = {i["signal_id"] for i in result["contributing_indicators"]}
        self.assertNotIn("graph_resembles_brand_domain", ids)


class TestScoreBoundaries(unittest.TestCase):

    def test_score_never_below_zero(self):
        result = fuse_evidence({})
        self.assertGreaterEqual(result["risk_score"], 0)

    def test_score_never_above_100(self):
        # Pile on every positive signal by crafting worst-case evidence
        today = datetime.date.today()
        new_date = (today - datetime.timedelta(days=5)).isoformat()
        matches = [
            {"brand": "Google", "canonical_domain": "google.com",
             "method": "unicode_confusable_skeleton", "strength": "strong_candidate"},
            {"brand": "Microsoft", "canonical_domain": "microsoft.com",
             "method": "single_character_substitution", "strength": "moderate"},
        ]
        result = fuse_evidence(_full_evidence(
            brand_matches=matches,
            mixed_scripts=True,
            html_counts={
                "password_inputs": 5, "login_like_forms": 3,
                "cross_domain_form_actions": 5, "external_form_actions": 5,
                "invalid_form_actions": 2, "hidden_elements": 20,
                "external_scripts": 10, "iframes": 5,
                "meta_refreshes": 3, "external_links": 10,
                "suspicious_link_schemes": 5,
            },
            tls="failed",
            creation_date=new_date,
            prediction=_prediction(True),
            features={
                "url_length": 250, "hostname_length": 80, "path_length": 100,
                "dot_count": 8, "hyphen_count": 10, "at_symbol_count": 2,
                "digit_count": 20, "uses_https": 0, "uses_ip_address": 1,
                "suspicious_keyword_count": 8,
            },
            edge_types=["resembles_brand_domain"],
        ))
        self.assertLessEqual(result["risk_score"], 100)

    def test_risk_level_boundaries(self):
        for level, (lo, hi) in RISK_THRESHOLDS.items():
            self.assertEqual(_risk_level(lo), level,
                             f"lower bound of {level} should map to {level}")
            self.assertEqual(_risk_level(hi), level,
                             f"upper bound of {level} should map to {level}")

    def test_risk_level_boundaries_adjacent(self):
        self.assertEqual(_risk_level(24), "low")
        self.assertEqual(_risk_level(25), "moderate")
        self.assertEqual(_risk_level(49), "moderate")
        self.assertEqual(_risk_level(50), "high")
        self.assertEqual(_risk_level(74), "high")
        self.assertEqual(_risk_level(75), "critical")


class TestUnitExtractors(unittest.TestCase):
    """Unit tests for individual signal extractors."""

    def test_days_since_recent(self):
        today = datetime.date.today()
        date_str = (today - datetime.timedelta(days=15)).isoformat()
        days = _days_since(date_str)
        self.assertIsNotNone(days)
        self.assertGreaterEqual(days, 14)
        self.assertLessEqual(days, 16)

    def test_days_since_none(self):
        self.assertIsNone(_days_since(None))

    def test_days_since_invalid(self):
        self.assertIsNone(_days_since("not-a-date"))

    def test_extract_brand_no_matches(self):
        signals = _extract_brand_signals(_brand_obs())
        self.assertEqual(signals, [])

    def test_extract_brand_unicode_confusable(self):
        matches = [{"brand": "Google", "canonical_domain": "google.com",
                    "method": "unicode_confusable_skeleton", "strength": "strong_candidate"}]
        signals = _extract_brand_signals(_brand_obs(matches=matches))
        self.assertIn("brand_unicode_confusable", signals)

    def test_extract_brand_canonical_no_signal(self):
        # canonical_domain_or_subdomain is not suspicious
        matches = [{"brand": "Google", "canonical_domain": "google.com",
                    "method": "canonical_domain_or_subdomain", "strength": "catalog_reference"}]
        signals = _extract_brand_signals(_brand_obs(matches=matches))
        self.assertNotIn("brand_unicode_confusable", signals)

    def test_extract_html_cross_domain_form(self):
        signals = _extract_html_signals(
            _html_obs(counts={"cross_domain_form_actions": 1, "external_form_actions": 1})
        )
        self.assertIn("html_cross_domain_form", signals)
        self.assertNotIn("html_external_form", signals,
                         "cross_domain is higher-specificity; external should not double-count")

    def test_extract_html_no_signals(self):
        signals = _extract_html_signals(_html_obs())
        self.assertEqual(signals, [])

    def test_extract_url_ip_address(self):
        signals = _extract_url_signals({"uses_ip_address": 1, "url_length": 20,
                                         "hostname_length": 15, "path_length": 1,
                                         "dot_count": 0, "hyphen_count": 0,
                                         "at_symbol_count": 0, "digit_count": 10,
                                         "uses_https": 0, "suspicious_keyword_count": 0})
        self.assertIn("url_uses_ip_address", signals)

    def test_extract_url_no_signals(self):
        signals = _extract_url_signals({"uses_ip_address": 0, "url_length": 25,
                                         "hostname_length": 11, "path_length": 1,
                                         "dot_count": 1, "hyphen_count": 0,
                                         "at_symbol_count": 0, "digit_count": 0,
                                         "uses_https": 1, "suspicious_keyword_count": 0})
        self.assertEqual(signals, [])

    def test_extract_tls_verified(self):
        pos, neg = _extract_tls_signals(_tls_verified())
        self.assertEqual(pos, [])
        self.assertIn("tls_verified", neg)

    def test_extract_tls_failed(self):
        pos, neg = _extract_tls_signals(_tls_failed())
        self.assertIn("tls_verification_failed", pos)
        self.assertEqual(neg, [])

    def test_extract_domain_new(self):
        today = datetime.date.today()
        date_str = (today - datetime.timedelta(days=20)).isoformat()
        signals = _extract_domain_signals(_domain_obs(creation_date=date_str))
        self.assertIn("domain_very_new", signals)

    def test_extract_domain_old(self):
        today = datetime.date.today()
        date_str = (today - datetime.timedelta(days=1000)).isoformat()
        signals = _extract_domain_signals(_domain_obs(creation_date=date_str))
        self.assertEqual(signals, [])

    def test_extract_graph_brand_edge(self):
        signals = _extract_graph_signals(_graph_obs(["resembles_brand_domain"]))
        self.assertIn("graph_resembles_brand_domain", signals)

    def test_extract_graph_no_brand_edge(self):
        signals = _extract_graph_signals(_graph_obs(["resolves_to", "links_to"]))
        self.assertEqual(signals, [])

    def test_score_signals_clamped(self):
        # Passing the same high-weight signal 100 times should not exceed 100
        signals = ["brand_unicode_confusable"] * 100
        score = _score_signals(signals, [])
        self.assertLessEqual(score, 100)


class TestRecommendedActions(unittest.TestCase):

    def test_critical_risk_recommends_leaving_page(self):
        today = datetime.date.today()
        new_date = (today - datetime.timedelta(days=5)).isoformat()
        matches = [{"brand": "Google", "canonical_domain": "google.com",
                    "method": "unicode_confusable_skeleton", "strength": "strong_candidate"}]
        result = fuse_evidence(_full_evidence(
            brand_matches=matches,
            tls="failed",
            creation_date=new_date,
            html_counts={"cross_domain_form_actions": 1, "login_like_forms": 1,
                         "password_inputs": 1},
        ))
        actions_text = " ".join(result["recommended_actions"]).lower()
        self.assertIn("credentials", actions_text)

    def test_low_risk_produces_at_least_one_action(self):
        result = fuse_evidence(_full_evidence())
        self.assertGreaterEqual(len(result["recommended_actions"]), 1)


class TestEvidenceSufficiency(unittest.TestCase):

    def test_all_sources_observed_is_sufficient(self):
        today = datetime.date.today()
        old = (today - datetime.timedelta(days=800)).isoformat()
        ev = _full_evidence(creation_date=old)
        # Add DNS
        ev["dns"] = {"A": {
            "source": "dns.a", "status": "observed",
            "observation": {"availability": "available", "addresses": ["1.2.3.4"]},
            "uncertainty": [],
        }}
        result = fuse_evidence(ev)
        self.assertEqual(result["evidence_sufficiency"], "sufficient")

    def test_empty_dict_is_limited(self):
        result = fuse_evidence({})
        self.assertEqual(result["evidence_sufficiency"], "limited")


class TestAPIIntegration(unittest.TestCase):
    """
    Verify that the Flask /api/analyze/deeper route includes risk_assessment
    in its response without breaking the existing evidence key.
    """

    def setUp(self):
        from app import create_app
        self.client = create_app().test_client()

    def test_deeper_response_includes_risk_assessment_key(self):
        from unittest.mock import patch, MagicMock
        from detection.evidence import EvidenceRecord
        from intelligence.relationship_graph import analyze_relationship_graph

        def _mock_evidence(*a, **kw):
            return EvidenceRecord(
                source="html.static",
                observation={"availability": "https_required"},
                status="unavailable",
                uncertainty=["HTTPS required."],
            )

        def _mock_dns(*a, **kw):
            return {
                t: EvidenceRecord(
                    source=f"dns.{t.lower()}",
                    observation={"availability": "unavailable"},
                    status="unavailable",
                    uncertainty=["Not resolved."],
                )
                for t in ("A", "AAAA", "MX", "NS", "TXT")
            }

        with patch("app.routes.fetch_html", side_effect=Exception("no fetch")), \
             patch("app.routes.analyze_html_document", return_value=_mock_evidence()), \
             patch("app.routes.lookup_dns", return_value=_mock_dns()), \
             patch("app.routes.lookup_domain_registration", return_value=_mock_evidence()), \
             patch("app.routes.analyze_tls_certificate", return_value=_mock_evidence()), \
             patch("app.routes.analyze_brand_impersonation", return_value=EvidenceRecord(
                 source="brand.impersonation",
                 observation={"availability": "available", "hostname_ascii": "example.com",
                              "registrable_domain": "example.com",
                              "matches": [], "mixed_scripts_in_registrable_label": False,
                              "unicode_present": False},
                 status="observed",
                 uncertainty=["Heuristic only."],
             )), \
             patch("app.routes.analyze_relationship_graph", return_value=EvidenceRecord(
                 source="relationship.graph",
                 observation={"availability": "no_relationships", "nodes": [],
                              "edges": [], "truncated": False},
                 status="unavailable",
                 uncertainty=["No relationships found."],
             )), \
             patch("app.routes.predict_url_features",
                   return_value={"status": "available", "label": "legitimate",
                                 "is_phishing": False, "disclaimer": "Estimate only."}):

            response = self.client.post(
                "/api/analyze/deeper",
                json={"url": "https://example.com/"}
            )

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertTrue(body["success"])
        self.assertIn("evidence", body)
        self.assertIn("risk_assessment", body, "risk_assessment must be in /deeper response")
        ra = body["risk_assessment"]
        self.assertIn("risk_score", ra)
        self.assertIn("risk_level", ra)
        self.assertIn("contributing_indicators", ra)

    def test_deeper_response_evidence_key_preserved(self):
        """Existing evidence key must still be present and contain the same sub-keys."""
        from unittest.mock import patch
        from detection.evidence import EvidenceRecord

        def _er(source):
            return EvidenceRecord(
                source=source, observation={"availability": "unavailable"},
                status="unavailable", uncertainty=["Unavailable."],
            )

        with patch("app.routes.fetch_html", side_effect=Exception("no")), \
             patch("app.routes.analyze_html_document", return_value=_er("html.static")), \
             patch("app.routes.lookup_dns", return_value={
                 t: _er(f"dns.{t.lower()}") for t in ("A","AAAA","MX","NS","TXT")}), \
             patch("app.routes.lookup_domain_registration", return_value=_er("domain.whois")), \
             patch("app.routes.analyze_tls_certificate", return_value=_er("tls.certificate")), \
             patch("app.routes.analyze_brand_impersonation", return_value=EvidenceRecord(
                 source="brand.impersonation",
                 observation={"availability": "available", "hostname_ascii": "x.com",
                              "registrable_domain": "x.com",
                              "matches": [], "mixed_scripts_in_registrable_label": False,
                              "unicode_present": False},
                 status="observed", uncertainty=["Heuristic."])), \
             patch("app.routes.analyze_relationship_graph", return_value=_er("relationship.graph")), \
             patch("app.routes.predict_url_features", side_effect=Exception("no model")):

            response = self.client.post(
                "/api/analyze/deeper",
                json={"url": "https://example.com/"}
            )

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertIn("evidence", body)
        for key in ("html", "dns", "domain", "tls", "brand", "relationships"):
            self.assertIn(key, body["evidence"], f"evidence.{key} must still be present")


class TestAllSourcesUnavailable(unittest.TestCase):
    """When all telemetry sources are unavailable or not run, assessment must be inconclusive."""

    def setUp(self):
        self.result = fuse_evidence({
            "html": {"source": "html.static", "status": "unavailable", "observation": {}},
            "dns": {"A": {"source": "dns.a", "status": "unavailable", "observation": {}}},
            "domain": {"source": "domain.whois", "status": "unavailable", "observation": {}},
            "tls": {"source": "tls.cert", "status": "unavailable", "observation": {}},
            "brand": {"source": "brand.detector", "status": "unavailable", "observation": {}},
            "visual": {"source": "visual.logo_crop", "status": "not_run", "observation": {}},
            "relationships": {"source": "graph.topology", "status": "not_run", "observation": {}},
        })

    def test_verdict_is_inconclusive(self):
        self.assertEqual(self.result["verdict"], "inconclusive")

    def test_evidence_sufficiency_is_limited(self):
        self.assertEqual(self.result["evidence_sufficiency"], "limited")

    def test_no_false_reassuring_indicators(self):
        neg_ids = {n["signal_id"] for n in self.result["negative_indicators"]}
        self.assertNotIn("no_brand_matches", neg_ids)
        self.assertNotIn("url_uses_https", neg_ids)
        self.assertNotIn("domain_established", neg_ids)
        self.assertNotIn("tls_verified", neg_ids)

    def test_no_invented_suspicious_indicators(self):
        self.assertEqual(self.result["contributing_indicators"], [])


class TestDnsAndTlsFailures(unittest.TestCase):
    """Failed or absent DNS/TLS must not be treated as proof of safety."""

    def setUp(self):
        self.result = fuse_evidence({
            "html": {"source": "html.static", "status": "destination_rejected", "observation": {"availability": "destination_rejected"}},
            "dns": {"A": {"source": "dns.a", "status": "domain_absent", "observation": {"availability": "domain_absent"}}},
            "domain": {"source": "domain.whois", "status": "invalid_input", "observation": {"availability": "invalid_input"}},
            "tls": {"source": "tls.cert", "status": "destination_rejected", "observation": {"availability": "destination_rejected"}},
            "brand": {"source": "brand.detector", "status": "unavailable", "observation": {"availability": "unavailable"}},
            "relationships": {"source": "graph.topology", "status": "no_relationships", "observation": {"nodes": [], "edges": []}},
            "visual": {"source": "visual.logo_crop", "status": "not_run", "observation": {}},
            "analysis": {
                "features": {"uses_https": 1, "url_length": 38, "hostname_length": 28},
                "prediction": {"label": 0, "prediction": "legitimate", "confidence": 0.8},
            }
        })

    def test_verdict_is_not_likely_safe(self):
        self.assertNotEqual(self.result["verdict"], "likely_safe")
        self.assertEqual(self.result["verdict"], "inconclusive")

    def test_negative_indicators_do_not_claim_safety(self):
        neg_ids = {n["signal_id"] for n in self.result["negative_indicators"]}
        self.assertNotIn("no_brand_matches", neg_ids)
        self.assertNotIn("url_uses_https", neg_ids)
        self.assertNotIn("tls_verified", neg_ids)


class TestBrandUnavailable(unittest.TestCase):
    """When brand detection is unavailable or fails, no_brand_matches must NOT be claimed."""

    def test_brand_unavailable_status(self):
        result = fuse_evidence({
            "brand": {"source": "brand.detector", "status": "unavailable", "observation": {}}
        })
        neg_ids = {n["signal_id"] for n in result["negative_indicators"]}
        self.assertNotIn("no_brand_matches", neg_ids)

    def test_brand_error_status(self):
        result = fuse_evidence({
            "brand": {"source": "brand.detector", "status": "error", "observation": {"availability": "error"}}
        })
        neg_ids = {n["signal_id"] for n in result["negative_indicators"]}
        self.assertNotIn("no_brand_matches", neg_ids)

    def test_brand_not_run_status(self):
        result = fuse_evidence({
            "brand": {"source": "brand.detector", "status": "not_run", "observation": {}}
        })
        neg_ids = {n["signal_id"] for n in result["negative_indicators"]}
        self.assertNotIn("no_brand_matches", neg_ids)


class TestOnlyHttpsAndMLLegitimate(unittest.TestCase):
    """Only HTTPS in URL features and ML legitimate estimate with deeper sources unavailable."""

    def setUp(self):
        self.result = fuse_evidence({
            "analysis": {
                "features": {"uses_https": 1, "url_length": 20},
                "prediction": {"label": 0, "prediction": "legitimate", "confidence": 0.95},
            },
            "tls": {"source": "tls.cert", "status": "unavailable", "observation": {}},
            "html": {"source": "html.static", "status": "unavailable", "observation": {}},
            "brand": {"source": "brand.detector", "status": "unavailable", "observation": {}},
            "domain": {"source": "domain.whois", "status": "unavailable", "observation": {}},
        })

    def test_sufficiency_is_limited(self):
        self.assertEqual(self.result["evidence_sufficiency"], "limited")

    def test_verdict_is_inconclusive(self):
        self.assertEqual(self.result["verdict"], "inconclusive")

    def test_url_uses_https_not_claimed(self):
        neg_ids = {n["signal_id"] for n in self.result["negative_indicators"]}
        self.assertNotIn("url_uses_https", neg_ids)


class TestGenuinelySufficientReassuring(unittest.TestCase):
    """4+ observed sources, TLS verified, domain established, brand observed with 0 matches."""

    def setUp(self):
        today = datetime.date.today()
        old_date = (today - datetime.timedelta(days=1200)).isoformat()
        self.result = fuse_evidence(_full_evidence(
            creation_date=old_date,
            tls="verified",
            brand_matches=[],
            features={
                "uses_https": 1,
                "url_length": 25,
                "hostname_length": 12,
                "path_length": 1,
                "hyphen_count": 0,
                "dot_count": 1,
                "at_symbol_count": 0,
                "digit_count": 0,
                "suspicious_keyword_count": 0,
                "uses_ip_address": 0,
            },
        ))

    def test_sufficiency_is_sufficient(self):
        self.assertEqual(self.result["evidence_sufficiency"], "sufficient")

    def test_verdict_is_likely_safe(self):
        self.assertEqual(self.result["verdict"], "likely_safe")

    def test_reassuring_indicators_present(self):
        neg_ids = {n["signal_id"] for n in self.result["negative_indicators"]}
        self.assertIn("tls_verified", neg_ids)
        self.assertIn("domain_established", neg_ids)
        self.assertIn("no_brand_matches", neg_ids)
        self.assertIn("url_uses_https", neg_ids)


class TestGenuinelySuspicious(unittest.TestCase):
    """Brand confusable or cross-domain form leads to suspicious or high_risk verdict."""

    def test_brand_confusable_is_suspicious_or_high(self):
        result = fuse_evidence(_full_evidence(
            brand_matches=[{
                "brand": "PayPal",
                "canonical_domain": "paypal.com",
                "method": "unicode_confusable_skeleton",
                "strength": "strong_candidate",
            }],
            mixed_scripts=True,
        ))
        self.assertIn(result["verdict"], {"suspicious", "high_risk"})
        pos_ids = {c["signal_id"] for c in result["contributing_indicators"]}
        self.assertIn("brand_unicode_confusable", pos_ids)

    def test_cross_domain_login_form_is_suspicious_or_high(self):
        result = fuse_evidence(_full_evidence(
            html_counts={
                "password_inputs": 1,
                "login_like_forms": 1,
                "cross_domain_form_actions": 1,
                "external_form_actions": 1,
                "invalid_form_actions": 0,
                "hidden_elements": 0,
                "external_scripts": 0,
                "iframes": 0,
                "meta_refreshes": 0,
                "external_links": 0,
                "suspicious_link_schemes": 0,
            }
        ))
        self.assertIn(result["verdict"], {"suspicious", "high_risk"})
        pos_ids = {c["signal_id"] for c in result["contributing_indicators"]}
        self.assertIn("html_cross_domain_form", pos_ids)


class TestEmptyAssessmentRiskLevel(unittest.TestCase):
    """_empty_assessment() and non-dict inputs must never report risk_level 'low'."""

    def test_none_input_risk_level_not_low(self):
        result = fuse_evidence(None)
        self.assertEqual(result["verdict"], "inconclusive")
        self.assertEqual(result["risk_level"], "inconclusive")
        self.assertEqual(result["assessment_state"], "inconclusive")

    def test_string_input_risk_level_not_low(self):
        result = fuse_evidence("not a dict")
        self.assertEqual(result["verdict"], "inconclusive")
        self.assertEqual(result["risk_level"], "inconclusive")

    def test_list_input_risk_level_not_low(self):
        result = fuse_evidence([1, 2, 3])
        self.assertEqual(result["verdict"], "inconclusive")
        self.assertEqual(result["risk_level"], "inconclusive")

    def test_int_input_risk_level_not_low(self):
        result = fuse_evidence(42)
        self.assertEqual(result["verdict"], "inconclusive")
        self.assertEqual(result["risk_level"], "inconclusive")


class TestInconclusiveZeroScore(unittest.TestCase):
    """Zero-score inconclusive assessments must not display as LOW RISK."""

    def setUp(self):
        self.result = fuse_evidence({
            "html": {"source": "html.static", "status": "unavailable", "observation": {}},
            "dns": {"A": {"source": "dns.a", "status": "unavailable", "observation": {}}},
            "domain": {"source": "domain.whois", "status": "unavailable", "observation": {}},
            "tls": {"source": "tls.cert", "status": "unavailable", "observation": {}},
            "brand": {"source": "brand.detector", "status": "unavailable", "observation": {}},
            "visual": {"source": "visual.logo_crop", "status": "not_run", "observation": {}},
            "relationships": {"source": "graph.topology", "status": "not_run", "observation": {}},
        })

    def test_score_is_zero(self):
        self.assertEqual(self.result["risk_score"], 0)

    def test_verdict_is_inconclusive(self):
        self.assertEqual(self.result["verdict"], "inconclusive")

    def test_risk_level_not_low(self):
        self.assertNotEqual(self.result["risk_level"], "low")
        self.assertEqual(self.result["risk_level"], "inconclusive")

    def test_assessment_state_inconclusive(self):
        self.assertEqual(self.result["assessment_state"], "inconclusive")


class TestConclusiveLowRisk(unittest.TestCase):
    """Genuine conclusive low-risk assessment: old domain, verified TLS, no brand matches."""

    def setUp(self):
        today = datetime.date.today()
        old_date = (today - datetime.timedelta(days=1000)).isoformat()
        self.result = fuse_evidence(_full_evidence(creation_date=old_date))

    def test_score_is_low(self):
        self.assertLessEqual(self.result["risk_score"], 24)

    def test_risk_level_is_low(self):
        self.assertEqual(self.result["risk_level"], "low")

    def test_verdict_is_likely_safe(self):
        self.assertEqual(self.result["verdict"], "likely_safe")

    def test_assessment_state_is_conclusive(self):
        self.assertEqual(self.result["assessment_state"], "conclusive")

    def test_negative_indicators_present(self):
        neg_ids = {n["signal_id"] for n in self.result["negative_indicators"]}
        self.assertIn("tls_verified", neg_ids)
        self.assertIn("domain_established", neg_ids)


class TestConclusiveHighRisk(unittest.TestCase):
    """Genuine conclusive high-risk impersonation with all evidence sources observed."""

    def setUp(self):
        today = datetime.date.today()
        new_date = (today - datetime.timedelta(days=10)).isoformat()
        matches = [{
            "brand": "Google",
            "canonical_domain": "google.com",
            "method": "unicode_confusable_skeleton",
            "strength": "strong_candidate",
        }]
        self.result = fuse_evidence(_full_evidence(
            brand_matches=matches,
            mixed_scripts=True,
            html_counts={
                "password_inputs": 1,
                "login_like_forms": 1,
                "cross_domain_form_actions": 1,
                "external_form_actions": 1,
                "invalid_form_actions": 0,
                "hidden_elements": 0,
                "external_scripts": 0,
                "iframes": 0,
                "meta_refreshes": 1,
                "external_links": 0,
                "suspicious_link_schemes": 0,
            },
            tls="failed",
            creation_date=new_date,
            prediction=_prediction(True),
            features={
                "url_length": 120,
                "hostname_length": 20,
                "path_length": 50,
                "dot_count": 5,
                "hyphen_count": 4,
                "at_symbol_count": 0,
                "digit_count": 3,
                "uses_https": 0,
                "uses_ip_address": 0,
                "suspicious_keyword_count": 3,
            },
        ))

    def test_score_is_high(self):
        self.assertGreaterEqual(self.result["risk_score"], 50)

    def test_verdict_is_suspicious_or_high(self):
        self.assertIn(self.result["verdict"], {"suspicious", "high_risk"})

    def test_assessment_state_is_conclusive(self):
        self.assertEqual(self.result["assessment_state"], "conclusive")

    def test_risk_level_not_low(self):
        self.assertNotEqual(self.result["risk_level"], "low")


class TestHtmlCoverageRequiredForLikelySafe(unittest.TestCase):
    """HTML must be observed before a "likely_safe" verdict can be returned."""

    def _make_evidence(self, html_status, html_availability="https_required"):
        today = datetime.date.today()
        old_date = (today - datetime.timedelta(days=1000)).isoformat()
        return {
            "brand": _brand_obs(matches=[]),
            "html": {
                "source": "html.static",
                "status": html_status,
                "observation": {"availability": html_availability},
                "uncertainty": ["HTML retrieval failed."],
            },
            "tls": _tls_verified(),
            "domain": _domain_obs(creation_date=old_date),
            "dns": {
                "A": {
                    "source": "dns.a",
                    "status": "observed",
                    "observation": {"availability": "available", "addresses": ["1.2.3.4"]},
                    "uncertainty": [],
                }
            },
            "relationships": _graph_obs(),
            "visual": {
                "source": "visual.logo_crop",
                "status": "not_run",
                "observation": {},
                "uncertainty": [],
            },
            "analysis": {
                "features": {
                    "url_length": 25,
                    "hostname_length": 11,
                    "path_length": 1,
                    "dot_count": 1,
                    "hyphen_count": 0,
                    "at_symbol_count": 0,
                    "digit_count": 0,
                    "uses_https": 1,
                    "uses_ip_address": 0,
                    "suspicious_keyword_count": 0,
                },
                "prediction": {
                    "status": "available",
                    "label": "legitimate",
                    "is_phishing": False,
                    "disclaimer": "Estimate only.",
                },
            },
        }

    def test_html_error_prevents_likely_safe(self):
        result = fuse_evidence(self._make_evidence("error"))
        self.assertEqual(result["verdict"], "inconclusive")
        self.assertEqual(result["risk_level"], "inconclusive")
        self.assertEqual(result["assessment_state"], "inconclusive")
        self.assertEqual(result["risk_score"], 0)
        self.assertNotEqual(result["verdict"], "likely_safe")

    def test_html_unavailable_prevents_likely_safe(self):
        result = fuse_evidence(self._make_evidence("unavailable"))
        self.assertEqual(result["verdict"], "inconclusive")
        self.assertEqual(result["risk_level"], "inconclusive")
        self.assertNotEqual(result["verdict"], "likely_safe")

    def test_html_not_run_prevents_likely_safe(self):
        result = fuse_evidence(self._make_evidence("not_run"))
        self.assertEqual(result["verdict"], "inconclusive")
        self.assertEqual(result["risk_level"], "inconclusive")
        self.assertNotEqual(result["verdict"], "likely_safe")

    def test_html_missing_prevents_likely_safe(self):
        result = fuse_evidence(self._make_evidence("missing"))
        self.assertEqual(result["verdict"], "inconclusive")
        self.assertEqual(result["risk_level"], "inconclusive")
        self.assertNotEqual(result["verdict"], "likely_safe")

    def test_html_observed_clean_still_likely_safe(self):
        today = datetime.date.today()
        old_date = (today - datetime.timedelta(days=1000)).isoformat()
        ev = {
            "brand": _brand_obs(matches=[]),
            "html": _html_obs(),
            "tls": _tls_verified(),
            "domain": _domain_obs(creation_date=old_date),
            "dns": {
                "A": {
                    "source": "dns.a",
                    "status": "observed",
                    "observation": {"availability": "available", "addresses": ["1.2.3.4"]},
                    "uncertainty": [],
                }
            },
            "relationships": _graph_obs(),
            "visual": {
                "source": "visual.logo_crop",
                "status": "not_run",
                "observation": {},
                "uncertainty": [],
            },
            "analysis": {
                "features": {
                    "url_length": 25,
                    "hostname_length": 11,
                    "path_length": 1,
                    "dot_count": 1,
                    "hyphen_count": 0,
                    "at_symbol_count": 0,
                    "digit_count": 0,
                    "uses_https": 1,
                    "uses_ip_address": 0,
                    "suspicious_keyword_count": 0,
                },
                "prediction": {
                    "status": "available",
                    "label": "legitimate",
                    "is_phishing": False,
                    "disclaimer": "Estimate only.",
                },
            },
        }
        result = fuse_evidence(ev)
        self.assertEqual(result["verdict"], "likely_safe")
        self.assertEqual(result["risk_level"], "low")
        self.assertEqual(result["assessment_state"], "conclusive")

    def test_html_error_adds_coverage_limitation(self):
        result = fuse_evidence(self._make_evidence("error"))
        limitations_text = " ".join(result["limitations"])
        self.assertIn("HTML", limitations_text)
        self.assertIn("safety", limitations_text.lower())

    def test_html_error_no_reassuring_indicator(self):
        result = fuse_evidence(self._make_evidence("error"))
        pos_ids = {s["signal_id"] for s in result["contributing_indicators"]}
        # HTML failure must not contribute any HTML-specific suspicious signal
        html_signals = [s for s in pos_ids if s.startswith("html_")]
        self.assertEqual(len(html_signals), 0)
        # Despite reassuring indicators from other sources, verdict is still inconclusive
        self.assertEqual(result["verdict"], "inconclusive")


class TestFusionExceptionRoute(unittest.TestCase):
    """Integration: when fuse_evidence raises, /api/analyze/deeper returns an explicit inconclusive assessment."""

    def setUp(self):
        from app import create_app
        self.client = create_app().test_client()

    def test_fusion_exception_returns_inconclusive_assessment(self):
        from unittest.mock import patch
        from detection.evidence import EvidenceRecord

        def _mock_evidence(*a, **kw):
            return EvidenceRecord(
                source="html.static",
                observation={"availability": "https_required"},
                status="unavailable",
                uncertainty=["HTTPS required."],
            )

        def _mock_dns(*a, **kw):
            return {
                t: EvidenceRecord(
                    source=f"dns.{t.lower()}",
                    observation={"availability": "unavailable"},
                    status="unavailable",
                    uncertainty=["Not resolved."],
                )
                for t in ("A", "AAAA", "MX", "NS", "TXT")
            }

        with patch("app.routes.fetch_html", side_effect=Exception("no fetch")), \
             patch("app.routes.analyze_html_document", return_value=_mock_evidence()), \
             patch("app.routes.lookup_dns", return_value=_mock_dns()), \
             patch("app.routes.lookup_domain_registration", return_value=_mock_evidence()), \
             patch("app.routes.analyze_tls_certificate", return_value=_mock_evidence()), \
             patch("app.routes.analyze_brand_impersonation", return_value=EvidenceRecord(
                 source="brand.impersonation",
                 observation={"availability": "available", "hostname_ascii": "example.com",
                              "registrable_domain": "example.com",
                              "matches": [], "mixed_scripts_in_registrable_label": False,
                              "unicode_present": False},
                 status="observed",
                 uncertainty=["Heuristic only."],
             )), \
             patch("app.routes.analyze_relationship_graph", return_value=EvidenceRecord(
                 source="relationship.graph",
                 observation={"availability": "no_relationships", "nodes": [],
                              "edges": [], "truncated": False},
                 status="unavailable",
                 uncertainty=["No relationships found."],
             )), \
             patch("app.routes.predict_url_features",
                   side_effect=RuntimeError("fusion boom")):

            response = self.client.post(
                "/api/analyze/deeper",
                json={"url": "https://example.com/"}
            )

        self.assertEqual(response.status_code, 200)
        body = response.get_json()
        self.assertTrue(body["success"])
        self.assertIn("evidence", body)
        self.assertIn("risk_assessment", body, "risk_assessment must be present even when fusion fails")
        ra = body["risk_assessment"]
        self.assertEqual(ra["verdict"], "inconclusive")
        self.assertEqual(ra["risk_level"], "inconclusive")
        self.assertEqual(ra["assessment_state"], "inconclusive")
        self.assertEqual(ra["risk_score"], 0)
        self.assertNotIn("fusion boom", str(body), "raw exception details must not leak")
        self.assertNotIn("RuntimeError", str(body), "raw exception details must not leak")


if __name__ == "__main__":
    unittest.main()
