"""
MimicTrace AI — Evidence Fusion Engine (Stage 7)

Aggregates evidence from all detection modules into an explainable risk
assessment. Scores are NOT probabilities. They reflect signal strength
only and must never be presented as a guarantee.

Risk levels:
    0–24   Low Risk
    25–49  Moderate Risk
    50–74  High Risk
    75–100 Critical Risk
"""

from __future__ import annotations

import datetime
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------

RISK_THRESHOLDS: Dict[str, Tuple[int, int]] = {
    "low":      (0,  24),
    "moderate": (25, 49),
    "high":     (50, 74),
    "critical": (75, 100),
}

# Maximum raw score before clamping to 100.
_MAX_RAW_SCORE = 100

# ---------------------------------------------------------------------------
# Signal weights — tunable without changing logic.
# Each entry: (signal_id, weight, description)
# Weights are additive; correlated groups are capped (see _apply_caps).
# ---------------------------------------------------------------------------

_BRAND_SIGNALS: List[Tuple[str, int, str]] = [
    ("brand_unicode_confusable",          25, "Domain uses Unicode characters that visually mimic a brand name"),
    ("brand_single_char_substitution",    18, "Domain differs from a known brand by one character substitution"),
    ("brand_adjacent_transposition",      18, "Domain differs from a known brand by one character transposition"),
    ("brand_insertion_deletion",          15, "Domain differs from a known brand by one insertion or deletion"),
    ("brand_exact_label_different_tld",   12, "Domain label matches a known brand exactly on a different TLD"),
    ("brand_token_in_label",               8, "Domain label contains a known brand token"),
    ("brand_token_in_subdomain",           6, "Subdomain contains a known brand token"),
    ("brand_mixed_scripts",               10, "Domain label mixes scripts (e.g. Latin and Cyrillic)"),
    ("brand_unicode_present",              5, "Domain contains non-ASCII Unicode characters"),
]

_HTML_SIGNALS: List[Tuple[str, int, str]] = [
    ("html_cross_domain_form",            20, "Login or credential form submits to a different domain"),
    ("html_external_form",                12, "Form submits data to an external host"),
    ("html_invalid_form_action",          10, "Form action uses a suspicious or invalid URL scheme"),
    ("html_password_input",               10, "Page contains a password input field"),
    ("html_login_form",                    8, "Page contains a form with login signals"),
    ("html_meta_refresh",                  8, "Page uses a meta-refresh redirect"),
    ("html_suspicious_link_scheme",        8, "Page contains links using dangerous schemes (javascript:, data:)"),
    ("html_many_hidden_elements",          6, "Page contains multiple hidden HTML elements"),
    ("html_redirect_changed_host",         8, "HTTP redirect led to a different hostname than submitted"),
    ("html_many_redirects",                5, "Page required multiple HTTP redirects"),
]

_URL_SIGNALS: List[Tuple[str, int, str]] = [
    ("url_uses_ip_address",               12, "URL uses a raw IP address instead of a hostname"),
    ("url_at_symbol",                     12, "URL contains an @ symbol which may obscure the real host"),
    ("url_many_suspicious_keywords",      10, "URL contains multiple phishing-associated keywords"),
    ("url_some_suspicious_keywords",       6, "URL contains phishing-associated keywords"),
    ("url_very_long",                      6, "URL is unusually long"),
    ("url_many_hyphens",                   5, "Hostname contains many hyphens, common in lookalike domains"),
    ("url_many_dots",                      5, "Hostname has many subdomains"),
]

_ML_SIGNALS: List[Tuple[str, int, str]] = [
    ("ml_predicts_phishing",              12, "Machine learning model estimates this URL as phishing"),
]

_DOMAIN_SIGNALS: List[Tuple[str, int, str]] = [
    ("domain_very_new",                   15, "Domain was registered less than 30 days ago"),
    ("domain_new",                        10, "Domain was registered less than 90 days ago"),
    ("domain_recently_registered",         5, "Domain was registered less than 180 days ago"),
]

_TLS_SIGNALS: List[Tuple[str, int, str]] = [
    ("tls_verification_failed",           15, "TLS certificate verification failed"),
    ("tls_handshake_failed",               8, "TLS handshake did not complete successfully"),
]

_GRAPH_SIGNALS: List[Tuple[str, int, str]] = [
    ("graph_resembles_brand_domain",      10, "Relationship graph found text-based brand resemblance"),
]

_NEGATIVE_SIGNALS: List[Tuple[str, int, str]] = [
    ("tls_verified",                      -8, "TLS certificate is valid and verified"),
    ("domain_established",               -10, "Domain has been registered for more than two years"),
    ("no_brand_matches",                   0, "No brand impersonation signals detected"),
    ("url_uses_https",                    -3, "URL uses HTTPS"),
    ("ml_predicts_legitimate",            -5, "Machine learning model estimates this URL as legitimate"),
]

# Build lookup maps for descriptions
_ALL_SIGNALS: Dict[str, str] = {
    sid: desc
    for group in (
        _BRAND_SIGNALS, _HTML_SIGNALS, _URL_SIGNALS,
        _ML_SIGNALS, _DOMAIN_SIGNALS, _TLS_SIGNALS,
        _GRAPH_SIGNALS, _NEGATIVE_SIGNALS,
    )
    for sid, _, desc in group
}
_SIGNAL_WEIGHT: Dict[str, int] = {
    sid: weight
    for group in (
        _BRAND_SIGNALS, _HTML_SIGNALS, _URL_SIGNALS,
        _ML_SIGNALS, _DOMAIN_SIGNALS, _TLS_SIGNALS,
        _GRAPH_SIGNALS, _NEGATIVE_SIGNALS,
    )
    for sid, weight, _ in group
}

# ---------------------------------------------------------------------------
# Group caps — prevent correlated signals from dominating the score
# ---------------------------------------------------------------------------

_GROUP_CAPS: Dict[str, int] = {
    "brand":  30,   # max total contribution from brand signals
    "html":   28,   # max total contribution from HTML signals
    "url":    18,   # max total contribution from URL signals
    "domain": 15,   # max total contribution from domain-age signals
    "ml":     12,   # max total contribution from ML signals
    "tls":    15,   # max total contribution from TLS signals
    "graph":  10,   # max total contribution from graph signals
}

_SIGNAL_GROUP: Dict[str, str] = {
    sid: group
    for group, signals in {
        "brand":  _BRAND_SIGNALS,
        "html":   _HTML_SIGNALS,
        "url":    _URL_SIGNALS,
        "ml":     _ML_SIGNALS,
        "domain": _DOMAIN_SIGNALS,
        "tls":    _TLS_SIGNALS,
        "graph":  _GRAPH_SIGNALS,
    }.items()
    for sid, _, _ in signals
}

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_METHOD_TO_SIGNAL = {
    "unicode_confusable_skeleton":          "brand_unicode_confusable",
    "single_character_substitution":        "brand_single_char_substitution",
    "adjacent_transposition":               "brand_adjacent_transposition",
    "single_character_insertion_or_deletion": "brand_insertion_deletion",
    "exact_brand_label_different_domain":   "brand_exact_label_different_tld",
    "brand_token_in_registrable_label":     "brand_token_in_label",
    "brand_token_in_subdomain":             "brand_token_in_subdomain",
    "unicode_confusable_token_in_subdomain": "brand_unicode_confusable",
    "canonical_domain_or_subdomain":        None,  # legitimate reference, not suspicious
}


def _obs(record: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Return observation dict if record is a serialized EvidenceRecord with status=observed."""
    if not isinstance(record, dict):
        return None
    if record.get("status") != "observed":
        return None
    obs = record.get("observation")
    return obs if isinstance(obs, dict) else None


def _obs_any(record: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Return observation dict for any non-null status (useful for checking availability)."""
    if not isinstance(record, dict):
        return None
    obs = record.get("observation")
    return obs if isinstance(obs, dict) else None


def _status(record: Optional[Dict[str, Any]]) -> str:
    if not isinstance(record, dict):
        return "missing"
    return record.get("status") or "missing"


def _days_since(iso_date: Optional[str]) -> Optional[int]:
    """Return days since the given ISO-8601 date string, or None if unparseable."""
    if not isinstance(iso_date, str):
        return None
    try:
        dt = datetime.datetime.fromisoformat(iso_date[:10])
        delta = datetime.date.today() - dt.date()
        return max(0, delta.days)
    except (ValueError, AttributeError):
        return None


# ---------------------------------------------------------------------------
# Signal extractors — one function per evidence category
# ---------------------------------------------------------------------------

def _extract_brand_signals(brand_record: Optional[Dict[str, Any]]) -> List[str]:
    signals: List[str] = []
    obs = _obs(brand_record)
    if obs is None:
        return signals

    # Unicode / mixed-script flags
    if obs.get("mixed_scripts_in_registrable_label"):
        signals.append("brand_mixed_scripts")
    if obs.get("unicode_present"):
        signals.append("brand_unicode_present")

    # Per-match method mapping
    seen_sids: set = set()
    for match in obs.get("matches", []):
        if not isinstance(match, dict):
            continue
        method = match.get("method", "")
        sid = _METHOD_TO_SIGNAL.get(method)
        if sid is None or sid in seen_sids:
            continue
        seen_sids.add(sid)
        signals.append(sid)

    return signals


def _extract_html_signals(html_record: Optional[Dict[str, Any]]) -> List[str]:
    signals: List[str] = []
    obs = _obs(html_record)
    if obs is None:
        return signals

    counts = obs.get("counts", {}) or {}
    if not isinstance(counts, dict):
        counts = {}

    if counts.get("cross_domain_form_actions", 0) > 0:
        signals.append("html_cross_domain_form")
    elif counts.get("external_form_actions", 0) > 0:
        signals.append("html_external_form")

    if counts.get("invalid_form_actions", 0) > 0:
        signals.append("html_invalid_form_action")

    pw = counts.get("password_inputs", 0) or 0
    login = counts.get("login_like_forms", 0) or 0
    # Avoid double-counting: only add html_password_input if no login form
    if login > 0:
        signals.append("html_login_form")
        if pw > 0:
            signals.append("html_password_input")
    elif pw > 0:
        signals.append("html_password_input")

    if counts.get("meta_refreshes", 0) > 0:
        signals.append("html_meta_refresh")

    if counts.get("suspicious_link_schemes", 0) > 0:
        signals.append("html_suspicious_link_scheme")

    if counts.get("hidden_elements", 0) > 5:
        signals.append("html_many_hidden_elements")

    if obs.get("redirect_changed_host"):
        signals.append("html_redirect_changed_host")
    elif obs.get("redirect_count", 0) and obs.get("redirect_count", 0) > 1:
        signals.append("html_many_redirects")

    return signals


def _extract_url_signals(features: Optional[Dict[str, Any]]) -> List[str]:
    signals: List[str] = []
    if not isinstance(features, dict):
        return signals

    if features.get("uses_ip_address"):
        signals.append("url_uses_ip_address")

    if features.get("at_symbol_count", 0) > 0:
        signals.append("url_at_symbol")

    kw = features.get("suspicious_keyword_count", 0) or 0
    if kw >= 3:
        signals.append("url_many_suspicious_keywords")
    elif kw >= 1:
        signals.append("url_some_suspicious_keywords")

    if features.get("url_length", 0) > 100:
        signals.append("url_very_long")

    if features.get("hyphen_count", 0) >= 4:
        signals.append("url_many_hyphens")

    if features.get("dot_count", 0) >= 4:
        signals.append("url_many_dots")

    return signals


def _extract_ml_signals(
    prediction: Optional[Dict[str, Any]],
) -> Tuple[List[str], List[str]]:
    pos: List[str] = []
    neg: List[str] = []
    if not isinstance(prediction, dict):
        return pos, neg
    if prediction.get("status") != "available":
        return pos, neg
    if prediction.get("is_phishing") is True:
        pos.append("ml_predicts_phishing")
    elif prediction.get("is_phishing") is False:
        neg.append("ml_predicts_legitimate")
    return pos, neg


def _extract_domain_signals(domain_record: Optional[Dict[str, Any]]) -> List[str]:
    signals: List[str] = []
    if not isinstance(domain_record, dict):
        return signals

    obs = _obs(domain_record)
    if obs is None:
        obs = _obs_any(domain_record)
    if obs is None:
        return signals

    creation = obs.get("creation_date")
    days = _days_since(creation)
    if days is not None:
        if days < 30:
            signals.append("domain_very_new")
        elif days < 90:
            signals.append("domain_new")
        elif days < 180:
            signals.append("domain_recently_registered")
    return signals


def _extract_tls_signals(
    tls_record: Optional[Dict[str, Any]],
) -> Tuple[List[str], List[str]]:
    pos: List[str] = []
    neg: List[str] = []
    if not isinstance(tls_record, dict):
        return pos, neg
    status = tls_record.get("status")
    obs = _obs_any(tls_record)
    avail = (obs or {}).get("availability", "")

    if status == "observed" and avail == "verified":
        neg.append("tls_verified")
    elif avail == "verification_failed":
        pos.append("tls_verification_failed")
    elif avail in ("tls_handshake_failed",):
        pos.append("tls_handshake_failed")

    return pos, neg


def _extract_domain_negative_signals(
    domain_record: Optional[Dict[str, Any]],
) -> List[str]:
    neg: List[str] = []
    if not isinstance(domain_record, dict):
        return neg
    if domain_record.get("status") != "observed":
        return neg
    obs = _obs(domain_record)
    if obs is None:
        return neg

    creation = obs.get("creation_date")
    days = _days_since(creation)
    if days is not None and days >= 730:
        neg.append("domain_established")
    return neg


def _extract_graph_signals(
    relationships_record: Optional[Dict[str, Any]],
) -> List[str]:
    signals: List[str] = []
    obs = _obs(relationships_record)
    if obs is None:
        return signals
    edges = obs.get("edges", [])
    if not isinstance(edges, list):
        return signals
    edge_types = {
        e.get("type") for e in edges if isinstance(e, dict)
    }
    if "resembles_brand_domain" in edge_types:
        signals.append("graph_resembles_brand_domain")
    return signals


# ---------------------------------------------------------------------------
# Score calculation
# ---------------------------------------------------------------------------

def _apply_caps(grouped_scores: Dict[str, int]) -> int:
    """Sum group scores, applying per-group caps."""
    total = 0
    for group, raw in grouped_scores.items():
        cap = _GROUP_CAPS.get(group, raw)
        total += min(raw, cap)
    return total


def _score_signals(
    positive_signal_ids: List[str],
    negative_signal_ids: List[str],
) -> int:
    """Convert signal lists to a clamped 0–100 score."""
    grouped: Dict[str, int] = {}
    for sid in positive_signal_ids:
        weight = _SIGNAL_WEIGHT.get(sid, 0)
        if weight <= 0:
            continue
        group = _SIGNAL_GROUP.get(sid, "other")
        grouped[group] = grouped.get(group, 0) + weight

    raw = _apply_caps(grouped)

    # Apply negative signals
    for sid in negative_signal_ids:
        weight = _SIGNAL_WEIGHT.get(sid, 0)
        raw += weight  # negative weights reduce score

    return max(0, min(_MAX_RAW_SCORE, raw))


def _risk_level(score: int) -> str:
    for level, (lo, hi) in RISK_THRESHOLDS.items():
        if lo <= score <= hi:
            return level
    return "critical"


_CRITICAL_SUSPICIOUS_SIGNALS = {
    "brand_unicode_confusable",
    "brand_mixed_scripts",
    "html_cross_domain_form",
}


def _verdict(
    score: int,
    positive_signals: List[str],
    sufficiency: str = "sufficient",
    negative_signals: Optional[List[str]] = None,
    html_observed: bool = False,
) -> str:
    if score >= 75:
        return "high_risk"
    if score >= 50 or any(s in _CRITICAL_SUSPICIOUS_SIGNALS for s in positive_signals):
        return "suspicious"
    if sufficiency == "limited":
        return "inconclusive"
    if score >= 25 or len(positive_signals) > 0:
        return "low_concern"
    if sufficiency == "sufficient":
        # HTML coverage is required before a reassuring "likely_safe" verdict.
        # A score of 0 with no HTML inspection does not prove safety.
        if not html_observed:
            return "inconclusive"
        return "likely_safe"
    # Partial sufficiency: only likely safe if independently verified reassuring signals exist
    neg = negative_signals or []
    if any(s in neg for s in ("tls_verified", "domain_established")):
        if not html_observed:
            return "inconclusive"
        return "likely_safe"
    return "low_concern"


def _evidence_sufficiency(
    evidence: Dict[str, Any],
    positive_signals: List[str],
) -> str:
    """
    Returns 'sufficient', 'partial', or 'limited'.
    Does not describe accuracy — only how many evidence sources contributed.
    """
    observed_sources = 0
    for key in ("html", "brand", "domain", "tls"):
        rec = evidence.get(key)
        if isinstance(rec, dict) and rec.get("status") == "observed":
            observed_sources += 1
    dns = evidence.get("dns") or {}
    if isinstance(dns, dict):
        for v in dns.values():
            if isinstance(v, dict) and v.get("status") == "observed":
                observed_sources += 1
                break

    if observed_sources >= 4:
        return "sufficient"
    if observed_sources >= 2:
        return "partial"
    return "limited"


def _build_indicator_detail(sid: str) -> Dict[str, str]:
    return {
        "signal_id": sid,
        "description": _ALL_SIGNALS.get(sid, sid),
    }


def _build_recommended_actions(
    score: int,
    positive_signals: List[str],
    verdict: str = "",
) -> List[str]:
    actions: List[str] = []
    if verdict == "inconclusive":
        actions.append("Evidence is insufficient to verify the authenticity of this website. Do not enter credentials until verified.")
        actions.append("Check if the website domain is spelled correctly and verify the server status.")
    elif score >= 75:
        actions.append("Do not submit credentials or personal information to this website.")
        actions.append("Close this page and navigate directly to the official website.")
        actions.append("Report this URL to your organisation's security team.")
    elif score >= 50:
        actions.append("Exercise extreme caution before submitting any credentials or personal data.")
        actions.append("Verify the website's authenticity through an official channel before proceeding.")
    elif score >= 25:
        actions.append("Verify the website address carefully before entering any information.")
        actions.append("Look for a valid TLS certificate and a trusted domain name.")

    if "brand_unicode_confusable" in positive_signals or "brand_mixed_scripts" in positive_signals:
        actions.append("The domain uses visually deceptive characters. Navigate via official bookmarks or typed URLs only.")
    if "html_cross_domain_form" in positive_signals:
        actions.append("A form on this page submits data to a different website, which is unusual for legitimate services.")
    if "tls_verification_failed" in positive_signals:
        actions.append("The TLS certificate is not trusted. Never enter credentials on a site with certificate errors.")

    if not actions:
        actions.append("No immediate action required. Continue to verify website identity through official channels.")

    return actions


def _build_evidence_summary(
    evidence: Dict[str, Any],
    positive_signals: List[str],
    negative_signals: List[str],
) -> Dict[str, Any]:
    """
    Build a human-readable summary of which sources contributed evidence.
    """
    source_statuses: Dict[str, str] = {}
    for key in ("html", "brand", "domain", "tls", "visual", "relationships"):
        rec = evidence.get(key)
        source_statuses[key] = _status(rec) if rec is not None else "not_run"

    dns = evidence.get("dns") or {}
    dns_observed = any(
        isinstance(v, dict) and v.get("status") == "observed"
        for v in dns.values()
    ) if isinstance(dns, dict) else False
    source_statuses["dns"] = "observed" if dns_observed else "not_observed"

    return {
        "source_statuses": source_statuses,
        "positive_signal_count": len(positive_signals),
        "negative_signal_count": len(negative_signals),
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def fuse_evidence(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """
    Aggregate evidence records from the deeper-analysis pipeline and return
    an explainable risk assessment.

    Parameters
    ----------
    evidence : dict
        The assembled evidence dict from ``POST /api/analyze/deeper``.
        Expected keys: html, dns, domain, tls, brand, visual, relationships.
        Also accepts an ``analysis`` sub-dict containing URL features and ML
        prediction (injected by the route).

    Returns
    -------
    dict
        risk_score         : int   0–100 (not a probability)
        risk_level         : str   low | moderate | high | critical
        verdict            : str   likely_safe | low_concern | suspicious | high_risk
        evidence_sufficiency: str  sufficient | partial | limited
        contributing_indicators : list of {signal_id, description}
        negative_indicators     : list of {signal_id, description}
        evidence_summary        : dict
        recommended_actions     : list[str]
        limitations             : list[str]
    """
    if not isinstance(evidence, dict):
        return _empty_assessment("Evidence must be a non-empty object.")

    limitations = [
        "Risk scores are heuristic estimates of signal strength, not probabilities.",
        "This assessment is based on static evidence collected at analysis time and may not reflect real-time changes.",
        "The absence of negative indicators does not confirm a website is safe.",
        "Signals may have benign explanations; human judgment is required.",
    ]

    # -- Collect analysis sub-dict (URL features + ML prediction) -----------
    analysis = evidence.get("analysis") or {}
    features = analysis.get("features") if isinstance(analysis, dict) else None
    prediction = analysis.get("prediction") if isinstance(analysis, dict) else None

    # Also accept prediction at the top level (some callers pass it there)
    if prediction is None:
        prediction = evidence.get("prediction")

    # -- Extract signals from each source ------------------------------------
    pos_signals: List[str] = []
    neg_signals: List[str] = []

    brand_rec = evidence.get("brand")
    brand_pos = _extract_brand_signals(brand_rec)
    pos_signals.extend(brand_pos)
    if (
        isinstance(brand_rec, dict)
        and brand_rec.get("status") == "observed"
        and not brand_pos
    ):
        neg_signals.append("no_brand_matches")

    pos_signals.extend(_extract_html_signals(evidence.get("html")))

    url_pos = _extract_url_signals(features)
    pos_signals.extend(url_pos)

    # HTTPS as a weak negative (only if no suspicious URL signals AND TLS certificate was actually observed and verified)
    tls_rec = evidence.get("tls")
    tls_is_verified = (
        isinstance(tls_rec, dict)
        and tls_rec.get("status") == "observed"
        and isinstance(tls_rec.get("observation"), dict)
        and tls_rec.get("observation", {}).get("availability") == "verified"
    )
    if isinstance(features, dict) and features.get("uses_https") and not url_pos and tls_is_verified:
        neg_signals.append("url_uses_https")

    ml_pos, ml_neg = _extract_ml_signals(prediction)
    pos_signals.extend(ml_pos)
    neg_signals.extend(ml_neg)

    pos_signals.extend(_extract_domain_signals(evidence.get("domain")))
    neg_signals.extend(_extract_domain_negative_signals(evidence.get("domain")))

    tls_pos, tls_neg = _extract_tls_signals(evidence.get("tls"))
    pos_signals.extend(tls_pos)
    neg_signals.extend(tls_neg)

    pos_signals.extend(_extract_graph_signals(evidence.get("relationships")))

    # De-duplicate while preserving order
    seen: set = set()
    deduped_pos: List[str] = []
    for s in pos_signals:
        if s not in seen:
            seen.add(s)
            deduped_pos.append(s)
    seen_neg: set = set()
    deduped_neg: List[str] = []
    for s in neg_signals:
        if s not in seen_neg:
            seen_neg.add(s)
            deduped_neg.append(s)

    # -- Compute score -------------------------------------------------------
    score = _score_signals(deduped_pos, deduped_neg)
    level = _risk_level(score)
    sufficiency = _evidence_sufficiency(evidence, deduped_pos)
    html_observed = (
        isinstance(evidence.get("html"), dict)
        and evidence.get("html", {}).get("status") == "observed"
    )
    verdict = _verdict(score, deduped_pos, sufficiency, deduped_neg, html_observed=html_observed)

    # Ensure an inconclusive verdict is never represented as a reassuring risk level.
    if verdict == "inconclusive":
        level = "inconclusive"

    # -- Build structured output ---------------------------------------------
    contributing = [_build_indicator_detail(s) for s in deduped_pos]
    negatives = [_build_indicator_detail(s) for s in deduped_neg]
    summary = _build_evidence_summary(evidence, deduped_pos, deduped_neg)
    actions = _build_recommended_actions(score, deduped_pos, verdict=verdict)

    if sufficiency == "limited":
        limitations.append(
            "Only limited evidence was collected. Critical analysis sources are unavailable or unreachable."
        )
    if not html_observed and verdict == "inconclusive":
        limitations.append(
            "HTML analysis was unavailable or did not complete. Page content could not be inspected "
            "for credential forms, cross-domain submissions, or impersonation indicators. "
            "Absence of HTML telemetry does not indicate safety."
        )

    return {
        "risk_score": score,
        "risk_level": level,
        "verdict": verdict,
        "evidence_sufficiency": sufficiency,
        "assessment_state": "inconclusive" if verdict == "inconclusive" else "conclusive",
        "contributing_indicators": contributing,
        "negative_indicators": negatives,
        "evidence_summary": summary,
        "recommended_actions": actions,
        "limitations": limitations,
    }


def _empty_assessment(reason: str) -> Dict[str, Any]:
    return {
        "risk_score": 0,
        "risk_level": "inconclusive",
        "verdict": "inconclusive",
        "evidence_sufficiency": "limited",
        "assessment_state": "inconclusive",
        "contributing_indicators": [],
        "negative_indicators": [],
        "evidence_summary": {
            "source_statuses": {},
            "positive_signal_count": 0,
            "negative_signal_count": 0,
        },
        "recommended_actions": [
            "Evidence is insufficient to verify the authenticity of this website. Do not enter credentials until verified.",
            "Verify the website URL and TLS certificate directly in your browser before entering credentials.",
        ],
        "limitations": [reason],
    }
