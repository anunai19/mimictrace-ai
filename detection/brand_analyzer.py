import re
import unicodedata
from urllib.parse import urlsplit

import tldextract

from detection.destination_safety import DestinationSafetyError, parse_http_url
from detection.evidence import EvidenceRecord
from detection.url_analyzer import analyze_url


BRAND_CATALOG = (
    ("Google", "google.com"),
    ("Microsoft", "microsoft.com"),
    ("Apple", "apple.com"),
    ("Amazon", "amazon.com"),
    ("PayPal", "paypal.com"),
)

_TLD_EXTRACTOR = tldextract.TLDExtract(
    suffix_list_urls=(),
    cache_dir=None,
    fallback_to_snapshot=True,
)

# A deliberately incomplete set of common lookalikes, not a full UTS #39 table.
_CONFUSABLES = str.maketrans({
    "а": "a",
    "с": "c",
    "е": "e",
    "і": "i",
    "к": "k",
    "м": "m",
    "н": "h",
    "о": "o",
    "р": "p",
    "х": "x",
    "у": "y",
    "в": "b",
    "α": "a",
    "ε": "e",
    "ι": "i",
    "κ": "k",
    "ο": "o",
    "ρ": "p",
    "τ": "t",
    "χ": "x",
})
_TOKEN_PATTERN = re.compile(r"[a-z0-9]+")


def _record(status, availability, observation, uncertainty):
    return EvidenceRecord(
        source="brand.impersonation",
        observation={
            "availability": availability,
            **observation,
        },
        status=status,
        uncertainty=uncertainty,
    )


def _decode_idna_label(label):
    if not label.lower().startswith("xn--"):
        return label
    try:
        return label.encode("ascii").decode("idna")
    except UnicodeError:
        return label


def _hostname_from_netloc(netloc):
    authority = netloc.rsplit("@", 1)[-1]
    if authority.startswith("["):
        closing_bracket = authority.find("]")
        if closing_bracket > 0:
            return authority[1:closing_bracket]
    if ":" in authority:
        return authority.rsplit(":", 1)[0]
    return authority


def _unicode_hostname(ascii_hostname):
    return ".".join(
        _decode_idna_label(label)
        for label in ascii_hostname.split(".")
    )


def _has_unicode_representation(submitted_hostname, ascii_hostname):
    return any(ord(character) > 127 for character in submitted_hostname) or any(
        _decode_idna_label(label) != label
        for label in ascii_hostname.split(".")
    )


def _unicode_script(character):
    name = unicodedata.name(character, "")
    for script in ("LATIN", "CYRILLIC", "GREEK"):
        if script in name:
            return script
    if unicodedata.category(character).startswith("L"):
        return "OTHER"
    return None


def _has_mixed_scripts(label):
    scripts = {
        script
        for character in label
        if (script := _unicode_script(character)) is not None
    }
    return len(scripts) > 1


def _confusable_skeleton(label):
    normalized = unicodedata.normalize("NFKC", label).casefold()
    return normalized.translate(_CONFUSABLES)


def _subdomain_token_method(labels, brand_label):
    plain_match = False
    for label in labels:
        decoded_label = _decode_idna_label(label)
        skeleton = _confusable_skeleton(decoded_label)
        if brand_label not in _TOKEN_PATTERN.findall(skeleton):
            continue
        plain_label = unicodedata.normalize("NFC", decoded_label).casefold()
        if skeleton != plain_label:
            return "unicode_confusable_token_in_subdomain"
        plain_match = True
    return "brand_token_in_subdomain" if plain_match else None


def _one_edit_method(left, right):
    if len(left) < 6 or len(right) < 6 or abs(len(left) - len(right)) > 1:
        return None

    if len(left) == len(right):
        differences = [
            index
            for index, (first, second) in enumerate(zip(left, right))
            if first != second
        ]
        if len(differences) == 1:
            return "single_character_substitution"
        if (
            len(differences) == 2
            and differences[1] == differences[0] + 1
            and left[differences[0]] == right[differences[1]]
            and left[differences[1]] == right[differences[0]]
        ):
            return "adjacent_transposition"
        return None

    shorter, longer = sorted((left, right), key=len)
    short_index = 0
    long_index = 0
    skipped = False
    while short_index < len(shorter) and long_index < len(longer):
        if shorter[short_index] == longer[long_index]:
            short_index += 1
            long_index += 1
        elif skipped:
            return None
        else:
            skipped = True
            long_index += 1
    return "single_character_insertion_or_deletion"


def _candidate(name, canonical_domain, method, strength):
    return {
        "brand": name,
        "canonical_domain": canonical_domain,
        "method": method,
        "strength": strength,
    }


def analyze_brand_impersonation(url):
    """Compare a URL hostname to a small local brand catalog without networking."""
    uncertainty = [
        "The catalog contains five manually selected canonical domains and has no aliases.",
        "Catalog entries are not independently verified; resemblance does not establish ownership or affiliation.",
        "Similarity is heuristic and does not prove phishing or impersonation.",
        "Unicode confusable handling uses NFKC and a limited set of mapped characters; coverage is incomplete.",
    ]

    if not isinstance(url, str) or not url.strip():
        return _record(
            "error",
            "invalid_input",
            {"matches": []},
            uncertainty,
        )

    try:
        normalized_url = analyze_url(url)["normalized_url"]
        netloc = urlsplit(normalized_url).netloc
        submitted_hostname = _hostname_from_netloc(netloc)
        _, ascii_hostname, _, _, _, literal_address = parse_http_url(normalized_url)
    except (DestinationSafetyError, TypeError, ValueError, UnicodeError):
        return _record(
            "error",
            "invalid_input",
            {"matches": []},
            uncertainty,
        )

    if literal_address is not None:
        return _record(
            "unavailable",
            "ip_literal",
            {
                "hostname_submitted": submitted_hostname,
                "hostname_ascii": ascii_hostname,
                "hostname_unicode": _unicode_hostname(ascii_hostname),
                "unicode_present": _has_unicode_representation(
                    submitted_hostname,
                    ascii_hostname,
                ),
                "matches": [],
            },
            [*uncertainty, "Brand comparison requires a registrable domain name."],
        )

    try:
        extracted = _TLD_EXTRACTOR(ascii_hostname)
    except Exception:
        return _record(
            "error",
            "registrable_domain_error",
            {
                "hostname_submitted": submitted_hostname,
                "hostname_ascii": ascii_hostname,
                "hostname_unicode": _unicode_hostname(ascii_hostname),
                "unicode_present": _has_unicode_representation(
                    submitted_hostname,
                    ascii_hostname,
                ),
                "matches": [],
            },
            [*uncertainty, "Local registrable-domain extraction failed; details are omitted."],
        )
    if not extracted.domain or not extracted.suffix:
        return _record(
            "unavailable",
            "registrable_domain_unavailable",
            {
                "hostname_submitted": submitted_hostname,
                "hostname_ascii": ascii_hostname,
                "hostname_unicode": _unicode_hostname(ascii_hostname),
                "unicode_present": _has_unicode_representation(
                    submitted_hostname,
                    ascii_hostname,
                ),
                "matches": [],
            },
            [*uncertainty, "A registrable domain could not be derived locally."],
        )

    registrable_domain = f"{extracted.domain}.{extracted.suffix}"
    unicode_hostname = _unicode_hostname(ascii_hostname)
    decoded_domain_label = _decode_idna_label(extracted.domain)
    unicode_present = _has_unicode_representation(
        submitted_hostname,
        ascii_hostname,
    )
    mixed_scripts = _has_mixed_scripts(decoded_domain_label)
    matches = []
    prefix_labels = []
    if ascii_hostname.endswith("." + registrable_domain):
        prefix = ascii_hostname[: -(len(registrable_domain) + 1)]
        prefix_labels = prefix.split(".")

    for name, canonical_domain in BRAND_CATALOG:
        brand_label = canonical_domain.split(".", 1)[0]
        if (
            ascii_hostname == canonical_domain
            or ascii_hostname.endswith("." + canonical_domain)
        ):
            matches.append(
                _candidate(
                    name,
                    canonical_domain,
                    "canonical_domain_or_subdomain",
                    "catalog_reference",
                )
            )
            continue

        method = None
        strength = None
        if (
            decoded_domain_label.casefold() != brand_label
            and _confusable_skeleton(decoded_domain_label) == brand_label
        ):
            method = "unicode_confusable_skeleton"
            strength = "strong_candidate"
        elif extracted.domain == brand_label:
            method = "exact_brand_label_different_domain"
            strength = "weak" if len(brand_label) < 6 else "moderate"
        elif brand_label in _TOKEN_PATTERN.findall(extracted.domain):
            method = "brand_token_in_registrable_label"
            strength = "weak"
        else:
            edit_method = _one_edit_method(extracted.domain, brand_label)
            if edit_method is not None:
                method = edit_method
                strength = "moderate"

        if method is None:
            method = _subdomain_token_method(prefix_labels, brand_label)
        if method is not None and strength is None:
            strength = "weak"

        if method is not None:
            matches.append(_candidate(name, canonical_domain, method, strength))

    observation = {
        "hostname_submitted": submitted_hostname,
        "hostname_ascii": ascii_hostname,
        "hostname_unicode": unicode_hostname,
        "registrable_domain": registrable_domain,
        "unicode_present": unicode_present,
        "mixed_scripts_in_registrable_label": mixed_scripts,
        "matches": matches,
    }
    return _record("observed", "available", observation, uncertainty)