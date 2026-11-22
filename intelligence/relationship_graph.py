import ipaddress
import re

from detection.destination_safety import is_allowed_public_address
from detection.evidence import EvidenceRecord


MAX_GRAPH_NODES = 100
MAX_GRAPH_EDGES = 200
MAX_GRAPH_EVIDENCE_REFS = 8
MAX_GRAPH_UNCERTAINTIES = 8
MAX_GRAPH_TEXT_LENGTH = 256
MAX_GRAPH_ITEMS_PER_SOURCE = 200

_HOST_LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_ALLOWED_RELATIONSHIPS = frozenset({
    "resolves_to",
    "form_submits_to",
    "loads_script_from",
    "embeds_host",
    "links_to",
    "redirected_to",
    "resembles_brand_domain",
    "visually_resembles_brand",
})
_BRAND_CANDIDATE_METHODS = frozenset({
    "unicode_confusable_skeleton",
    "exact_brand_label_different_domain",
    "brand_token_in_registrable_label",
    "single_character_substitution",
    "adjacent_transposition",
    "single_character_insertion_or_deletion",
    "brand_token_in_subdomain",
    "unicode_confusable_token_in_subdomain",
})
_BASE_UNCERTAINTY = [
    "Relationships describe evidence from this analysis only; they do not establish shared ownership or malicious intent.",
    "DNS, web references, and brand resemblance may have benign explanations and can change over time.",
    "WHOIS registrar data and certificate details are not used to create graph relationships.",
]


def _record(status, availability, nodes, edges, uncertainty, truncated=False):
    return EvidenceRecord(
        source="relationship.graph",
        observation={
            "availability": availability,
            "nodes": nodes,
            "edges": edges,
            "truncated": truncated,
        },
        status=status,
        uncertainty=uncertainty,
    )


def _observed_record(record, expected_source):
    if not isinstance(record, dict):
        return None
    if record.get("source") != expected_source or record.get("status") != "observed":
        return None
    observation = record.get("observation")
    if not isinstance(observation, dict):
        return None
    raw_uncertainty = record.get("uncertainty")
    uncertainty = []
    if isinstance(raw_uncertainty, list):
        uncertainty = [
            item[:MAX_GRAPH_TEXT_LENGTH]
            for item in raw_uncertainty[:MAX_GRAPH_UNCERTAINTIES - 1]
            if isinstance(item, str) and item.strip()
        ]
    if not uncertainty:
        uncertainty = ["The source evidence has limited uncertainty metadata."]
    return observation, uncertainty


def _normalize_host(value):
    if not isinstance(value, str) or not value or len(value) > 253:
        return None
    if value != value.strip() or any(ord(char) <= 0x20 for char in value):
        return None
    if "%" in value or "/" in value or "@" in value or "\\" in value:
        return None
    if value.endswith("."):
        value = value[:-1]
    if not value or value.endswith("."):
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        address = None
    if address is not None:
        if not is_allowed_public_address(address):
            return None
        return address.compressed.lower()
    try:
        normalized = value.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    if not normalized or len(normalized) > 253:
        return None
    labels = normalized.split(".")
    if any(not _HOST_LABEL_PATTERN.fullmatch(label) for label in labels):
        return None
    return normalized


def _add_reference(references, reference):
    if reference not in references and len(references) < MAX_GRAPH_EVIDENCE_REFS:
        references.append(reference)
        references.sort(key=lambda item: (item["key"], item["source"]))


def _uncertainties(source_uncertainty, relationship_uncertainty):
    values = {
        item[:MAX_GRAPH_TEXT_LENGTH]
        for item in (*source_uncertainty, relationship_uncertainty)
        if isinstance(item, str) and item.strip()
    }
    return sorted(values)[:MAX_GRAPH_UNCERTAINTIES]


class _GraphBuilder:
    def __init__(self):
        self.nodes = {}
        self.edges = {}
        self.truncated = False

    def add_edge(
        self,
        relation_type,
        source_id,
        source_type,
        source_label,
        target_id,
        target_type,
        target_label,
        evidence_ref,
        source_uncertainty,
        relationship_uncertainty,
        details=None,
    ):
        if relation_type not in _ALLOWED_RELATIONSHIPS:
            return
        edge_key = (relation_type, source_id, target_id)
        if edge_key not in self.edges:
            required_nodes = {source_id, target_id} - self.nodes.keys()
            if (
                len(self.edges) >= MAX_GRAPH_EDGES
                or len(self.nodes) + len(required_nodes) > MAX_GRAPH_NODES
            ):
                self.truncated = True
                return

            self.nodes.setdefault(
                source_id,
                {
                    "id": source_id,
                    "type": source_type,
                    "label": source_label[:MAX_GRAPH_TEXT_LENGTH],
                    "evidence_refs": [],
                },
            )
            self.nodes.setdefault(
                target_id,
                {
                    "id": target_id,
                    "type": target_type,
                    "label": target_label[:MAX_GRAPH_TEXT_LENGTH],
                    "evidence_refs": [],
                },
            )
            self.edges[edge_key] = {
                "type": relation_type,
                "source": source_id,
                "target": target_id,
                "evidence_refs": [],
                "uncertainty": [],
            }
            if details:
                self.edges[edge_key].update(details)

        edge = self.edges[edge_key]
        _add_reference(edge["evidence_refs"], evidence_ref)
        edge["uncertainty"] = _uncertainties(
            edge["uncertainty"],
            relationship_uncertainty,
        )
        for item in source_uncertainty:
            edge["uncertainty"] = _uncertainties(
                edge["uncertainty"],
                item,
            )
        _add_reference(self.nodes[source_id]["evidence_refs"], evidence_ref)
        _add_reference(self.nodes[target_id]["evidence_refs"], evidence_ref)

    def result(self):
        nodes = sorted(self.nodes.values(), key=lambda item: item["id"])
        edges = sorted(
            self.edges.values(),
            key=lambda item: (item["type"], item["source"], item["target"]),
        )
        uncertainty = list(_BASE_UNCERTAINTY)
        if self.truncated:
            uncertainty.append(
                "A fixed graph size limit was reached; some relationships may be omitted."
            )
        if edges:
            return _record(
                "observed",
                "available",
                nodes,
                edges,
                uncertainty,
                self.truncated,
            )
        uncertainty.append(
            "No supported relationships were available from the observed evidence."
        )
        return _record(
            "unavailable",
            "no_relationships",
            nodes,
            edges,
            uncertainty,
            self.truncated,
        )


def _get_record(evidence, group, source, record_type=None):
    if not isinstance(evidence, dict):
        return None
    records = evidence.get(group)
    if record_type is not None:
        if not isinstance(records, dict):
            return None
        records = records.get(record_type)
    return _observed_record(records, source)


def _host_node(builder, hostname, reference, uncertainty, node_type="host"):
    normalized = _normalize_host(hostname)
    if normalized is None:
        return None
    return f"{node_type}:{normalized}", normalized


def _analysis_hostname(evidence):
    brand = _get_record(evidence, "brand", "brand.impersonation")
    if brand:
        host = _normalize_host(brand[0].get("hostname_ascii"))
        if host:
            return host
    html = _get_record(evidence, "html", "html.static")
    if html:
        for key in ("original_host", "page_host"):
            host = _normalize_host(html[0].get(key))
            if host:
                return host
    return None


def _add_html_relationships(builder, evidence):
    record = _get_record(evidence, "html", "html.static")
    if not record:
        return
    observation, uncertainty = record
    page_host = _normalize_host(observation.get("page_host"))
    if page_host is None:
        return
    reference = {"key": "html", "source": "html.static"}
    html_uncertainty = "Static HTML references do not establish navigation or malicious intent."
    for evidence_field, relation_type in (
        ("external_form_actions", "form_submits_to"),
        ("external_scripts", "loads_script_from"),
        ("iframes", "embeds_host"),
        ("external_links", "links_to"),
    ):
        targets = observation.get(evidence_field)
        if not isinstance(targets, list):
            continue
        normalized_targets = sorted({
            target_host
            for target in targets
            if (
                isinstance(target, dict)
                and target.get("kind") == "web"
                and (target_host := _normalize_host(target.get("host"))) is not None
                and target_host != page_host
            )
        })
        if len(normalized_targets) > MAX_GRAPH_ITEMS_PER_SOURCE:
            builder.truncated = True
        for target_host in normalized_targets[:MAX_GRAPH_ITEMS_PER_SOURCE]:
            builder.add_edge(
                relation_type,
                f"host:{page_host}",
                "host",
                page_host,
                f"host:{target_host}",
                "host",
                target_host,
                reference,
                uncertainty,
                html_uncertainty,
            )

    original_host = _normalize_host(observation.get("original_host"))
    redirect_count = observation.get("redirect_count")
    if (
        original_host
        and original_host != page_host
        and isinstance(redirect_count, int)
        and not isinstance(redirect_count, bool)
        and 0 < redirect_count <= 3
    ):
        builder.add_edge(
            "redirected_to",
            f"host:{original_host}",
            "host",
            original_host,
            f"host:{page_host}",
            "host",
            page_host,
            reference,
            uncertainty,
            "Only the original and final host are available; intermediate redirects are not represented.",
        )


def _add_dns_relationships(builder, evidence):
    hostname = _analysis_hostname(evidence)
    if hostname is None:
        return
    for record_type in ("A", "AAAA"):
        source_key = f"dns.{record_type.lower()}"
        record = _get_record(evidence, "dns", source_key, record_type)
        if not record:
            continue
        observation, uncertainty = record
        addresses = observation.get("addresses")
        if not isinstance(addresses, list):
            continue
        normalized_addresses = sorted({
            normalized
            for address in addresses
            if isinstance(address, str)
            and (normalized := _normalize_host(address)) is not None
        })
        if len(normalized_addresses) > MAX_GRAPH_ITEMS_PER_SOURCE:
            builder.truncated = True
        for normalized in normalized_addresses[:MAX_GRAPH_ITEMS_PER_SOURCE]:
            builder.add_edge(
                "resolves_to",
                f"host:{hostname}",
                "host",
                hostname,
                f"ip:{normalized}",
                "ip_address",
                normalized,
                {"key": f"dns.{record_type}", "source": source_key},
                uncertainty,
                "DNS answers are time-dependent and do not imply common ownership.",
            )


def _add_visual_relationships(builder, evidence):
    """Add a visually_resembles_brand edge when visual evidence is calibrated and matched."""
    try:
        visual = evidence.get("visual") if isinstance(evidence, dict) else None
        if not isinstance(visual, dict):
            return
        if visual.get("status") != "observed":
            return
        observation = visual.get("observation")
        if not isinstance(observation, dict):
            return
        if observation.get("calibration_state") != "calibrated":
            return
        if observation.get("match_result") is None:
            return
        evaluations = observation.get("evaluations")
        if not isinstance(evaluations, list) or not evaluations:
            return
        top = evaluations[0]
        if not isinstance(top, dict):
            return
        candidate_brand = top.get("brand", "")
        if not isinstance(candidate_brand, str) or not candidate_brand.strip():
            return
        candidate_brand = candidate_brand.strip()
        if len(candidate_brand) > MAX_GRAPH_TEXT_LENGTH:
            return
        raw_canonical = top.get("canonical_domain", "")
        canonical_domain = _normalize_host(raw_canonical)
        if not canonical_domain:
            return
        page_host = _analysis_hostname(evidence)
        if page_host is None:
            return
        uncertainty = (
            "Visual similarity is independent structural evidence only. "
            "It does not establish phishing, impersonation, ownership, "
            "authorization, or malicious intent."
        )
        builder.add_edge(
            "visually_resembles_brand",
            f"host:{page_host}",
            "host",
            page_host,
            f"brand-domain:{canonical_domain}",
            "brand_reference",
            f"{candidate_brand} ({canonical_domain})",
            {"key": "visual", "source": "visual.logo_crop"},
            [],
            uncertainty,
        )
    except Exception:
        return


def _add_brand_relationships(builder, evidence):
    record = _get_record(evidence, "brand", "brand.impersonation")
    if not record:
        return
    observation, uncertainty = record
    source_domain = _normalize_host(observation.get("registrable_domain"))
    matches = observation.get("matches")
    if source_domain is None or not isinstance(matches, list):
        return
    reference = {"key": "brand", "source": "brand.impersonation"}
    normalized_matches = set()
    for match in matches:
        if not isinstance(match, dict):
            continue
        method = match.get("method")
        strength = match.get("strength")
        brand_name = match.get("brand")
        canonical_domain = _normalize_host(match.get("canonical_domain"))
        if (
            method not in _BRAND_CANDIDATE_METHODS
            or strength not in {"weak", "moderate", "strong_candidate"}
            or not isinstance(brand_name, str)
            or not brand_name.strip()
            or len(brand_name) > 64
            or canonical_domain is None
        ):
            continue
        normalized_matches.add(
            (canonical_domain, brand_name.strip(), method, strength)
        )
    normalized_matches = sorted(normalized_matches)
    if len(normalized_matches) > MAX_GRAPH_ITEMS_PER_SOURCE:
        builder.truncated = True
    for canonical_domain, brand_name, method, strength in normalized_matches[
        :MAX_GRAPH_ITEMS_PER_SOURCE
    ]:
        brand_node_id = f"brand-domain:{canonical_domain}"
        builder.add_edge(
            "resembles_brand_domain",
            f"domain:{source_domain}",
            "registrable_domain",
            source_domain,
            brand_node_id,
            "brand_reference",
            f"{brand_name} ({canonical_domain})",
            reference,
            uncertainty,
            "Similarity is heuristic and does not establish affiliation or phishing.",
            {"method": method, "strength": strength},
        )


def analyze_relationship_graph(evidence):
    """Build a bounded relationship graph from serialized evidence only."""
    if not isinstance(evidence, dict):
        return _record(
            "error",
            "invalid_input",
            [],
            [],
            [*_BASE_UNCERTAINTY, "Serialized evidence must be an object."],
        )

    builder = _GraphBuilder()
    _add_dns_relationships(builder, evidence)
    _add_html_relationships(builder, evidence)
    _add_brand_relationships(builder, evidence)
    _add_visual_relationships(builder, evidence)
    return builder.result()