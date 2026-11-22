import ipaddress
import itertools
import time
from typing import Any, Dict, Iterable, List, Optional

import dns.exception
import dns.resolver

from detection.destination_safety import (
    DestinationSafetyError,
    is_allowed_public_address,
    parse_http_url,
)
from detection.evidence import EvidenceRecord


DNS_TOTAL_DEADLINE_SECONDS = 5.0
DNS_MAX_QUERY_TIMEOUT_SECONDS = 2.0
DNS_MAX_ANSWERS_PER_TYPE = 20
DNS_MAX_TXT_BYTES_PER_TYPE = 4096
DNS_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT")
_DNS_UNCERTAINTY = [
    "DNS answers may vary by resolver, network, and observation time."
]


def _hostname_from_input(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise DestinationSafetyError("DNS input must be a non-empty URL or hostname.")
    candidate = value if "://" in value else "https://" + value
    _, hostname, _, _, _, _ = parse_http_url(candidate)
    return hostname


def _record_data_length(record: Any) -> int:
    strings = getattr(record, "strings", None)
    if strings is not None:
        return sum(
            len(part if isinstance(part, bytes) else str(part).encode("utf-8"))
            for part in strings
        )
    return len(record.to_wire())


def _make_record(
    record_type: str,
    *,
    status: str,
    availability: str,
    answer_count: int = 0,
    addresses: Optional[List[str]] = None,
    txt_bytes: Optional[int] = None,
    truncated: bool = False,
    uncertainty: Optional[List[str]] = None,
) -> EvidenceRecord:
    observation: Dict[str, Any] = {
        "record_type": record_type,
        "availability": availability,
        "answer_count": answer_count,
        "truncated": truncated,
    }
    if addresses is not None:
        observation["addresses"] = addresses
    if record_type == "TXT":
        observation["bytes_accounted"] = txt_bytes or 0
        observation["data_redacted"] = True
    return EvidenceRecord(
        source=f"dns.{record_type.lower()}",
        observation=observation,
        status=status,
        uncertainty=list(_DNS_UNCERTAINTY if uncertainty is None else uncertainty),
    )


def _unqueried_record(record_type: str, reason: str) -> EvidenceRecord:
    return _make_record(
        record_type,
        status="error",
        availability="deadline_exceeded",
        uncertainty=[reason, *_DNS_UNCERTAINTY],
    )


def _summarize_answer(
    record_type: str,
    answer: Iterable[Any],
) -> EvidenceRecord:
    records = list(itertools.islice(iter(answer), DNS_MAX_ANSWERS_PER_TYPE + 1))
    truncated = len(records) > DNS_MAX_ANSWERS_PER_TYPE
    records = records[:DNS_MAX_ANSWERS_PER_TYPE]

    if record_type in {"A", "AAAA"}:
        family = 4 if record_type == "A" else 6
        addresses = []
        for record in records:
            address = ipaddress.ip_address(record.address)
            if address.version == family and is_allowed_public_address(address):
                addresses.append(address.compressed)
        if not addresses:
            return _make_record(
                record_type,
                status="unavailable",
                availability="no_public_addresses",
                uncertainty=[
                    "Only globally routable address answers are included.",
                    *_DNS_UNCERTAINTY,
                ],
            )
        return _make_record(
            record_type,
            status="observed",
            availability="available",
            answer_count=len(addresses),
            addresses=addresses,
            truncated=truncated,
        )

    if record_type == "TXT":
        accounted_bytes = 0
        for record in records:
            record_bytes = _record_data_length(record)
            allowed_bytes = DNS_MAX_TXT_BYTES_PER_TYPE - accounted_bytes
            accounted_bytes += min(record_bytes, allowed_bytes)
            if record_bytes > allowed_bytes:
                truncated = True
                break
        if not records:
            return _make_record(
                record_type,
                status="unavailable",
                availability="no_records",
                uncertainty=_DNS_UNCERTAINTY,
            )
        return _make_record(
            record_type,
            status="observed",
            availability="available",
            answer_count=len(records),
            txt_bytes=accounted_bytes,
            truncated=truncated,
        )

    if not records:
        return _make_record(
            record_type,
            status="unavailable",
            availability="no_records",
            uncertainty=_DNS_UNCERTAINTY,
        )
    return _make_record(
        record_type,
        status="observed",
        availability="available",
        answer_count=len(records),
        truncated=truncated,
        uncertainty=[
            "MX and NS targets are intentionally not exposed or queried.",
            *_DNS_UNCERTAINTY,
        ],
    )


def lookup_dns(
    url_or_hostname: str,
    *,
    resolver: Optional[Any] = None,
) -> Dict[str, EvidenceRecord]:
    """Collect bounded DNS summaries without querying returned endpoints."""
    hostname = _hostname_from_input(url_or_hostname)
    resolver_instance = resolver if resolver is not None else dns.resolver.Resolver()
    deadline = time.monotonic() + DNS_TOTAL_DEADLINE_SECONDS
    results: Dict[str, EvidenceRecord] = {}

    try:
        address_literal = ipaddress.ip_address(hostname)
    except ValueError:
        address_literal = None
    if address_literal is not None:
        if not is_allowed_public_address(address_literal):
            raise DestinationSafetyError(
                "Destination address is not publicly routable."
            )
        for record_type in DNS_RECORD_TYPES:
            results[record_type] = _make_record(
                record_type,
                status="not_run",
                availability="ip_literal",
                uncertainty=[
                    "DNS record lookup is not applicable to an IP literal.",
                    *_DNS_UNCERTAINTY,
                ],
            )
        return results

    domain_absent = False
    for index, record_type in enumerate(DNS_RECORD_TYPES):
        remaining = deadline - time.monotonic()
        if domain_absent:
            results[record_type] = _make_record(
                record_type,
                status="unavailable",
                availability="domain_absent",
                uncertainty=[
                    "The DNS resolver reported that the queried name does not exist.",
                    *_DNS_UNCERTAINTY,
                ],
            )
            continue
        if remaining <= 0:
            for pending_type in DNS_RECORD_TYPES[index:]:
                results[pending_type] = _unqueried_record(
                    pending_type,
                    "The shared DNS lookup deadline was exhausted.",
                )
            break

        query_timeout = min(DNS_MAX_QUERY_TIMEOUT_SECONDS, remaining)
        try:
            answer = resolver_instance.resolve(
                hostname,
                record_type,
                lifetime=query_timeout,
                search=False,
                raise_on_no_answer=False,
            )
        except dns.resolver.NXDOMAIN:
            domain_absent = True
            results[record_type] = _make_record(
                record_type,
                status="unavailable",
                availability="domain_absent",
                uncertainty=[
                    "The DNS resolver reported that the queried name does not exist.",
                    *_DNS_UNCERTAINTY,
                ],
            )
            continue
        except dns.resolver.NoAnswer:
            results[record_type] = _make_record(
                record_type,
                status="unavailable",
                availability="no_records",
                uncertainty=_DNS_UNCERTAINTY,
            )
            continue
        except dns.exception.Timeout:
            results[record_type] = _make_record(
                record_type,
                status="error",
                availability="timeout",
                uncertainty=[
                    "The DNS query timed out; absence of records cannot be inferred.",
                    *_DNS_UNCERTAINTY,
                ],
            )
            continue
        except Exception:
            results[record_type] = _make_record(
                record_type,
                status="error",
                availability="resolver_error",
                uncertainty=[
                    "The DNS resolver failed; returned internal error details are omitted.",
                    *_DNS_UNCERTAINTY,
                ],
            )
            continue

        if getattr(answer, "rrset", True) is None:
            results[record_type] = _make_record(
                record_type,
                status="unavailable",
                availability="no_records",
                uncertainty=_DNS_UNCERTAINTY,
            )
            continue
        try:
            results[record_type] = _summarize_answer(record_type, answer)
        except Exception:
            results[record_type] = _make_record(
                record_type,
                status="error",
                availability="invalid_response",
                uncertainty=[
                    "The DNS response could not be safely normalized.",
                    *_DNS_UNCERTAINTY,
                ],
            )

    for record_type in DNS_RECORD_TYPES:
        if record_type not in results:
            results[record_type] = _unqueried_record(
                record_type,
                "The shared DNS lookup deadline was exhausted.",
            )
    return results