import ipaddress
import math
import socket
import ssl
import time
from typing import Any, Dict, List

from detection.destination_safety import (
    DEFAULT_DNS_TIMEOUT_SECONDS,
    DestinationSafetyError,
    parse_http_url,
    validate_destination,
    validated_addresses_for_connection,
)
from detection.evidence import EvidenceRecord


TLS_TOTAL_DEADLINE_SECONDS = 5.0
TLS_CONNECT_TIMEOUT_SECONDS = 3.0
TLS_HANDSHAKE_TIMEOUT_SECONDS = 3.0
MAX_CERTIFICATE_NAMES = 20


def _record(
    status: str,
    availability: str,
    observation: Dict[str, Any] = None,
    uncertainty: List[str] = None,
) -> EvidenceRecord:
    return EvidenceRecord(
        source="tls.certificate",
        observation={
            "availability": availability,
            **(observation or {}),
        },
        status=status,
        uncertainty=list(uncertainty or []),
    )


def _valid_timeout(value: float) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(value)
        and value > 0
    )


def _socket_address(address: Any, port: int):
    if isinstance(address, ipaddress.IPv4Address):
        return socket.AF_INET, (address.compressed, port)
    if isinstance(address, ipaddress.IPv6Address):
        return socket.AF_INET6, (address.compressed, port, 0, 0)
    raise DestinationSafetyError("Validated destination address is invalid.")


def _certificate_summary(certificate: Dict[str, Any]) -> Dict[str, Any]:
    dns_names = []
    ip_names = []
    for kind, value in certificate.get("subjectAltName", ()):
        if not isinstance(value, str):
            continue
        if kind == "DNS" and len(dns_names) < MAX_CERTIFICATE_NAMES:
            dns_names.append(value[:253])
        elif kind == "IP Address" and len(ip_names) < MAX_CERTIFICATE_NAMES:
            ip_names.append(value[:45])
    return {
        "verification": "verified",
        "subject_alt_names": {
            "dns": dns_names,
            "ip": ip_names,
        },
        "not_before": certificate.get("notBefore"),
        "not_after": certificate.get("notAfter"),
    }


def analyze_tls_certificate(
    url: str,
) -> EvidenceRecord:
    """Inspect verified TLS certificate metadata without fetching page content."""
    try:
        scheme, hostname, port, _, _, _ = parse_http_url(url)
    except (DestinationSafetyError, TypeError, ValueError):
        return _record(
            "error",
            "invalid_input",
            uncertainty=["A valid HTTPS URL is required for certificate analysis."],
        )
    if scheme != "https" or port != 443:
        return _record(
            "not_run",
            "https_required",
            {"hostname": hostname},
            ["TLS certificate analysis uses HTTPS on port 443 only."],
        )
    if not _valid_timeout(TLS_TOTAL_DEADLINE_SECONDS):
        return _record("error", "configuration_error")

    deadline = time.monotonic() + TLS_TOTAL_DEADLINE_SECONDS
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return _record(
            "error",
            "timeout",
            {"hostname": hostname},
            ["TLS analysis exceeded its total deadline before validation."],
        )
    try:
        destination = validate_destination(
            url,
            timeout=min(DEFAULT_DNS_TIMEOUT_SECONDS, remaining),
        )
        addresses = validated_addresses_for_connection(destination)
    except Exception:
        if time.monotonic() >= deadline:
            return _record(
                "error",
                "timeout",
                {"hostname": hostname},
                ["Destination validation exceeded the total TLS analysis deadline."],
            )
        return _record(
            "error",
            "destination_rejected",
            {"hostname": hostname},
            ["Destination validation failed; no TLS connection was attempted."],
        )

    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return _record(
            "error",
            "timeout",
            {"hostname": hostname},
            ["Destination validation exhausted the total TLS analysis deadline."],
        )
    address = addresses[0]
    family, sockaddr = _socket_address(address, 443)
    raw_socket = None
    tls_socket = None
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout("TLS total deadline expired")
        raw_socket = socket.socket(family, socket.SOCK_STREAM)
        raw_socket.settimeout(min(TLS_CONNECT_TIMEOUT_SECONDS, remaining))
        raw_socket.connect(sockaddr)

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise socket.timeout("TLS total deadline expired")
        raw_socket.settimeout(min(TLS_HANDSHAKE_TIMEOUT_SECONDS, remaining))
        context = ssl.create_default_context()
        if (
            not context.check_hostname
            or context.verify_mode != ssl.CERT_REQUIRED
        ):
            raise ssl.SSLError("TLS verification is not enabled")
        tls_socket = context.wrap_socket(
            raw_socket,
            server_hostname=destination.hostname,
        )
        raw_socket = None
        certificate = tls_socket.getpeercert()
        summary = _certificate_summary(certificate)
        if not summary["subject_alt_names"]["dns"] and not summary["subject_alt_names"]["ip"]:
            uncertainty = [
                "The TLS peer was verified, but certificate name metadata was unavailable."
            ]
        else:
            uncertainty = [
                "Certificate metadata describes the observed endpoint and may change."
            ]
        return _record(
            "observed",
            "verified",
            {"hostname": hostname, **summary},
            uncertainty,
        )
    except ssl.SSLCertVerificationError:
        return _record(
            "error",
            "verification_failed",
            {"hostname": hostname, "verification": "failed"},
            [
                "Certificate verification failed; detailed certificate metadata was not collected.",
                "No certificate-verification bypass was attempted.",
            ],
        )
    except (socket.timeout, TimeoutError):
        return _record(
            "error",
            "timeout",
            {"hostname": hostname},
            ["TLS connection or handshake exceeded its configured timeout."],
        )
    except ssl.SSLError:
        return _record(
            "error",
            "tls_handshake_failed",
            {"hostname": hostname, "verification": "not_confirmed"},
            ["TLS certificate verification did not complete successfully."],
        )
    except OSError:
        return _record(
            "error",
            "connection_failed",
            {"hostname": hostname},
            ["The pinned TLS connection could not be completed."],
        )
    finally:
        if tls_socket is not None:
            tls_socket.close()
        if raw_socket is not None:
            raw_socket.close()