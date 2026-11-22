import ipaddress
import math
import re
import time
from dataclasses import dataclass
from typing import Callable, Iterable, Optional, Tuple, Union
from urllib.parse import urlsplit

import dns.resolver


MAX_URL_LENGTH = 2048
DEFAULT_DNS_TIMEOUT_SECONDS = 2.0
ALLOWED_PORTS = frozenset({80, 443})
_HOST_LABEL_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
Resolver = Callable[[str, float], Iterable[Union[str, _IPAddress]]]


class DestinationSafetyError(ValueError):
    """Raised when a destination cannot be safely validated."""


class DestinationResolutionError(DestinationSafetyError):
    """Raised when a hostname cannot be resolved within the configured policy."""


@dataclass(frozen=True)
class ValidatedDestination:
    scheme: str
    hostname: str
    port: int
    path: str
    query: str
    is_ip_address: bool
    _resolved_addresses: Tuple[_IPAddress, ...]


def _normalize_hostname(hostname: str) -> Tuple[str, Optional[_IPAddress]]:
    if not hostname or "%" in hostname:
        raise DestinationSafetyError("Destination hostname is invalid.")

    try:
        address = ipaddress.ip_address(hostname)
        return address.compressed.lower(), address
    except ValueError:
        pass

    try:
        ascii_hostname = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise DestinationSafetyError("Destination hostname is invalid.") from error

    if ascii_hostname.endswith("."):
        ascii_hostname = ascii_hostname[:-1]
    if (
        not ascii_hostname
        or len(ascii_hostname) > 253
        or ascii_hostname.endswith(".")
    ):
        raise DestinationSafetyError("Destination hostname is invalid.")

    labels = ascii_hostname.split(".")
    if any(not _HOST_LABEL_PATTERN.fullmatch(label) for label in labels):
        raise DestinationSafetyError("Destination hostname is invalid.")
    if all(character in "0123456789." for character in ascii_hostname):
        raise DestinationSafetyError("Numeric destination hostname is invalid.")

    return ascii_hostname, None


def parse_http_url(url: str) -> Tuple[str, str, int, str, str, Optional[_IPAddress]]:
    if not isinstance(url, str) or not url:
        raise DestinationSafetyError("Destination URL must be a non-empty string.")
    if len(url) > MAX_URL_LENGTH:
        raise DestinationSafetyError("Destination URL exceeds the maximum length.")
    if url != url.strip() or any(ord(character) <= 0x20 for character in url):
        raise DestinationSafetyError("Destination URL contains whitespace or controls.")
    if "\\" in url:
        raise DestinationSafetyError("Destination URL contains an invalid separator.")

    try:
        parsed = urlsplit(url)
    except ValueError as error:
        raise DestinationSafetyError("Destination URL is malformed.") from error

    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.netloc:
        raise DestinationSafetyError("Only absolute HTTP and HTTPS URLs are accepted.")
    if "@" in parsed.netloc or parsed.username is not None or parsed.password is not None:
        raise DestinationSafetyError("Destination URL userinfo is not accepted.")
    if not parsed.hostname:
        raise DestinationSafetyError("Destination URL must include a hostname.")

    try:
        explicit_port = parsed.port
    except ValueError as error:
        raise DestinationSafetyError("Destination URL port is malformed.") from error
    if parsed.netloc.endswith(":"):
        raise DestinationSafetyError("Destination URL port is malformed.")

    port = explicit_port if explicit_port is not None else (
        443 if scheme == "https" else 80
    )
    if port not in ALLOWED_PORTS:
        raise DestinationSafetyError("Only destination ports 80 and 443 are accepted.")

    hostname, address = _normalize_hostname(parsed.hostname)
    return scheme, hostname, port, parsed.path or "/", parsed.query, address


def is_allowed_public_address(address: Union[str, _IPAddress]) -> bool:
    try:
        parsed_address = (
            address if isinstance(address, (ipaddress.IPv4Address, ipaddress.IPv6Address))
            else ipaddress.ip_address(address)
        )
    except (TypeError, ValueError):
        return False

    if isinstance(parsed_address, ipaddress.IPv6Address):
        mapped_ipv4 = parsed_address.ipv4_mapped
        if mapped_ipv4 is not None:
            return is_allowed_public_address(mapped_ipv4)

    return (
        parsed_address.is_global
        and not parsed_address.is_loopback
        and not parsed_address.is_private
        and not parsed_address.is_link_local
        and not parsed_address.is_reserved
        and not parsed_address.is_multicast
        and not parsed_address.is_unspecified
    )


def _resolve_hostname(hostname: str, timeout: float) -> Tuple[_IPAddress, ...]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    deadline = time.monotonic() + timeout
    addresses = []

    for record_type in ("A", "AAAA"):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DestinationResolutionError("DNS resolution timed out.")
        try:
            answer = resolver.resolve(
                hostname,
                record_type,
                lifetime=remaining,
                search=False,
                raise_on_no_answer=False,
            )
        except dns.resolver.NoAnswer:
            continue
        if answer.rrset is None:
            continue
        for record in answer:
            addresses.append(ipaddress.ip_address(record.address))

    return tuple(addresses)


def validate_destination(
    url: str,
    *,
    resolver: Optional[Resolver] = None,
    timeout: float = DEFAULT_DNS_TIMEOUT_SECONDS,
) -> ValidatedDestination:
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ValueError("DNS timeout must be a positive finite number.")

    scheme, hostname, port, path, query, literal_address = parse_http_url(url)
    if literal_address is not None:
        if not is_allowed_public_address(literal_address):
            raise DestinationSafetyError("Destination address is not publicly routable.")
        return ValidatedDestination(
            scheme=scheme,
            hostname=hostname,
            port=port,
            path=path,
            query=query,
            is_ip_address=True,
            _resolved_addresses=(literal_address,),
        )

    resolve = resolver if resolver is not None else _resolve_hostname
    try:
        resolved = tuple(
            ipaddress.ip_address(address)
            for address in resolve(hostname, float(timeout))
        )
    except DestinationSafetyError:
        raise
    except Exception as error:
        raise DestinationResolutionError("Destination hostname resolution failed.") from error

    if not resolved:
        raise DestinationResolutionError("Destination hostname returned no addresses.")
    if any(not is_allowed_public_address(address) for address in resolved):
        raise DestinationSafetyError(
            "Destination hostname resolves to a non-public address."
        )

    return ValidatedDestination(
        scheme=scheme,
        hostname=hostname,
        port=port,
        path=path,
        query=query,
        is_ip_address=False,
        _resolved_addresses=resolved,
    )


def validated_addresses_for_connection(
    destination: ValidatedDestination,
) -> Tuple[_IPAddress, ...]:
    """Return validated IPs for an internal pinned transport; never serialize them."""
    if not isinstance(destination, ValidatedDestination):
        raise DestinationSafetyError("Destination was not validated.")
    if destination.scheme != "https" or destination.port != 443:
        raise DestinationSafetyError(
            "Pinned TLS connections require an HTTPS destination on port 443."
        )
    if not isinstance(destination.hostname, str) or not destination.hostname:
        raise DestinationSafetyError("Validated destination hostname is invalid.")

    addresses = destination._resolved_addresses
    if (
        not isinstance(addresses, tuple)
        or not addresses
        or any(
            not isinstance(address, (ipaddress.IPv4Address, ipaddress.IPv6Address))
            or not is_allowed_public_address(address)
            for address in addresses
        )
    ):
        raise DestinationSafetyError("Validated destination addresses are invalid.")
    return tuple(addresses)
