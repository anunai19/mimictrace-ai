import datetime
import json
import subprocess
import sys
from typing import Any, Dict, List, Optional, Tuple

import tldextract

from detection.destination_safety import DestinationSafetyError, parse_http_url
from detection.evidence import EvidenceRecord


WHOIS_TOTAL_DEADLINE_SECONDS = 5.0
WHOIS_SOCKET_TIMEOUT_SECONDS = 2
WHOIS_MAX_RESPONSE_BYTES = 64 * 1024
MAX_WHOIS_OUTPUT_BYTES = 8192
MAX_REGISTRAR_LENGTH = 256
_TLD_EXTRACTOR = tldextract.TLDExtract(
    suffix_list_urls=(),
    cache_dir=None,
    fallback_to_snapshot=True,
)

_WHOIS_WORKER_SCRIPT = r"""
import datetime
import json
import sys
import whois

response_budget = {"remaining": 64 * 1024}
original_get_socket = whois.NICClient.get_socket

class BoundedSocket:
    def __init__(self, wrapped):
        self._wrapped = wrapped

    def recv(self, size, *args):
        remaining = response_budget["remaining"]
        data = self._wrapped.recv(min(size, remaining + 1), *args)
        if len(data) > remaining:
            raise OSError("WHOIS response exceeded its byte limit")
        response_budget["remaining"] -= len(data)
        return data

    def __getattr__(self, name):
        return getattr(self._wrapped, name)

def bounded_get_socket():
    return BoundedSocket(original_get_socket())

whois.NICClient.get_socket = staticmethod(bounded_get_socket)

def safe_value(value):
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        return [safe_value(item) for item in value[:8]]
    if isinstance(value, (datetime.datetime, datetime.date)):
        return value.isoformat()[:64]
    if isinstance(value, str):
        return value[:256]
    return None

entry = whois.whois(
    sys.argv[1],
    command=False,
    flags=whois.NICClient.WHOIS_QUICK,
    inc_raw=False,
    quiet=True,
    ignore_socket_errors=False,
    timeout=2,
)
print(json.dumps({
    "creation_date": safe_value(entry.get("creation_date")),
    "expiration_date": safe_value(entry.get("expiration_date")),
    "registrar": safe_value(entry.get("registrar")),
}, allow_nan=False))
"""
_WHOIS_WORKER_SCRIPT = _WHOIS_WORKER_SCRIPT.replace(
    "64 * 1024",
    str(WHOIS_MAX_RESPONSE_BYTES),
)


def _evidence(
    status: str,
    availability: str,
    observation: Optional[Dict[str, Any]] = None,
    uncertainty: Optional[List[str]] = None,
) -> EvidenceRecord:
    return EvidenceRecord(
        source="domain.whois",
        observation={
            "availability": availability,
            **(observation or {}),
        },
        status=status,
        uncertainty=list(uncertainty or []),
    )


def _registrable_domain(url_or_hostname: str) -> str:
    if not isinstance(url_or_hostname, str) or not url_or_hostname:
        raise DestinationSafetyError("Domain input must be a non-empty URL or hostname.")
    candidate = (
        url_or_hostname
        if "://" in url_or_hostname
        else "https://" + url_or_hostname
    )
    _, hostname, _, _, _, literal_address = parse_http_url(candidate)
    if literal_address is not None:
        raise DestinationSafetyError("WHOIS lookup requires a domain hostname.")
    extracted = _TLD_EXTRACTOR(hostname)
    if not extracted.domain or not extracted.suffix:
        raise DestinationSafetyError("A registrable public-suffix domain is required.")
    return f"{extracted.domain}.{extracted.suffix}"


def _run_whois_worker(domain: str) -> Dict[str, Any]:
    try:
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                _WHOIS_WORKER_SCRIPT,
                domain,
            ],
            check=False,
            stdout=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            timeout=WHOIS_TOTAL_DEADLINE_SECONDS,
            shell=False,
        )
    except subprocess.TimeoutExpired as error:
        raise TimeoutError("WHOIS worker exceeded its hard deadline.") from error
    except OSError as error:
        raise RuntimeError("WHOIS worker could not be started.") from error

    if result.returncode != 0:
        raise RuntimeError("WHOIS worker reported a lookup failure.")
    output = result.stdout or ""
    if len(output.encode("utf-8")) > MAX_WHOIS_OUTPUT_BYTES:
        raise RuntimeError("WHOIS worker output exceeded its limit.")
    try:
        payload = json.loads(output)
    except (TypeError, json.JSONDecodeError) as error:
        raise RuntimeError("WHOIS worker returned invalid normalized data.") from error
    if not isinstance(payload, dict):
        raise RuntimeError("WHOIS worker returned an invalid response.")
    return {
        "creation_date": payload.get("creation_date"),
        "expiration_date": payload.get("expiration_date"),
        "registrar": payload.get("registrar"),
    }


def _normalize_one_date(value: Any) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    if isinstance(value, datetime.datetime):
        parsed_datetime = value
    elif isinstance(value, datetime.date):
        return value.isoformat(), "unknown", None
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            return None, None, "malformed"
        try:
            parsed_datetime = datetime.datetime.fromisoformat(
                text[:-1] + "+00:00" if text.endswith("Z") else text
            )
        except ValueError:
            try:
                parsed_date = datetime.date.fromisoformat(text)
            except ValueError:
                return None, None, "malformed"
            return parsed_date.isoformat(), "unknown", None
    else:
        return None, None, "malformed"

    timezone_status = (
        "offset_known"
        if parsed_datetime.tzinfo is not None
        and parsed_datetime.utcoffset() is not None
        else "unknown"
    )
    return parsed_datetime.isoformat(), timezone_status, None


def _normalize_date_field(
    value: Any,
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    if value is None:
        return None, None, "missing"
    values = value if isinstance(value, (list, tuple)) else [value]
    if not values:
        return None, None, "missing"

    normalized = [_normalize_one_date(item) for item in values]
    if any(error == "malformed" for _, _, error in normalized):
        return None, None, "malformed"
    distinct_dates = {date_value for date_value, _, _ in normalized}
    if len(distinct_dates) != 1:
        return None, None, "conflicting"
    date_value = normalized[0][0]
    timezone_statuses = {timezone for _, timezone, _ in normalized}
    timezone_status = (
        timezone_statuses.pop()
        if len(timezone_statuses) == 1
        else "unknown"
    )
    return date_value, timezone_status, None


def _normalize_registrar(value: Any) -> Optional[str]:
    if isinstance(value, (list, tuple)):
        candidates = [item for item in value if isinstance(item, str) and item.strip()]
        unique_candidates = list(dict.fromkeys(item.strip() for item in candidates))
        if len(unique_candidates) != 1:
            return None
        value = unique_candidates[0]
    if not isinstance(value, str):
        return None
    cleaned = " ".join(value.split())
    cleaned = "".join(character for character in cleaned if character.isprintable())
    return cleaned[:MAX_REGISTRAR_LENGTH] or None


def lookup_domain_registration(url_or_hostname: str) -> EvidenceRecord:
    """Return bounded, allowlisted WHOIS fields without raw or contact data."""
    try:
        domain = _registrable_domain(url_or_hostname)
    except (DestinationSafetyError, TypeError, ValueError):
        return _evidence(
            "error",
            "invalid_input",
            uncertainty=["A valid registrable domain could not be derived."],
        )

    try:
        payload = _run_whois_worker(domain)
    except TimeoutError:
        return _evidence(
            "error",
            "timeout",
            {"domain": domain},
            ["WHOIS lookup was terminated at the hard five-second deadline."],
        )
    except Exception:
        return _evidence(
            "error",
            "lookup_error",
            {"domain": domain},
            ["WHOIS lookup failed; raw response and internal errors are omitted."],
        )

    observation: Dict[str, Any] = {"domain": domain}
    uncertainty = [
        "Registration data may be privacy-protected, incomplete, or stale.",
        "Domain age alone does not establish whether a site is malicious or legitimate.",
    ]
    field_errors = []
    for field, payload_name in (
        ("creation_date", "creation_date"),
        ("expiration_date", "expiration_date"),
    ):
        normalized, timezone_status, error = _normalize_date_field(
            payload.get(payload_name)
        )
        observation[field] = normalized
        observation[f"{field}_timezone"] = timezone_status
        if error == "missing":
            field_errors.append(f"{field}_missing")
        elif error == "malformed":
            field_errors.append(f"{field}_malformed")
        elif error == "conflicting":
            field_errors.append(f"{field}_conflicting")
        if timezone_status == "unknown":
            uncertainty.append(f"{field} timezone is unknown or date-only.")

    registrar = _normalize_registrar(payload.get("registrar"))
    observation["registrar"] = registrar
    if registrar is None:
        field_errors.append("registrar_unavailable")
    observation["field_issues"] = field_errors

    has_data = any(
        observation[field] is not None
        for field in ("creation_date", "expiration_date", "registrar")
    )
    if not has_data:
        return _evidence(
            "unavailable",
            "registration_data_unavailable",
            observation,
            uncertainty,
        )
    if field_errors:
        uncertainty.append("Some registration fields are missing or inconsistent.")
    return _evidence("observed", "partial" if field_errors else "available", observation, uncertainty)