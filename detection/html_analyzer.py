import ipaddress
import math
import re
from functools import lru_cache
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import tldextract

from detection.evidence import EvidenceRecord


MAX_HTML_BODY_BYTES = 1024 * 1024
MAX_HTML_TAG_EVENTS = 20_000
MAX_ANALYZED_TARGETS = 2_000
MAX_ACTIVE_FORMS = 128
MAX_ATTRIBUTE_VALUE_CHARS = 4_096
MAX_TARGET_URL_CHARS = 2_048
PARSER_CHUNK_CHARS = 4_096


_TLD_EXTRACTOR = tldextract.TLDExtract(
    suffix_list_urls=(),
    cache_dir=None,
    fallback_to_snapshot=True,
)
_MAX_REPORTED_TARGETS = 20
_LOGIN_NAME_PATTERN = re.compile(
    r"(?:user(?:name)?|email|login|account|pass(?:word)?)",
    re.IGNORECASE,
)
_HIDDEN_STYLE_PATTERN = re.compile(
    r"(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|"
    r"(?:width|height)\s*:\s*0(?:px|em|rem|%)?)",
    re.IGNORECASE,
)
_META_REFRESH_PATTERN = re.compile(
    r"^\s*([0-9]+(?:\.[0-9]+)?)\s*;\s*url\s*=\s*['\"]?([^'\"]*)",
    re.IGNORECASE,
)
_SUSPICIOUS_SCHEMES = frozenset({"javascript", "data", "file", "vbscript"})
_RELEVANT_ATTRIBUTES = frozenset({
    "action",
    "aria-hidden",
    "autocomplete",
    "content",
    "hidden",
    "href",
    "http-equiv",
    "id",
    "name",
    "src",
    "style",
    "type",
})


class _AnalysisBudgetExceeded(Exception):
    pass


def _record(status, availability, observation, uncertainty):
    return EvidenceRecord(
        source="html.static",
        observation={"availability": availability, **observation},
        status=status,
        uncertainty=uncertainty,
    )


def _host(url):
    try:
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            return None
        return parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    except (UnicodeError, ValueError, AttributeError):
        return None


@lru_cache(maxsize=256)
def _registrable_domain(hostname):
    if not hostname:
        return None
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        return address.compressed.lower()
    try:
        extracted = _TLD_EXTRACTOR(hostname)
    except Exception:
        return None
    if not extracted.domain or not extracted.suffix:
        return None
    return f"{extracted.domain}.{extracted.suffix}".lower()


def _target_info(raw_target, base_url, page_host, page_domain):
    if not isinstance(raw_target, str) or len(raw_target) > MAX_TARGET_URL_CHARS:
        return {"kind": "invalid", "reason": "target_too_long"}
    target_url = urljoin(base_url, raw_target)
    try:
        parsed = urlsplit(target_url)
        scheme = parsed.scheme.lower()
        hostname = _host(target_url)
        username_present = parsed.username is not None or parsed.password is not None
    except (ValueError, AttributeError):
        return {"kind": "invalid"}

    if scheme in _SUSPICIOUS_SCHEMES:
        return {"kind": "suspicious_scheme", "scheme": scheme}
    if scheme not in {"http", "https"} or not hostname:
        return {"kind": "non_web_scheme", "scheme": scheme or "relative"}

    target_domain = _registrable_domain(hostname)
    same_host = hostname == page_host
    same_domain = (
        None
        if target_domain is None or page_domain is None
        else target_domain == page_domain
    )
    info = {
        "kind": "web",
        "host": hostname[:253],
        "same_host": same_host,
        "same_registrable_domain": same_domain,
    }
    if username_present:
        info["credentials_present"] = True
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return info
    if not address.is_global:
        info["non_global_ip_literal"] = True
    return info


def _find_attribute(attributes, name):
    found = False
    value = None
    for attribute_name, attribute_value in attributes:
        if attribute_name == name:
            found = True
            value = attribute_value
    return found, value


class _BaseHrefFinder(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tag_events = 0
        self.base_href = None
        self.base_found = False
        self.truncated = False

    def handle_starttag(self, tag, attrs):
        self.tag_events += 1
        if self.tag_events > MAX_HTML_TAG_EVENTS:
            raise _AnalysisBudgetExceeded()
        if tag != "base" or self.base_found:
            return
        found, value = _find_attribute(attrs, "href")
        if not found:
            return
        self.base_found = True
        if value is None:
            self.base_href = ""
        else:
            value = str(value)
            if len(value) > MAX_TARGET_URL_CHARS:
                self.truncated = True
                return
            self.base_href = value


class _HTMLIndicatorParser(HTMLParser):
    def __init__(self, base_url, page_host, page_domain):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.page_host = page_host
        self.page_domain = page_domain
        self.tag_events = 0
        self.targets_analyzed = 0
        self.truncated = False
        self.active_forms = []
        self.password_input_count = 0
        self.login_form_count = 0
        self.counts = {
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
        self.targets = {
            "external_form_actions": [],
            "mismatched_form_actions": [],
            "invalid_form_actions": [],
            "hidden_element_tags": [],
            "external_scripts": [],
            "iframes": [],
            "meta_refreshes": [],
            "external_links": [],
            "suspicious_link_schemes": [],
        }

    def _count_tag_event(self):
        self.tag_events += 1
        if self.tag_events > MAX_HTML_TAG_EVENTS:
            self.truncated = True
            raise _AnalysisBudgetExceeded()

    def _attributes(self, attrs):
        result = {}
        for name, value in attrs:
            if name not in _RELEVANT_ATTRIBUTES:
                continue
            if value is None:
                result[name] = ""
                continue
            value = str(value)
            if len(value) > MAX_ATTRIBUTE_VALUE_CHARS:
                self.truncated = True
                value = value[:MAX_ATTRIBUTE_VALUE_CHARS]
            result[name] = value
        return result

    def _target(self, raw_target):
        if self.targets_analyzed >= MAX_ANALYZED_TARGETS:
            self.truncated = True
            raise _AnalysisBudgetExceeded()
        self.targets_analyzed += 1
        if len(raw_target) > MAX_TARGET_URL_CHARS:
            self.truncated = True
        return _target_info(raw_target, self.base_url, self.page_host, self.page_domain)

    def _store(self, category, info, count_name=None):
        if count_name is not None:
            self.counts[count_name] += 1
        if len(self.targets[category]) < _MAX_REPORTED_TARGETS:
            self.targets[category].append(info)

    def _handle_form_start(self, attrs):
        if len(self.active_forms) >= MAX_ACTIVE_FORMS:
            self.truncated = True
            raise _AnalysisBudgetExceeded()
        form = {"has_login_signal": False}
        self.active_forms.append(form)
        action = attrs.get("action", "").strip()
        if not action:
            return
        info = self._target(action)
        if info["kind"] == "web" and not info["same_host"]:
            self._store(
                "external_form_actions",
                info,
                "external_form_actions",
            )
            if info["same_registrable_domain"] is False:
                self.counts["cross_domain_form_actions"] += 1
                if len(self.targets["mismatched_form_actions"]) < _MAX_REPORTED_TARGETS:
                    self.targets["mismatched_form_actions"].append(info)
        elif info["kind"] in {"suspicious_scheme", "invalid"}:
            self._store(
                "invalid_form_actions",
                info,
                "invalid_form_actions",
            )

    def _finish_form(self):
        form = self.active_forms.pop()
        if form["has_login_signal"]:
            self.login_form_count += 1

    def _finish_open_forms(self):
        while self.active_forms:
            self._finish_form()

    def _handle_input(self, attrs):
        input_type = attrs.get("type", "").strip().lower()
        names = " ".join(
            attrs.get(attribute, "")
            for attribute in ("name", "id", "autocomplete")
        )
        has_login_signal = bool(_LOGIN_NAME_PATTERN.search(names))
        if input_type == "password":
            self.password_input_count += 1
            has_login_signal = True
        if self.active_forms and has_login_signal:
            self.active_forms[-1]["has_login_signal"] = True

    def _handle_hidden(self, tag, attrs):
        style = attrs.get("style", "")
        if (
            "hidden" in attrs
            or attrs.get("aria-hidden", "").strip().lower() == "true"
            or _HIDDEN_STYLE_PATTERN.search(style)
        ):
            self.counts["hidden_elements"] += 1
            if len(self.targets["hidden_element_tags"]) < _MAX_REPORTED_TARGETS:
                self.targets["hidden_element_tags"].append(tag[:32])

    def _handle_script(self, attrs):
        src = attrs.get("src")
        if not src:
            return
        info = self._target(src)
        if info["kind"] == "web" and not info["same_host"]:
            self._store("external_scripts", info, "external_scripts")

    def _handle_iframe(self, attrs):
        src = attrs.get("src")
        if not src:
            return
        info = self._target(src)
        if info["kind"] == "web":
            self._store("iframes", info, "iframes")

    def _handle_meta(self, attrs):
        if attrs.get("http-equiv", "").strip().lower() != "refresh":
            return
        content = attrs.get("content", "")
        match = _META_REFRESH_PATTERN.match(content)
        if not match:
            item = {"delay_seconds": None, "target": {"kind": "unparsed"}}
        else:
            try:
                delay = float(match.group(1))
            except ValueError:
                delay = None
            if delay is not None and not math.isfinite(delay):
                delay = None
            target = match.group(2).strip()
            item = {
                "delay_seconds": delay,
                "target": self._target(target),
            }
        self._store("meta_refreshes", item, "meta_refreshes")

    def _handle_link(self, attrs):
        href = attrs.get("href")
        if href is None:
            return
        info = self._target(href)
        if (
            info["kind"] == "web"
            and info["same_registrable_domain"] is False
        ):
            self._store("external_links", info, "external_links")
        elif info["kind"] in {"suspicious_scheme", "invalid"}:
            self._store(
                "suspicious_link_schemes",
                info,
                "suspicious_link_schemes",
            )

    def handle_starttag(self, tag, attrs):
        self._count_tag_event()
        attrs = self._attributes(attrs)
        self._handle_hidden(tag, attrs)
        if tag == "form":
            self._handle_form_start(attrs)
        elif tag == "input":
            self._handle_input(attrs)
        elif tag == "script":
            self._handle_script(attrs)
        elif tag == "iframe":
            self._handle_iframe(attrs)
        elif tag == "meta":
            self._handle_meta(attrs)
        elif tag == "a":
            self._handle_link(attrs)

    def handle_endtag(self, tag):
        self._count_tag_event()
        if tag == "form" and self.active_forms:
            self._finish_form()


def _feed_bounded(parser, text):
    truncated = False
    try:
        for offset in range(0, len(text), PARSER_CHUNK_CHARS):
            parser.feed(text[offset:offset + PARSER_CHUNK_CHARS])
        parser.close()
    except _AnalysisBudgetExceeded:
        truncated = True
    return truncated


def _empty_observation(page_host=None):
    return {
        "page_host": page_host,
        "indicators": [],
    }


def analyze_html_document(
    html_bytes,
    page_url,
    *,
    final_url=None,
    redirect_count=0,
):
    """Analyze supplied HTML bytes only with bounded, streaming parser state."""
    uncertainty = [
        "Only static HTML was inspected; scripts were not executed and computed styles were not evaluated.",
        "Form, hidden-element, and external-resource indicators can have benign explanations.",
        "HTML indicators are evidence only and do not establish phishing or malicious intent.",
        "Only bounded host-level destinations are reported; page content and form values are not retained.",
        "HTML is decoded as UTF-8 with replacement for malformed byte sequences.",
    ]
    if not isinstance(html_bytes, bytes) or not html_bytes:
        return _record("error", "invalid_input", {"indicators": []}, uncertainty)
    if len(html_bytes) > MAX_HTML_BODY_BYTES:
        return _record(
            "error",
            "response_too_large",
            {"indicators": []},
            uncertainty,
        )
    if (
        not isinstance(page_url, str)
        or not isinstance(final_url or page_url, str)
        or len(page_url) > MAX_TARGET_URL_CHARS
        or len(final_url or page_url) > MAX_TARGET_URL_CHARS
    ):
        return _record("error", "invalid_input", {"indicators": []}, uncertainty)
    if (
        isinstance(redirect_count, bool)
        or not isinstance(redirect_count, int)
        or redirect_count < 0
        or redirect_count > 3
    ):
        return _record("error", "invalid_input", {"indicators": []}, uncertainty)

    effective_url = final_url or page_url
    page_host = _host(effective_url)
    page_domain = _registrable_domain(page_host)
    if not page_host:
        return _record("error", "invalid_page_url", {"indicators": []}, uncertainty)

    try:
        html_text = html_bytes.decode("utf-8", errors="replace")
        base_finder = _BaseHrefFinder()
        base_truncated = _feed_bounded(base_finder, html_text)
        base_url = effective_url
        if base_finder.base_href is not None:
            base_url = urljoin(effective_url, base_finder.base_href)

        parser = _HTMLIndicatorParser(base_url, page_host, page_domain)
        parser_truncated = _feed_bounded(parser, html_text)
        parser._finish_open_forms()
        analysis_truncated = (
            base_truncated
            or base_finder.truncated
            or parser_truncated
            or parser.truncated
        )
        if analysis_truncated:
            uncertainty.append(
                "Analysis stopped at a fixed parser-work limit; counts may be incomplete."
            )

        indicator_values = (
            ("password_inputs", parser.password_input_count),
            ("login_like_forms", parser.login_form_count),
            ("external_form_actions", parser.counts["external_form_actions"]),
            ("cross_domain_form_actions", parser.counts["cross_domain_form_actions"]),
            ("invalid_form_actions", parser.counts["invalid_form_actions"]),
            ("hidden_elements", parser.counts["hidden_elements"]),
            ("external_scripts", parser.counts["external_scripts"]),
            ("iframes", parser.counts["iframes"]),
            ("meta_refreshes", parser.counts["meta_refreshes"]),
            ("external_links", parser.counts["external_links"]),
            ("suspicious_link_schemes", parser.counts["suspicious_link_schemes"]),
        )
        indicators = [
            {"type": name, "count": count}
            for name, count in indicator_values
            if count
        ]
        if redirect_count:
            indicators.append({
                "type": "http_redirects",
                "count": redirect_count,
                "final_host": page_host,
            })

        observation = {
            "original_host": _host(page_url),
            "page_host": page_host,
            "redirect_changed_host": _host(page_url) != page_host if redirect_count else False,
            "redirect_count": redirect_count,
            "analysis_truncated": analysis_truncated,
            "counts": {
                name: count
                for name, count in indicator_values
            },
            **parser.targets,
            "indicators": indicators,
        }
        return _record("observed", "available", observation, uncertainty)
    except Exception:
        return _record(
            "error",
            "parse_failed",
            _empty_observation(page_host),
            [*uncertainty, "Static HTML parsing failed; internal details are omitted."],
        )
