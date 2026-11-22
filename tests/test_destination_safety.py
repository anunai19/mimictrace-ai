import ipaddress
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import dns.resolver

from detection.destination_safety import (
    DEFAULT_DNS_TIMEOUT_SECONDS,
    DestinationResolutionError,
    DestinationSafetyError,
    is_allowed_public_address,
    parse_http_url,
    validate_destination,
    validated_addresses_for_connection,
)
from detection.url_analyzer import analyze_url


class FakeDNSAnswer(list):

    def __init__(self, addresses=(), *, has_rrset=True):
        super().__init__(SimpleNamespace(address=address) for address in addresses)
        self.rrset = object() if has_rrset else None


class FakeDNSResolver:

    def __init__(self, responses):
        self.responses = responses
        self.calls = []
        self.timeout = None

    def resolve(self, hostname, record_type, **kwargs):
        self.calls.append((hostname, record_type, kwargs))
        response = self.responses[record_type]
        if isinstance(response, Exception):
            raise response
        return response


class TestDestinationSafety(unittest.TestCase):

    def mock_production_resolver(self, responses):
        resolver = FakeDNSResolver(responses)
        resolver_patcher = patch(
            "detection.destination_safety.dns.resolver.Resolver",
            return_value=resolver,
        )
        getaddrinfo_patcher = patch(
            "socket.getaddrinfo",
            side_effect=AssertionError("System DNS access is forbidden."),
        )
        resolver_patcher.start()
        getaddrinfo_patcher.start()
        self.addCleanup(getaddrinfo_patcher.stop)
        self.addCleanup(resolver_patcher.stop)
        return resolver

    def assert_production_resolver_calls(self, resolver, expected_types, timeout):
        self.assertEqual(resolver.timeout, timeout)
        self.assertEqual(
            [record_type for _, record_type, _ in resolver.calls],
            expected_types,
        )
        for hostname, _, kwargs in resolver.calls:
            self.assertEqual(hostname, "xn--bcher-kva.example")
            self.assertGreater(kwargs["lifetime"], 0)
            self.assertLessEqual(kwargs["lifetime"], timeout)
            self.assertIs(kwargs["search"], False)
            self.assertIs(kwargs["raise_on_no_answer"], False)

    def test_production_dns_resolver_accepts_ipv4_a_answer(self):
        timeout = 1.25
        resolver = self.mock_production_resolver({
            "A": FakeDNSAnswer(["8.8.8.8"]),
            "AAAA": dns.resolver.NoAnswer(),
        })

        destination = validate_destination(
            "https://BÜCHER.example.:443/",
            timeout=timeout,
        )

        self.assertEqual(destination.hostname, "xn--bcher-kva.example")
        self.assertEqual(
            tuple(str(address) for address in destination._resolved_addresses),
            ("8.8.8.8",),
        )
        self.assert_production_resolver_calls(resolver, ["A", "AAAA"], timeout)

    def test_production_dns_resolver_accepts_ipv6_aaaa_answer(self):
        timeout = 1.25
        resolver = self.mock_production_resolver({
            "A": dns.resolver.NoAnswer(),
            "AAAA": FakeDNSAnswer(["2001:4860:4860::8888"]),
        })

        destination = validate_destination(
            "https://BÜCHER.example.:443/",
            timeout=timeout,
        )

        self.assertEqual(destination.hostname, "xn--bcher-kva.example")
        self.assertEqual(
            tuple(str(address) for address in destination._resolved_addresses),
            ("2001:4860:4860::8888",),
        )
        self.assert_production_resolver_calls(resolver, ["A", "AAAA"], timeout)

    def test_production_dns_resolver_timeout_fails_closed(self):
        timeout = 1.25
        resolver = self.mock_production_resolver({
            "A": TimeoutError("synthetic DNS timeout"),
            "AAAA": FakeDNSAnswer(["2001:4860:4860::8888"]),
        })

        with self.assertRaises(DestinationResolutionError):
            validate_destination(
                "https://BÜCHER.example.:443/",
                timeout=timeout,
            )

        self.assert_production_resolver_calls(resolver, ["A"], timeout)

    def test_production_dns_resolver_failure_fails_closed(self):
        timeout = 1.25
        resolver = self.mock_production_resolver({
            "A": OSError("synthetic DNS resolver failure"),
            "AAAA": FakeDNSAnswer(["2001:4860:4860::8888"]),
        })

        with self.assertRaises(DestinationResolutionError):
            validate_destination(
                "https://BÜCHER.example.:443/",
                timeout=timeout,
            )

        self.assert_production_resolver_calls(resolver, ["A"], timeout)

    def test_production_dns_resolver_rejects_mixed_public_and_private_answers(self):
        timeout = 1.25
        resolver = self.mock_production_resolver({
            "A": FakeDNSAnswer(["8.8.8.8"]),
            "AAAA": FakeDNSAnswer(["::1"]),
        })

        with self.assertRaises(DestinationSafetyError):
            validate_destination(
                "https://BÜCHER.example.:443/",
                timeout=timeout,
            )

        self.assert_production_resolver_calls(resolver, ["A", "AAAA"], timeout)

    def test_production_dns_resolver_empty_results_fail_closed(self):
        timeout = 1.25
        empty_responses = (
            {
                "A": dns.resolver.NoAnswer(),
                "AAAA": dns.resolver.NoAnswer(),
            },
            {
                "A": FakeDNSAnswer(has_rrset=False),
                "AAAA": FakeDNSAnswer(has_rrset=False),
            },
        )
        for responses in empty_responses:
            with self.subTest(responses=responses):
                resolver = self.mock_production_resolver(responses)
                with self.assertRaisesRegex(
                    DestinationResolutionError,
                    "no addresses",
                ):
                    validate_destination(
                        "https://BÜCHER.example.:443/",
                        timeout=timeout,
                    )
                self.assert_production_resolver_calls(
                    resolver,
                    ["A", "AAAA"],
                    timeout,
                )

    def test_production_dns_partial_family_failure_fails_closed(self):
        timeout = 1.25
        resolver = self.mock_production_resolver({
            "A": FakeDNSAnswer(["8.8.8.8"]),
            "AAAA": TimeoutError("synthetic AAAA timeout"),
        })

        with self.assertRaises(DestinationResolutionError):
            validate_destination(
                "https://BÜCHER.example.:443/",
                timeout=timeout,
            )

        self.assert_production_resolver_calls(resolver, ["A", "AAAA"], timeout)

    def test_public_ipv4_and_ipv6_literals_are_accepted_without_resolution(self):
        for url, expected_host in (
            ("https://8.8.8.8/path", "8.8.8.8"),
            ("https://[2001:4860:4860::8888]/path", "2001:4860:4860::8888"),
        ):
            with self.subTest(url=url):
                destination = validate_destination(
                    url,
                    resolver=lambda *_args: self.fail("IP literals must not be resolved"),
                )
                self.assertEqual(destination.hostname, expected_host)
                self.assertTrue(destination.is_ip_address)

    def test_private_and_reserved_ipv4_ipv6_literals_are_rejected(self):
        blocked_urls = (
            "http://127.0.0.1/",
            "http://10.0.0.1/",
            "http://169.254.1.1/",
            "http://192.0.2.1/",
            "http://224.0.0.1/",
            "http://0.0.0.0/",
            "http://[::1]/",
            "http://[fc00::1]/",
            "http://[fe80::1]/",
            "http://[2001:db8::1]/",
            "http://[ff02::1]/",
            "http://[::]/",
            "https://3232235777/",
        )
        for url in blocked_urls:
            with self.subTest(url=url):
                with self.assertRaises(DestinationSafetyError):
                    validate_destination(url)

    def test_address_classifier_handles_ipv4_mapped_ipv6(self):
        self.assertFalse(is_allowed_public_address("::ffff:127.0.0.1"))
        self.assertFalse(is_allowed_public_address("::ffff:10.0.0.1"))
        self.assertTrue(is_allowed_public_address("::ffff:8.8.8.8"))
        self.assertFalse(is_allowed_public_address("not-an-ip"))

    def test_hostname_is_normalized_for_idn_case_and_trailing_dot(self):
        calls = []

        def resolver(hostname, timeout):
            calls.append((hostname, timeout))
            return ["8.8.8.8"]

        destination = validate_destination(
            "https://BÜCHER.example.:443/path",
            resolver=resolver,
            timeout=1.25,
        )

        self.assertEqual(destination.hostname, "xn--bcher-kva.example")
        self.assertEqual(destination.port, 443)
        self.assertEqual(calls, [("xn--bcher-kva.example", 1.25)])

    def test_all_dns_answers_must_be_public(self):
        resolvers = (
            lambda *_args: ["127.0.0.1"],
            lambda *_args: ["8.8.8.8", "10.0.0.1"],
            lambda *_args: ["2001:4860:4860::8888", "fe80::1"],
        )
        for resolver in resolvers:
            with self.subTest(resolver=resolver):
                with self.assertRaises(DestinationSafetyError):
                    validate_destination(
                        "https://example.test/",
                        resolver=resolver,
                    )

    def test_empty_dns_result_and_resolution_failure_are_rejected(self):
        with self.assertRaisesRegex(DestinationResolutionError, "no addresses"):
            validate_destination("https://example.test/", resolver=lambda *_args: [])

        def failing_resolver(*_args):
            raise TimeoutError("synthetic DNS timeout")

        with self.assertRaisesRegex(DestinationResolutionError, "resolution failed"):
            validate_destination(
                "https://example.test/",
                resolver=failing_resolver,
            )

    def test_strict_url_parser_accepts_only_absolute_http_https_urls(self):
        parsed = parse_http_url("http://example.test/path?q=1")

        self.assertEqual(parsed[:5], ("http", "example.test", 80, "/path", "q=1"))
        with self.assertRaises(DestinationSafetyError):
            parse_http_url("example.test")

    def test_invalid_schemes_userinfo_and_malformed_urls_are_rejected(self):
        invalid_urls = (
            "ftp://example.test/",
            "file:///etc/passwd",
            "https:///missing-host",
            "https://user@example.test/",
            "https://user:pass@example.test/",
            "https://[not-ipv6]/",
            "https://bad host/",
            "https://example.test\\@127.0.0.1/",
        )
        for url in invalid_urls:
            with self.subTest(url=url):
                with self.assertRaises(DestinationSafetyError):
                    parse_http_url(url)

    def test_malformed_and_disallowed_ports_are_rejected(self):
        for url in (
            "https://example.test:/",
            "https://example.test:abc/",
            "https://example.test:444/",
            "https://example.test:0/",
        ):
            with self.subTest(url=url):
                with self.assertRaises(DestinationSafetyError):
                    parse_http_url(url)

    def test_url_length_limit_is_enforced(self):
        oversized_url = "https://example.test/" + ("a" * 2048)

        with self.assertRaisesRegex(DestinationSafetyError, "maximum length"):
            parse_http_url(oversized_url)

    def test_connection_accessor_returns_immutable_revalidated_addresses(self):
        destination = validate_destination(
            "https://example.test/",
            resolver=lambda *_args: ["8.8.8.8", "2001:4860:4860::8888"],
        )

        addresses = validated_addresses_for_connection(destination)

        self.assertIsInstance(addresses, tuple)
        self.assertEqual(
            tuple(str(address) for address in addresses),
            ("8.8.8.8", "2001:4860:4860::8888"),
        )

    def test_connection_accessor_rejects_unvalidated_or_non_tls_destinations(self):
        with self.assertRaises(DestinationSafetyError):
            validated_addresses_for_connection(object())

        http_destination = validate_destination(
            "http://8.8.8.8/",
        )
        with self.assertRaisesRegex(DestinationSafetyError, "HTTPS"):
            validated_addresses_for_connection(http_destination)

    def test_connection_accessor_rechecks_addresses(self):
        destination = validate_destination("https://8.8.8.8/")
        object.__setattr__(
            destination,
            "_resolved_addresses",
            (ipaddress.ip_address("127.0.0.1"),),
        )

        with self.assertRaisesRegex(DestinationSafetyError, "invalid"):
            validated_addresses_for_connection(destination)

    def test_dns_timeout_must_be_positive_and_finite(self):
        for timeout in (0, -1, float("inf"), float("nan"), True):
            with self.subTest(timeout=timeout):
                with self.assertRaises(ValueError):
                    validate_destination(
                        "https://example.test/",
                        resolver=lambda *_args: ["8.8.8.8"],
                        timeout=timeout,
                    )

    def test_default_dns_timeout_is_bounded(self):
        self.assertEqual(DEFAULT_DNS_TIMEOUT_SECONDS, 2.0)
        self.assertFalse(
            is_allowed_public_address(ipaddress.ip_address("192.0.2.1"))
        )

    def test_existing_url_analysis_does_not_make_network_requests(self):
        with patch("socket.getaddrinfo", side_effect=AssertionError("DNS access")), \
             patch("dns.resolver.Resolver", side_effect=AssertionError("DNS access")), \
             patch("requests.get", side_effect=AssertionError("HTTP access")), \
             patch(
                 "requests.sessions.Session.request",
                 side_effect=AssertionError("HTTP access"),
             ):
            result = analyze_url("https://example.com/login")

        self.assertEqual(result["hostname"], "example.com")
        self.assertEqual(result["features"]["suspicious_keyword_count"], 1)


if __name__ == "__main__":
    unittest.main()
