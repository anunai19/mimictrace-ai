import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import dns.exception
import dns.resolver

from detection.destination_safety import DestinationSafetyError
from detection.evidence import EvidenceRecord
from intelligence.dns_lookup import (
    DNS_MAX_ANSWERS_PER_TYPE,
    DNS_MAX_QUERY_TIMEOUT_SECONDS,
    DNS_MAX_TXT_BYTES_PER_TYPE,
    DNS_RECORD_TYPES,
    lookup_dns,
)


class IterableAnswer:

    def __init__(self, records):
        self.rrset = object()
        self.records = records

    def __iter__(self):
        return iter(self.records)


class TestDNSLookup(unittest.TestCase):

    def test_collects_record_types_and_redacts_targets_and_txt(self):
        responses = {
            "A": IterableAnswer([SimpleNamespace(address="8.8.8.8")]),
            "AAAA": IterableAnswer([SimpleNamespace(address="2001:4860:4860::8888")]),
            "MX": IterableAnswer([
                SimpleNamespace(preference=10, exchange="internal.example.test.")
            ]),
            "NS": IterableAnswer([SimpleNamespace(target="ns.internal.example.test.")]),
            "TXT": IterableAnswer([
                SimpleNamespace(strings=(b"secret-token=do-not-return",))
            ]),
        }
        resolver = Mock()
        resolver.resolve.side_effect = lambda _host, record_type, **_kwargs: responses[
            record_type
        ]

        results = lookup_dns("https://example.test/", resolver=resolver)

        self.assertEqual(tuple(results), DNS_RECORD_TYPES)
        self.assertTrue(all(isinstance(value, EvidenceRecord) for value in results.values()))
        self.assertEqual(results["A"].observation["addresses"], ["8.8.8.8"])
        self.assertEqual(results["AAAA"].observation["addresses"], ["2001:4860:4860::8888"])
        self.assertNotIn("internal.example.test", str(results["MX"].to_dict()))
        self.assertNotIn("internal.example.test", str(results["NS"].to_dict()))
        self.assertNotIn("secret-token", str(results["TXT"].to_dict()))
        self.assertTrue(results["TXT"].observation["data_redacted"])
        self.assertTrue(all(call.kwargs["search"] is False for call in resolver.resolve.call_args_list))
        self.assertTrue(
            all(call.kwargs["lifetime"] <= DNS_MAX_QUERY_TIMEOUT_SECONDS
                for call in resolver.resolve.call_args_list)
        )

    def test_missing_records_and_domain_absence_are_distinct(self):
        no_answer_resolver = Mock()
        no_answer_resolver.resolve.side_effect = dns.resolver.NoAnswer
        missing = lookup_dns("example.test", resolver=no_answer_resolver)
        self.assertTrue(all(item.status == "unavailable" for item in missing.values()))
        self.assertTrue(all(
            item.observation["availability"] == "no_records"
            for item in missing.values()
        ))

        absent_resolver = Mock()
        absent_resolver.resolve.side_effect = dns.resolver.NXDOMAIN
        absent = lookup_dns("example.test", resolver=absent_resolver)
        self.assertTrue(all(item.status == "unavailable" for item in absent.values()))
        self.assertTrue(all(
            item.observation["availability"] == "domain_absent"
            for item in absent.values()
        ))
        self.assertEqual(absent_resolver.resolve.call_count, 1)

    def test_timeout_and_other_resolver_failures_are_reported_separately(self):
        timeout_resolver = Mock()
        timeout_resolver.resolve.side_effect = dns.exception.Timeout
        timed_out = lookup_dns("example.test", resolver=timeout_resolver)
        self.assertEqual(timed_out["A"].status, "error")
        self.assertEqual(timed_out["A"].observation["availability"], "timeout")

        failure_resolver = Mock()
        failure_resolver.resolve.side_effect = RuntimeError("sensitive resolver detail")
        failed = lookup_dns("example.test", resolver=failure_resolver)
        self.assertEqual(failed["A"].status, "error")
        self.assertEqual(failed["A"].observation["availability"], "resolver_error")
        self.assertNotIn("sensitive resolver detail", str(failed["A"].to_dict()))

    def test_non_global_address_answers_are_not_exposed(self):
        resolver = Mock()
        resolver.resolve.side_effect = lambda _host, record_type, **_kwargs: (
            IterableAnswer([SimpleNamespace(address="10.0.0.1")])
            if record_type == "A"
            else dns.resolver.NoAnswer()
        )

        result = lookup_dns("example.test", resolver=resolver)

        self.assertEqual(result["A"].status, "unavailable")
        self.assertNotIn("10.0.0.1", str(result["A"].to_dict()))

    def test_txt_answer_count_and_data_are_bounded(self):
        txt_records = [
            SimpleNamespace(strings=(b"x" * 2048,)),
            SimpleNamespace(strings=(b"y" * 2048,)),
            SimpleNamespace(strings=(b"z" * 100,)),
        ]
        resolver = Mock()
        resolver.resolve.side_effect = lambda _host, record_type, **_kwargs: (
            IterableAnswer(txt_records) if record_type == "TXT" else dns.resolver.NoAnswer()
        )

        result = lookup_dns("example.test", resolver=resolver)["TXT"]

        self.assertEqual(result.observation["bytes_accounted"], DNS_MAX_TXT_BYTES_PER_TYPE)
        self.assertTrue(result.observation["truncated"])
        self.assertLessEqual(result.observation["answer_count"], DNS_MAX_ANSWERS_PER_TYPE)

    def test_answers_are_capped_at_twenty_per_record_type(self):
        addresses = [
            SimpleNamespace(address=f"8.8.8.{index}")
            for index in range(1, 26)
        ]
        resolver = Mock()
        resolver.resolve.side_effect = lambda _host, record_type, **_kwargs: (
            IterableAnswer(addresses) if record_type == "A" else dns.resolver.NoAnswer()
        )

        result = lookup_dns("example.test", resolver=resolver)["A"]

        self.assertEqual(result.observation["answer_count"], DNS_MAX_ANSWERS_PER_TYPE)
        self.assertEqual(len(result.observation["addresses"]), DNS_MAX_ANSWERS_PER_TYPE)
        self.assertTrue(result.observation["truncated"])

    def test_shared_deadline_marks_unqueried_types_without_more_queries(self):
        resolver = Mock()
        resolver.resolve.side_effect = dns.resolver.NoAnswer
        with patch("intelligence.dns_lookup.time.monotonic", side_effect=[0, 0, 6]):
            results = lookup_dns("example.test", resolver=resolver)

        self.assertEqual(resolver.resolve.call_count, 1)
        self.assertEqual(results["A"].status, "unavailable")
        self.assertEqual(results["AAAA"].observation["availability"], "deadline_exceeded")
        self.assertEqual(results["TXT"].observation["availability"], "deadline_exceeded")

    def test_ip_literal_does_not_trigger_dns_queries(self):
        resolver = Mock()

        results = lookup_dns("https://8.8.8.8/", resolver=resolver)

        self.assertTrue(all(record.status == "not_run" for record in results.values()))
        resolver.resolve.assert_not_called()

    def test_non_public_ip_literal_is_rejected_before_dns_queries(self):
        blocked_urls = (
            "https://127.0.0.1/",
            "https://10.0.0.1/",
            "https://169.254.169.254/",
            "https://[::1]/",
            "https://[fc00::1]/",
            "https://0.0.0.0/",
            "https://224.0.0.1/",
        )
        resolver = Mock()
        for url in blocked_urls:
            with self.subTest(url=url):
                with self.assertRaises(DestinationSafetyError):
                    lookup_dns(url, resolver=resolver)
                resolver.resolve.assert_not_called()


if __name__ == "__main__":
    unittest.main()
