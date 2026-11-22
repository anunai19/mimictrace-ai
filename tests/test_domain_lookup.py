import json
import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from detection.evidence import EvidenceRecord
from intelligence.domain_lookup import (
    MAX_WHOIS_OUTPUT_BYTES,
    WHOIS_MAX_RESPONSE_BYTES,
    WHOIS_TOTAL_DEADLINE_SECONDS,
    _WHOIS_WORKER_SCRIPT,
    _normalize_date_field,
    lookup_domain_registration,
)


class TestDomainLookup(unittest.TestCase):

    def run_with_payload(self, payload):
        result = SimpleNamespace(
            returncode=0,
            stdout=json.dumps(payload),
        )
        with patch("intelligence.domain_lookup.subprocess.run", return_value=result) as run:
            record = lookup_domain_registration("https://sub.example.com/login")
        run.assert_called_once()
        self.assertIn("example.com", run.call_args.args[0])
        self.assertEqual(
            run.call_args.kwargs["timeout"],
            WHOIS_TOTAL_DEADLINE_SECONDS,
        )
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertIn("WHOIS_QUICK", run.call_args.args[0][2])
        self.assertIs(
            run.call_args.kwargs["stderr"],
            subprocess.DEVNULL,
        )
        return record

    def test_normalizes_allowlisted_whois_fields_only(self):
        record = self.run_with_payload({
            "creation_date": "2020-01-02T03:04:05+00:00",
            "expiration_date": "2030-01-02",
            "registrar": "  Example   Registrar ",
            "email": "private@example.test",
            "raw": "private contact response",
        })

        self.assertIsInstance(record, EvidenceRecord)
        self.assertEqual(record.status, "observed")
        self.assertEqual(record.observation["domain"], "example.com")
        self.assertEqual(record.observation["creation_date_timezone"], "offset_known")
        self.assertEqual(record.observation["expiration_date_timezone"], "unknown")
        self.assertEqual(record.observation["registrar"], "Example Registrar")
        self.assertNotIn("email", str(record.to_dict()))
        self.assertNotIn("private contact", str(record.to_dict()))
        self.assertTrue(any("age alone" in item for item in record.uncertainty))

    def test_missing_fields_return_unavailable_not_a_verdict(self):
        record = self.run_with_payload({
            "creation_date": None,
            "expiration_date": None,
            "registrar": None,
        })

        self.assertEqual(record.status, "unavailable")
        self.assertEqual(record.observation["availability"], "registration_data_unavailable")
        self.assertEqual(
            set(record.observation["field_issues"]),
            {"creation_date_missing", "expiration_date_missing", "registrar_unavailable"},
        )

    def test_malformed_and_conflicting_dates_are_not_silently_selected(self):
        self.assertEqual(
            _normalize_date_field("not a date"),
            (None, None, "malformed"),
        )
        self.assertEqual(
            _normalize_date_field(["2020-01-01", "2021-01-01"]),
            (None, None, "conflicting"),
        )

        record = self.run_with_payload({
            "creation_date": ["2020-01-01", "2021-01-01"],
            "expiration_date": "broken",
            "registrar": "Example Registrar",
        })
        self.assertEqual(record.status, "observed")
        self.assertIsNone(record.observation["creation_date"])
        self.assertIsNone(record.observation["expiration_date"])
        self.assertIn("creation_date_conflicting", record.observation["field_issues"])
        self.assertIn("expiration_date_malformed", record.observation["field_issues"])

    def test_invalid_or_nonregistrable_input_does_not_start_worker(self):
        with patch("intelligence.domain_lookup.subprocess.run") as run:
            invalid = lookup_domain_registration("file:///C:/sensitive")
            unknown_suffix = lookup_domain_registration("host.invalidtld")

        run.assert_not_called()
        self.assertEqual(invalid.status, "error")
        self.assertEqual(unknown_suffix.status, "error")

    def test_whois_hard_deadline_returns_error_without_raw_details(self):
        timeout = subprocess.TimeoutExpired(["python", "-c"], WHOIS_TOTAL_DEADLINE_SECONDS)
        with patch(
            "intelligence.domain_lookup.subprocess.run",
            side_effect=timeout,
        ) as run:
            record = lookup_domain_registration("example.com")

        self.assertEqual(record.status, "error")
        self.assertEqual(record.observation["availability"], "timeout")
        self.assertEqual(run.call_args.kwargs["timeout"], 5.0)
        self.assertNotIn("TimeoutExpired", str(record.to_dict()))

    def test_worker_stops_accumulating_response_at_byte_limit(self):
        class FakeSocket:
            def __init__(self):
                self.bytes_returned = 0

            def recv(self, size, *_args):
                self.bytes_returned += size
                return b"x" * size

        fake_socket = FakeSocket()

        class FakeNICClient:
            WHOIS_QUICK = 2

            @staticmethod
            def get_socket():
                return fake_socket

        def fake_whois(*_args, **_kwargs):
            import whois

            connection = whois.NICClient.get_socket()
            response = bytearray()
            while True:
                data = connection.recv(4096)
                if not data:
                    break
                response.extend(data)
            return {
                "creation_date": "2020-01-01",
                "expiration_date": None,
                "registrar": None,
                "raw": response.decode("ascii"),
            }

        fake_whois_module = SimpleNamespace(
            NICClient=FakeNICClient,
            whois=fake_whois,
        )
        import io
        import sys

        output = io.StringIO()
        with patch.dict(sys.modules, {"whois": fake_whois_module}), \
             patch("sys.argv", ["worker", "example.com"]), \
             patch("sys.stdout", output):
            with self.assertRaisesRegex(OSError, "byte limit"):
                exec(_WHOIS_WORKER_SCRIPT, {})

        self.assertEqual(fake_socket.bytes_returned, WHOIS_MAX_RESPONSE_BYTES + 1)
        self.assertLessEqual(
            MAX_WHOIS_OUTPUT_BYTES,
            WHOIS_MAX_RESPONSE_BYTES,
        )
        self.assertEqual(output.getvalue(), "")

    def test_worker_failure_is_sanitized(self):
        with patch(
            "intelligence.domain_lookup.subprocess.run",
            side_effect=OSError("sensitive local path"),
        ):
            record = lookup_domain_registration("example.com")

        self.assertEqual(record.observation["availability"], "lookup_error")
        self.assertNotIn("sensitive local path", str(record.to_dict()))

    def test_tld_extractor_has_no_suffix_list_network_sources(self):
        from intelligence.domain_lookup import _TLD_EXTRACTOR

        self.assertEqual(_TLD_EXTRACTOR.suffix_list_urls, ())


if __name__ == "__main__":
    unittest.main()
