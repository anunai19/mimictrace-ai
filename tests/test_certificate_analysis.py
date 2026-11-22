import ipaddress
import socket
import ssl
import unittest
from unittest.mock import Mock, patch

from detection.destination_safety import validate_destination
from detection.evidence import EvidenceRecord
from intelligence.certificate_analysis import analyze_tls_certificate


class FakeRawSocket:

    def __init__(self, fail_connect=False):
        self.fail_connect = fail_connect
        self.timeouts = []
        self.connected_to = None
        self.closed = False

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def connect(self, address):
        self.connected_to = address
        if self.fail_connect:
            raise socket.timeout("synthetic timeout")

    def close(self):
        self.closed = True


class FakeTLSSocket:

    def __init__(self, certificate, raw_socket):
        self.certificate = certificate
        self.raw_socket = raw_socket
        self.closed = False

    def getpeercert(self):
        return self.certificate

    def close(self):
        self.closed = True
        self.raw_socket.close()


class FakeTLSContext:

    def __init__(self, certificate=None, error=None):
        self.certificate = certificate or {}
        self.error = error
        self.server_hostname = None
        self.check_hostname = True
        self.verify_mode = ssl.CERT_REQUIRED

    def wrap_socket(self, raw_socket, *, server_hostname):
        self.server_hostname = server_hostname
        if self.error is not None:
            raise self.error
        return FakeTLSSocket(self.certificate, raw_socket)


class TestCertificateAnalysis(unittest.TestCase):

    def setUp(self):
        self.destination = validate_destination(
            "https://example.test/",
            resolver=lambda *_args: ["8.8.8.8"],
        )
        self.raw_socket = FakeRawSocket()
        self.context = FakeTLSContext({
            "subjectAltName": (("DNS", "example.test"),),
            "notBefore": "Nov 16 00:00:00 2026 GMT",
            "notAfter": "Nov 16 00:00:00 2027 GMT",
        })

    def test_connects_to_pinned_ip_and_preserves_sni_and_verification(self):
        created_sockets = []
        def socket_factory(family, kind):
            self.assertEqual(family, socket.AF_INET)
            self.assertEqual(kind, socket.SOCK_STREAM)
            created_sockets.append(self.raw_socket)
            return self.raw_socket

        with patch("intelligence.certificate_analysis.validate_destination",
                   return_value=self.destination), \
             patch("intelligence.certificate_analysis.socket.socket",
                   side_effect=socket_factory), \
             patch("intelligence.certificate_analysis.ssl.create_default_context",
                   return_value=self.context):
            record = analyze_tls_certificate("https://example.test/")

        self.assertIsInstance(record, EvidenceRecord)
        self.assertEqual(record.status, "observed")
        self.assertEqual(record.observation["availability"], "verified")
        self.assertEqual(self.raw_socket.connected_to, ("8.8.8.8", 443))
        self.assertEqual(self.context.server_hostname, "example.test")
        self.assertEqual(record.observation["subject_alt_names"]["dns"], ["example.test"])
        self.assertTrue(all(0 < timeout <= 3.0 for timeout in self.raw_socket.timeouts))
        self.assertEqual(len(self.raw_socket.timeouts), 2)
        self.assertTrue(self.raw_socket.closed)

    def test_idn_hostname_is_normalized_for_certificate_sni(self):
        url = "https://bücher.example/"
        hostname = "xn--bcher-kva.example"
        destination = validate_destination(
            url,
            resolver=lambda *_args: ["8.8.8.8"],
        )
        self.context = FakeTLSContext({
            "subjectAltName": (("DNS", hostname),),
            "notBefore": "Nov 16 00:00:00 2026 GMT",
            "notAfter": "Nov 16 00:00:00 2027 GMT",
        })

        with patch(
            "intelligence.certificate_analysis.validate_destination",
            return_value=destination,
        ), patch(
            "intelligence.certificate_analysis.socket.socket",
            return_value=self.raw_socket,
        ), patch(
            "intelligence.certificate_analysis.ssl.create_default_context",
            return_value=self.context,
        ):
            record = analyze_tls_certificate(url)

        self.assertEqual(record.status, "observed")
        self.assertEqual(record.observation["hostname"], hostname)
        self.assertEqual(self.context.server_hostname, hostname)
        self.assertEqual(self.raw_socket.connected_to, ("8.8.8.8", 443))

    def test_ipv6_destination_uses_pinned_ipv6_socket_address(self):
        destination = validate_destination(
            "https://[2001:4860:4860::8888]/",
        )
        socket_factory = Mock(return_value=self.raw_socket)
        with patch("intelligence.certificate_analysis.validate_destination",
                   return_value=destination), \
             patch("intelligence.certificate_analysis.socket.socket",
                   socket_factory), \
             patch("intelligence.certificate_analysis.ssl.create_default_context",
                   return_value=self.context):
            analyze_tls_certificate("https://[2001:4860:4860::8888]/")

        self.assertEqual(socket_factory.call_args.args[0], socket.AF_INET6)
        self.assertEqual(
            self.raw_socket.connected_to,
            ("2001:4860:4860::8888", 443, 0, 0),
        )

    def test_rejects_non_https_or_non_443_without_connecting(self):
        with patch("intelligence.certificate_analysis.socket.socket") as socket_factory:
            for url in ("http://example.test/", "https://example.test:80/"):
                with self.subTest(url=url):
                    record = analyze_tls_certificate(url)
                    self.assertEqual(record.status, "not_run")
        socket_factory.assert_not_called()

    def test_destination_validation_failure_stops_before_connect(self):
        with patch(
            "intelligence.certificate_analysis.validate_destination",
            side_effect=ValueError("private address"),
        ), patch("intelligence.certificate_analysis.socket.socket") as socket_factory:
            record = analyze_tls_certificate("https://example.test/")

        self.assertEqual(record.observation["availability"], "destination_rejected")
        socket_factory.assert_not_called()

    def test_total_tls_deadline_includes_destination_validation(self):
        destination_validator = Mock(return_value=self.destination)
        with patch(
            "intelligence.certificate_analysis.time.monotonic",
            side_effect=[0.0, 0.0, 5.1],
        ), patch(
            "intelligence.certificate_analysis.validate_destination",
            destination_validator,
        ), patch("intelligence.certificate_analysis.socket.socket") as socket_factory:
            record = analyze_tls_certificate("https://example.test/")

        self.assertEqual(record.observation["availability"], "timeout")
        self.assertEqual(destination_validator.call_args.kwargs["timeout"], 2.0)
        socket_factory.assert_not_called()

    def test_certificate_verification_failure_is_not_bypassed(self):
        self.context = FakeTLSContext(
            error=ssl.SSLCertVerificationError("sensitive certificate details")
        )
        with patch("intelligence.certificate_analysis.validate_destination",
                   return_value=self.destination), \
             patch("intelligence.certificate_analysis.socket.socket",
                   return_value=self.raw_socket), \
             patch("intelligence.certificate_analysis.ssl.create_default_context",
                   return_value=self.context):
            record = analyze_tls_certificate("https://example.test/")

        self.assertEqual(record.status, "error")
        self.assertEqual(record.observation["availability"], "verification_failed")
        self.assertNotIn("sensitive certificate details", str(record.to_dict()))
        self.assertTrue(any("bypass" in reason for reason in record.uncertainty))

    def test_unverified_tls_context_is_rejected(self):
        self.context.check_hostname = False
        self.context.verify_mode = ssl.CERT_NONE
        with patch("intelligence.certificate_analysis.validate_destination",
                   return_value=self.destination), \
             patch("intelligence.certificate_analysis.socket.socket",
                   return_value=self.raw_socket), \
             patch("intelligence.certificate_analysis.ssl.create_default_context",
                   return_value=self.context):
            record = analyze_tls_certificate("https://example.test/")

        self.assertEqual(record.status, "error")
        self.assertEqual(record.observation["availability"], "tls_handshake_failed")
        self.assertTrue(self.raw_socket.closed)

    def test_connection_timeout_is_reported_safely(self):
        self.raw_socket = FakeRawSocket(fail_connect=True)
        with patch("intelligence.certificate_analysis.validate_destination",
                   return_value=self.destination), \
             patch("intelligence.certificate_analysis.socket.socket",
                   return_value=self.raw_socket), \
             patch("intelligence.certificate_analysis.ssl.create_default_context",
                   return_value=self.context):
            record = analyze_tls_certificate("https://example.test/")

        self.assertEqual(record.status, "error")
        self.assertEqual(record.observation["availability"], "timeout")
        self.assertTrue(self.raw_socket.closed)

    def test_tls_handshake_timeout_is_reported(self):
        self.context = FakeTLSContext(error=socket.timeout("synthetic handshake timeout"))
        with patch("intelligence.certificate_analysis.validate_destination",
                   return_value=self.destination), \
             patch("intelligence.certificate_analysis.socket.socket",
                   return_value=self.raw_socket), \
             patch("intelligence.certificate_analysis.ssl.create_default_context",
                   return_value=self.context):
            record = analyze_tls_certificate("https://example.test/")

        self.assertEqual(record.observation["availability"], "timeout")

    def test_hostname_mismatch_is_a_verification_failure(self):
        self.context = FakeTLSContext(
            error=ssl.SSLCertVerificationError("hostname mismatch")
        )
        with patch("intelligence.certificate_analysis.validate_destination",
                   return_value=self.destination), \
             patch("intelligence.certificate_analysis.socket.socket",
                   return_value=self.raw_socket), \
             patch("intelligence.certificate_analysis.ssl.create_default_context",
                   return_value=self.context):
            record = analyze_tls_certificate("https://example.test/")

        self.assertEqual(record.observation["verification"], "failed")
        self.assertNotIn("hostname mismatch", str(record.to_dict()))

    def test_certificate_metadata_is_bounded_and_json_safe(self):
        many_names = tuple(("DNS", f"host-{index}.example.test") for index in range(25))
        self.context = FakeTLSContext({"subjectAltName": many_names})

        with patch("intelligence.certificate_analysis.validate_destination",
                   return_value=self.destination), \
             patch("intelligence.certificate_analysis.socket.socket",
                   return_value=self.raw_socket), \
             patch("intelligence.certificate_analysis.ssl.create_default_context",
                   return_value=self.context):
            record = analyze_tls_certificate("https://example.test/")

        self.assertLessEqual(len(record.observation["subject_alt_names"]["dns"]), 20)
        record.to_json()


if __name__ == "__main__":
    unittest.main()
