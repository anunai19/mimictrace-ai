import io
import ipaddress
import multiprocessing
import os
import socket
import ssl
import time
import unittest
from unittest.mock import Mock, patch

from detection.destination_safety import DestinationSafetyError, validate_destination
from detection.html_fetcher import (
    HTMLFetchResult,
    MAX_HTML_BODY_BYTES,
    MAX_IPC_FRAME_BYTES,
    MAX_RESPONSE_HEADER_BYTES,
    _BoundedHTTPResponse,
    _FetchFailure,
    _HeaderLimitExceeded,
    _fetch_document,
    _read_bounded_body,
    _read_response_headers,
    _run_fetch_worker,
    _request_one_hop,
    _WindowsWorkerJob,
    fetch_html,
)


class FakeHeaders:
    def __init__(self, values):
        self._values = values

    def get_all(self, name):
        return self._values.get(name.lower(), [])


class FakeResponse:
    def __init__(self, chunks, headers=None):
        self.chunks = list(chunks)
        self.headers = FakeHeaders(headers or {})

    def read(self, size):
        if not self.chunks:
            return b""
        chunk = self.chunks.pop(0)
        if len(chunk) <= size:
            return chunk
        self.chunks.insert(0, chunk[size:])
        return chunk[:size]


class FakeSocket:
    def __init__(self, response=b""):
        self.response = response
        self.connected_to = None
        self.timeouts = []
        self.sent = []
        self.closed = False

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def connect(self, address):
        self.connected_to = address

    def sendall(self, value):
        self.sent.append(value)

    def recv(self, size):
        chunk = self.response[:size]
        self.response = self.response[size:]
        return chunk

    def makefile(self, _mode):
        return io.BytesIO(b"")

    def close(self):
        self.closed = True
        raw_socket = getattr(self, "raw_socket", None)
        if raw_socket is not None:
            raw_socket.close()


class FakeReceiveConnection:
    def __init__(self, frames, state=None, poll_error=None):
        self.frames = list(frames)
        self.state = state if state is not None else {}
        self.poll_error = poll_error
        self.closed = False

    def poll(self, _timeout):
        if self.poll_error:
            raise self.poll_error
        return bool(self.frames)

    def recv_bytes(self, maxlength):
        frame = self.frames.pop(0)
        if len(frame) > maxlength:
            raise OSError("message exceeds maximum")
        if frame[:1] == b"Z":
            self.state["done"] = True
        return frame

    def close(self):
        self.closed = True


class FakeSendConnection:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class FakeEvent:
    def __init__(self, state, sequence):
        self.state = state
        self.sequence = sequence

    def set(self):
        self.sequence.append("gate")
        self.state["gate"] = True


class FakeProcess:
    def __init__(self, state, sequence):
        self.state = state
        self.sequence = sequence
        self.pid = None
        self.daemon = None
        self.terminated = False
        self.killed = False
        self.joined = False

    def start(self):
        self.pid = 1234
        self.sequence.append("start")

    def is_alive(self):
        return not self.state.get("done", False) and not self.terminated and not self.killed

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True

    def join(self, timeout=None):
        self.joined = True
        if timeout == 0:
            self.state["done"] = True


class FakeProcessContext:
    def __init__(self, frames, poll_error=None):
        self.state = {}
        self.sequence = []
        self.receive = FakeReceiveConnection(
            frames,
            self.state,
            poll_error=poll_error,
        )
        self.send = FakeSendConnection()
        self.event = FakeEvent(self.state, self.sequence)
        self.process = FakeProcess(self.state, self.sequence)

    def Pipe(self, duplex=False):
        if duplex:
            raise AssertionError("Only one-way IPC is permitted.")
        return self.receive, self.send

    def Event(self):
        return self.event

    def Process(self, *, target, args):
        self.sequence.append(("worker", target, args))
        return self.process


class FakeJob:
    def __init__(self):
        self.assigned_pid = None
        self.closed = False

    def assign(self, process_id):
        self.assigned_pid = process_id

    def close(self):
        self.closed = True


def _wait_for_gate(gate):
    gate.wait(30)
    time.sleep(30)


class FakeTLSContext:
    check_hostname = True
    verify_mode = ssl.CERT_REQUIRED

    def __init__(self, tls_socket):
        self.tls_socket = tls_socket
        self.server_hostname = None

    def wrap_socket(self, raw_socket, *, server_hostname):
        self.server_hostname = server_hostname
        self.tls_socket.raw_socket = raw_socket
        return self.tls_socket


class TestHTMLFetcher(unittest.TestCase):

    def setUp(self):
        self.destination = validate_destination(
            "https://example.com/page?q=1",
            resolver=lambda *_args: ["8.8.8.8"],
        )

    def request_with_response(self, response_bytes, context_error=None):
        raw_socket = FakeSocket()
        tls_socket = FakeSocket(response_bytes)
        context = FakeTLSContext(tls_socket)
        if context_error is not None:
            context.wrap_socket = Mock(side_effect=context_error)
        with patch(
            "detection.html_fetcher.validate_destination",
            return_value=self.destination,
        ), patch(
            "detection.html_fetcher.socket.socket",
            return_value=raw_socket,
        ), patch(
            "detection.html_fetcher.ssl.create_default_context",
            return_value=context,
        ):
            result = _request_one_hop("https://example.com/page", 10**12)
        return result, raw_socket, tls_socket, context

    def test_http_input_is_unavailable_without_starting_worker(self):
        with patch("detection.html_fetcher._run_fetch_worker") as worker:
            result = fetch_html("http://example.com/")

        self.assertEqual(result, HTMLFetchResult("unavailable", "https_required"))
        worker.assert_not_called()

    def test_credentials_are_rejected_without_starting_worker(self):
        with patch("detection.html_fetcher._run_fetch_worker") as worker:
            result = fetch_html("https://user:password@example.com/")

        self.assertEqual(result.status, "error")
        self.assertEqual(result.availability, "invalid_input")
        worker.assert_not_called()

    def test_unusual_port_is_rejected_without_starting_worker(self):
        with patch("detection.html_fetcher._run_fetch_worker") as worker:
            result = fetch_html("https://example.com:444/")

        self.assertEqual(result.status, "error")
        self.assertEqual(result.availability, "invalid_input")
        worker.assert_not_called()

    def test_response_headers_are_capped_before_parsing(self):
        sock = FakeSocket(b"X" * (MAX_RESPONSE_HEADER_BYTES + 2))
        with self.assertRaises(_FetchFailure) as raised:
            _read_response_headers(sock, 10**12)

        self.assertEqual(raised.exception.code, "response_headers_too_large")
        self.assertLessEqual(len(sock.response), 1)

    def test_header_block_within_limit_is_accepted(self):
        header = b"HTTP/1.1 200 OK\r\nX-Test: value\r\n\r\n"
        sock = FakeSocket(header + b"body")

        prefix, header_bytes = _read_response_headers(sock, 10**12)

        self.assertEqual(header_bytes, len(header))
        self.assertEqual(prefix, header + b"body")
        self.assertLessEqual(header_bytes, MAX_RESPONSE_HEADER_BYTES)

    def test_header_limit_includes_chunked_trailers(self):
        response = _BoundedHTTPResponse.__new__(_BoundedHTTPResponse)
        response._header_bytes = 16
        response.fp = io.BytesIO(
            (b"x:a\r\n" * (MAX_RESPONSE_HEADER_BYTES // 4)) + b"\r\n"
        )
        with self.assertRaises(_HeaderLimitExceeded):
            response._read_and_discard_trailer()

    def test_body_streaming_stops_at_the_byte_limit(self):
        response = FakeResponse(
            [b"x" * MAX_HTML_BODY_BYTES, b"y"],
        )
        with self.assertRaises(_FetchFailure) as raised:
            _read_bounded_body(response, FakeSocket(), 10**12)

        self.assertEqual(raised.exception.code, "response_too_large")

    def test_compressed_response_is_rejected_before_body_read(self):
        response = FakeResponse(
            [b"compressed"],
            {"content-encoding": ["gzip"]},
        )
        with self.assertRaises(_FetchFailure) as raised:
            _read_bounded_body(response, FakeSocket(), 10**12)

        self.assertEqual(raised.exception.code, "unsupported_content_encoding")

    def test_pinned_connection_uses_validated_ip_and_verified_sni(self):
        raw_socket = FakeSocket()
        tls_socket = FakeSocket(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/html; charset=utf-8\r\n"
            b"Content-Length: 11\r\n"
            b"\r\n"
            b"<p>safe</p>"
        )
        context = FakeTLSContext(tls_socket)
        with patch(
            "detection.html_fetcher.validate_destination",
            return_value=self.destination,
        ), patch(
            "detection.html_fetcher.socket.socket",
            return_value=raw_socket,
        ) as socket_factory, patch(
            "detection.html_fetcher.ssl.create_default_context",
            return_value=context,
        ), patch(
            "socket.getaddrinfo",
            side_effect=AssertionError("A second DNS lookup is forbidden."),
        ):
            status, location, content = _request_one_hop(
                "https://example.com/page?q=1",
                10**12,
            )

        self.assertEqual(status, 200)
        self.assertIsNone(location)
        self.assertEqual(content, b"<p>safe</p>")
        socket_factory.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
        self.assertEqual(raw_socket.connected_to, ("8.8.8.8", 443))
        self.assertEqual(context.server_hostname, "example.com")
        self.assertIn(b"Host: example.com\r\n", tls_socket.sent[0])
        self.assertTrue(raw_socket.closed)
        self.assertTrue(tls_socket.closed)

    def test_pinned_connection_normalizes_idn_for_sni_and_host(self):
        url = "https://bücher.example/page"
        hostname = "xn--bcher-kva.example"
        destination = validate_destination(
            url,
            resolver=lambda *_args: ["8.8.8.8"],
        )
        raw_socket = FakeSocket()
        tls_socket = FakeSocket(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/html\r\n"
            b"Content-Length: 4\r\n"
            b"\r\n"
            b"<p/>"
        )
        context = FakeTLSContext(tls_socket)

        with patch(
            "detection.html_fetcher.validate_destination",
            return_value=destination,
        ), patch(
            "detection.html_fetcher.socket.socket",
            return_value=raw_socket,
        ), patch(
            "detection.html_fetcher.ssl.create_default_context",
            return_value=context,
        ):
            status, location, content = _request_one_hop(url, 10**12)

        self.assertEqual(status, 200)
        self.assertIsNone(location)
        self.assertEqual(content, b"<p/>")
        self.assertEqual(context.server_hostname, hostname)
        self.assertIn(f"Host: {hostname}\r\n".encode("ascii"), tls_socket.sent[0])
        self.assertEqual(raw_socket.connected_to, ("8.8.8.8", 443))

    def test_only_successful_html_responses_are_accepted(self):
        responses = (
            (
                b"HTTP/1.1 404 Not Found\r\n"
                b"Content-Type: text/html\r\nContent-Length: 0\r\n\r\n",
                "http_status",
            ),
            (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
                "unsupported_content_type",
            ),
            (
                b"HTTP/1.1 204 No Content\r\n"
                b"Content-Type: text/html\r\nContent-Length: 0\r\n\r\n",
                "http_status",
            ),
        )
        for response, expected_code in responses:
            with self.subTest(expected_code=expected_code):
                with self.assertRaises(_FetchFailure) as raised:
                    self.request_with_response(response)
                self.assertEqual(raised.exception.code, expected_code)

    def test_certificate_verification_failure_never_falls_back(self):
        raw_socket = FakeSocket()
        tls_socket = FakeSocket()
        context = FakeTLSContext(tls_socket)
        context.wrap_socket = Mock(
            side_effect=ssl.SSLCertVerificationError("untrusted")
        )
        with patch(
            "detection.html_fetcher.validate_destination",
            return_value=self.destination,
        ), patch(
            "detection.html_fetcher.socket.socket",
            return_value=raw_socket,
        ), patch(
            "detection.html_fetcher.ssl.create_default_context",
            return_value=context,
        ):
            with self.assertRaises(_FetchFailure) as raised:
                _request_one_hop("https://example.com/", 10**12)

        self.assertEqual(raised.exception.code, "tls_verification_failed")
        self.assertTrue(raw_socket.closed)

    def test_redirect_hop_is_resolved_and_pinned_again(self):
        first_destination = validate_destination(
            "https://example.com/",
            resolver=lambda *_args: ["8.8.8.8"],
        )
        second_destination = validate_destination(
            "https://other.example.net/final",
            resolver=lambda *_args: ["1.1.1.1"],
        )
        first_raw = FakeSocket()
        second_raw = FakeSocket()
        first_tls = FakeSocket(
            b"HTTP/1.1 302 Found\r\n"
            b"Location: https://other.example.net/final\r\n"
            b"Content-Length: 0\r\n\r\n"
        )
        second_tls = FakeSocket(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/html\r\n"
            b"Content-Length: 11\r\n\r\n"
            b"<p>safe</p>"
        )
        contexts = [FakeTLSContext(first_tls), FakeTLSContext(second_tls)]
        validator = Mock(side_effect=[first_destination, second_destination])
        sockets = [first_raw, second_raw]
        with patch(
            "detection.html_fetcher.validate_destination",
            validator,
        ), patch(
            "detection.html_fetcher.socket.socket",
            side_effect=sockets,
        ), patch(
            "detection.html_fetcher.ssl.create_default_context",
            side_effect=contexts,
        ):
            final_url, redirects, content = _fetch_document(
                "https://example.com/",
                10**12,
            )

        self.assertEqual(redirects, 1)
        self.assertEqual(final_url, "https://other.example.net/final")
        self.assertEqual(content, b"<p>safe</p>")
        self.assertEqual(validator.call_count, 2)
        self.assertEqual(first_raw.connected_to, ("8.8.8.8", 443))
        self.assertEqual(second_raw.connected_to, ("1.1.1.1", 443))

    def test_redirect_to_disallowed_destination_stops_before_second_connection(self):
        first_destination = validate_destination(
            "https://example.com/",
            resolver=lambda *_args: ["8.8.8.8"],
        )
        raw_socket = FakeSocket()
        tls_socket = FakeSocket(
            b"HTTP/1.1 302 Found\r\n"
            b"Location: https://private.example.net/\r\n"
            b"Content-Length: 0\r\n\r\n"
        )
        context = FakeTLSContext(tls_socket)
        validator = Mock(side_effect=[
            first_destination,
            DestinationSafetyError("private destination"),
        ])
        with patch(
            "detection.html_fetcher.validate_destination",
            validator,
        ), patch(
            "detection.html_fetcher.socket.socket",
            return_value=raw_socket,
        ), patch(
            "detection.html_fetcher.ssl.create_default_context",
            return_value=context,
        ):
            with self.assertRaises(_FetchFailure) as raised:
                _fetch_document("https://example.com/", 10**12)

        self.assertEqual(raised.exception.code, "destination_rejected")
        self.assertEqual(validator.call_count, 2)
    def test_redirect_to_http_is_rejected_without_following(self):
        with patch(
            "detection.html_fetcher._request_one_hop",
            return_value=(302, "http://example.net/", b""),
        ) as request:
            with self.assertRaises(_FetchFailure) as raised:
                _fetch_document("https://example.com/", 10**12)

        self.assertEqual(raised.exception.code, "https_downgrade")
        request.assert_called_once()

    def test_redirects_are_bounded_and_loop_checked(self):
        with patch(
            "detection.html_fetcher._request_one_hop",
            side_effect=[
                (302, "/next", b""),
                (302, "/", b""),
            ],
        ):
            with self.assertRaises(_FetchFailure) as raised:
                _fetch_document("https://example.com/", 10**12)

        self.assertEqual(raised.exception.code, "redirect_loop")

    def test_ip_address_sockaddr_supports_ipv6(self):
        from detection.html_fetcher import _socket_address

        family, address = _socket_address(ipaddress.ip_address("2001:4860:4860::8888"), 443)
        self.assertEqual(family, socket.AF_INET6)
        self.assertEqual(address, ("2001:4860:4860::8888", 443, 0, 0))

    def test_content_length_over_cap_is_rejected_without_reading(self):
        response = FakeResponse([], {"content-length": [str(MAX_HTML_BODY_BYTES + 1)]})
        with self.assertRaises(_FetchFailure) as raised:
            _read_bounded_body(response, FakeSocket(), 10**12)
        self.assertEqual(raised.exception.code, "response_too_large")

    def test_parent_caps_ipc_and_reaps_worker_on_failure(self):
        context = FakeProcessContext([b"B" + b"x" * MAX_IPC_FRAME_BYTES])
        with patch(
            "detection.html_fetcher.multiprocessing.get_context",
            return_value=context,
        ), patch(
            "detection.html_fetcher._WindowsWorkerJob",
            return_value=FakeJob(),
        ):
            result = _run_fetch_worker("https://example.com/", time.monotonic() + 1)

        self.assertEqual(result.status, "error")
        self.assertEqual(result.availability, "worker_failed")
        self.assertTrue(context.process.terminated)
        self.assertTrue(context.process.joined)
        self.assertTrue(context.receive.closed)
        self.assertTrue(context.send.closed)

    def test_parent_timeout_terminates_and_reaps_worker(self):
        context = FakeProcessContext([])
        with patch(
            "detection.html_fetcher.multiprocessing.get_context",
            return_value=context,
        ), patch(
            "detection.html_fetcher._WindowsWorkerJob",
            return_value=FakeJob(),
        ):
            result = _run_fetch_worker("https://example.com/", time.monotonic() - 1)

        self.assertEqual(result.availability, "timeout")
        self.assertTrue(context.process.terminated)
        self.assertTrue(context.process.joined)

    def test_cancellation_reaps_worker_and_windows_job_is_assigned_before_release(self):
        state = {}
        context = FakeProcessContext(
            [],
            poll_error=KeyboardInterrupt(),
        )

        class OrderedFakeJob(FakeJob):
            def assign(self, process_id):
                super().assign(process_id)
                context.sequence.append("job")

            def close(self):
                super().close()
                context.sequence.append("job-close")

        with patch(
            "detection.html_fetcher.multiprocessing.get_context",
            return_value=context,
        ), patch(
            "detection.html_fetcher._WindowsWorkerJob",
            return_value=OrderedFakeJob(),
        ), patch(
            "detection.html_fetcher.os.name",
            "nt",
        ):
            with self.assertRaises(KeyboardInterrupt):
                _run_fetch_worker("https://example.com/", time.monotonic() + 1)

        self.assertLess(
            context.sequence.index("job"),
            context.sequence.index("gate"),
        )
        self.assertTrue(context.process.terminated)
        self.assertTrue(context.process.joined)
        self.assertIn("job-close", context.sequence)

    @unittest.skipUnless(os.name == "nt", "Windows Job Objects are platform-specific.")
    def test_windows_job_kills_and_reaps_assigned_worker_on_close(self):
        context = multiprocessing.get_context("spawn")
        gate = context.Event()
        process = context.Process(target=_wait_for_gate, args=(gate,))
        job = _WindowsWorkerJob()
        try:
            process.start()
            job.assign(process.pid)
            gate.set()
        except Exception:
            if process.pid is not None and process.is_alive():
                process.terminate()
                process.join(timeout=1)
            job.close()
            raise

        job.close()
        process.join(timeout=2)
        if process.is_alive():
            process.terminate()
            process.join(timeout=1)
        self.assertFalse(process.is_alive())
