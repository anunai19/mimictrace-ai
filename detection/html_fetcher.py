import ctypes
import ctypes.wintypes
import ipaddress
import json
import multiprocessing
import os
import socket
import ssl
import time
from dataclasses import dataclass
from http.client import HTTPException, HTTPResponse, IncompleteRead
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

from detection.destination_safety import (
    DEFAULT_DNS_TIMEOUT_SECONDS,
    DestinationSafetyError,
    ValidatedDestination,
    parse_http_url,
    validate_destination,
    validated_addresses_for_connection,
)


HTML_RETRIEVAL_DEADLINE_SECONDS = 8.0
HTML_CONNECT_TIMEOUT_SECONDS = 2.0
HTML_READ_TIMEOUT_SECONDS = 3.0
MAX_HTML_BODY_BYTES = 1024 * 1024
MAX_RESPONSE_HEADER_BYTES = 32 * 1024
MAX_CHUNK_LINE_BYTES = 8 * 1024
MAX_REDIRECTS = 3
READ_CHUNK_BYTES = 16 * 1024
IPC_CHUNK_BYTES = 16 * 1024
MAX_IPC_FRAME_BYTES = IPC_CHUNK_BYTES + 1
MAX_IPC_FRAMES = (MAX_HTML_BODY_BYTES + IPC_CHUNK_BYTES - 1) // IPC_CHUNK_BYTES + 2
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
_SUCCESS_STATUSES = frozenset(range(200, 300)) - {204, 206}
_WORKER_ERRORS = frozenset({
    "destination_rejected",
    "timeout",
    "connection_failed",
    "tls_verification_failed",
    "tls_failed",
    "invalid_response",
    "response_headers_too_large",
    "http_status",
    "unsupported_content_type",
    "unsupported_content_encoding",
    "response_too_large",
    "redirect_invalid",
    "redirect_loop",
    "redirect_limit",
    "https_downgrade",
    "worker_failed",
})


class _BasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", ctypes.c_uint32),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", ctypes.c_uint32),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", ctypes.c_uint32),
        ("SchedulingClass", ctypes.c_uint32),
    ]


class _IoCounters(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_uint64),
        ("WriteOperationCount", ctypes.c_uint64),
        ("OtherOperationCount", ctypes.c_uint64),
        ("ReadTransferCount", ctypes.c_uint64),
        ("WriteTransferCount", ctypes.c_uint64),
        ("OtherTransferCount", ctypes.c_uint64),
    ]


class _ExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _BasicLimitInformation),
        ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


@dataclass(frozen=True)
class HTMLFetchResult:
    status: str
    availability: str
    content: bytes = b""
    final_url: str = ""
    redirect_count: int = 0


class _FetchFailure(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class _HeaderLimitExceeded(HTTPException):
    pass


class _PrefixFile:
    def __init__(self, prefix, stream):
        self._prefix = memoryview(prefix)
        self._offset = 0
        self._stream = stream

    def read(self, size=-1):
        remaining = len(self._prefix) - self._offset
        if size is None or size < 0:
            prefix = self._prefix[self._offset:].tobytes()
            self._offset = len(self._prefix)
            return prefix + self._stream.read()
        if remaining >= size:
            start = self._offset
            self._offset += size
            return self._prefix[start:self._offset].tobytes()
        prefix = self._prefix[self._offset:].tobytes()
        self._offset = len(self._prefix)
        return prefix + self._stream.read(size - len(prefix))

    def readline(self, size=-1):
        remaining = len(self._prefix) - self._offset
        if remaining:
            available = self._prefix[self._offset:].tobytes()
            newline = available.find(b"\n")
            end = newline + 1 if newline >= 0 else len(available)
            if size is not None and size >= 0:
                end = min(end, size)
            prefix = available[:end]
            self._offset += len(prefix)
            if b"\n" in prefix or (size is not None and size >= 0 and len(prefix) == size):
                return prefix
            remainder_size = -1 if size is None or size < 0 else size - len(prefix)
            return prefix + self._stream.readline(remainder_size)
        return self._stream.readline(size)

    def close(self):
        self._stream.close()

    def flush(self):
        self._stream.flush()


class _PrefixedSocket:
    def __init__(self, sock, prefix):
        self._sock = sock
        self._prefix = prefix

    def makefile(self, mode):
        return _PrefixFile(self._prefix, self._sock.makefile(mode))


class _BoundedHTTPResponse(HTTPResponse):
    def __init__(self, sock, *, header_bytes, method):
        self._header_bytes = header_bytes
        super().__init__(sock, method=method)

    def _read_next_chunk_size(self):
        line = self.fp.readline(MAX_CHUNK_LINE_BYTES + 1)
        if len(line) > MAX_CHUNK_LINE_BYTES:
            raise HTTPException("Chunk-size line exceeds its limit.")
        if not line.endswith(b"\r\n"):
            raise HTTPException("Malformed chunk-size line.")
        size_text = line.split(b";", 1)[0].strip()
        try:
            chunk_size = int(size_text, 16)
        except ValueError:
            raise HTTPException("Malformed chunk size.") from None
        if chunk_size < 0:
            raise HTTPException("Negative chunk size.")
        return chunk_size

    def _read_and_discard_trailer(self):
        while True:
            remaining = MAX_RESPONSE_HEADER_BYTES - self._header_bytes
            if remaining <= 0:
                raise _HeaderLimitExceeded("Response headers exceed their limit.")
            line = self.fp.readline(min(MAX_CHUNK_LINE_BYTES, remaining + 1))
            self._header_bytes += len(line)
            if self._header_bytes > MAX_RESPONSE_HEADER_BYTES:
                raise _HeaderLimitExceeded("Response headers exceed their limit.")
            if not line:
                break
            if line in (b"\r\n", b"\n"):
                break
            if not line.endswith(b"\r\n"):
                raise HTTPException("Malformed response trailer.")


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _FetchFailure("timeout")
    return remaining


def _socket_address(address, port):
    if isinstance(address, ipaddress.IPv4Address):
        return socket.AF_INET, (address.compressed, port)
    if isinstance(address, ipaddress.IPv6Address):
        return socket.AF_INET6, (address.compressed, port, 0, 0)
    raise _FetchFailure("destination_rejected")


def _read_response_headers(sock, deadline):
    header_buffer = bytearray()
    delimiter = b"\r\n\r\n"
    while True:
        delimiter_index = header_buffer.find(delimiter)
        if delimiter_index >= 0:
            header_end = delimiter_index + len(delimiter)
            if header_end > MAX_RESPONSE_HEADER_BYTES:
                raise _FetchFailure("response_headers_too_large")
            return bytes(header_buffer), header_end
        if len(header_buffer) > MAX_RESPONSE_HEADER_BYTES:
            raise _FetchFailure("response_headers_too_large")

        remaining_capacity = MAX_RESPONSE_HEADER_BYTES + 1 - len(header_buffer)
        remaining = _remaining(deadline)
        sock.settimeout(min(HTML_READ_TIMEOUT_SECONDS, remaining))
        try:
            chunk = sock.recv(min(READ_CHUNK_BYTES, remaining_capacity))
        except (socket.timeout, TimeoutError):
            raise _FetchFailure("timeout") from None
        if not chunk:
            raise _FetchFailure("invalid_response")
        header_buffer.extend(chunk)
        if len(header_buffer) > MAX_RESPONSE_HEADER_BYTES:
            delimiter_index = header_buffer.find(delimiter)
            if delimiter_index < 0 or delimiter_index + len(delimiter) > MAX_RESPONSE_HEADER_BYTES:
                raise _FetchFailure("response_headers_too_large")


def _normalized_https_url(url):
    try:
        scheme, hostname, port, path, query, _ = parse_http_url(url)
    except (DestinationSafetyError, TypeError, ValueError, UnicodeError):
        raise _FetchFailure("redirect_invalid") from None
    if scheme != "https":
        raise _FetchFailure("https_downgrade")
    if port != 443:
        raise _FetchFailure("redirect_invalid")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        authority = hostname
    else:
        authority = f"[{address.compressed}]" if address.version == 6 else address.compressed
    request_path = quote(path or "/", safe="/%:@!$&'()*+,;=-._~")
    request_query = quote(query, safe="/?%:@!$&'()*+,;=-._~")
    return urlunsplit(("https", authority, request_path, request_query, ""))


def _http_response(sock, deadline):
    header_prefix, header_bytes = _read_response_headers(sock, deadline)
    response = _BoundedHTTPResponse(
        _PrefixedSocket(sock, header_prefix),
        header_bytes=header_bytes,
        method="GET",
    )
    try:
        response.begin()
    except (HTTPException, OSError, ValueError):
        try:
            response.close()
        except OSError:
            pass
        raise _FetchFailure("invalid_response") from None
    return response


def _read_bounded_body(response, sock, deadline):
    transfer_encoding = response.headers.get_all("Transfer-Encoding") or []
    content_lengths = response.headers.get_all("Content-Length") or []
    if len(transfer_encoding) > 1 or len(content_lengths) > 1:
        raise _FetchFailure("invalid_response")
    if transfer_encoding and content_lengths:
        raise _FetchFailure("invalid_response")
    if transfer_encoding and transfer_encoding[0].strip().lower() != "chunked":
        raise _FetchFailure("invalid_response")

    content_length = None
    if content_lengths:
        try:
            content_length = int(content_lengths[0].strip())
        except (TypeError, ValueError):
            raise _FetchFailure("invalid_response") from None
        if content_length < 0:
            raise _FetchFailure("invalid_response")
        if content_length > MAX_HTML_BODY_BYTES:
            raise _FetchFailure("response_too_large")

    content_encodings = response.headers.get_all("Content-Encoding") or []
    if len(content_encodings) > 1 or (
        content_encodings
        and content_encodings[0].strip().lower() not in {"", "identity"}
    ):
        raise _FetchFailure("unsupported_content_encoding")

    body = bytearray()
    while True:
        remaining = _remaining(deadline)
        sock.settimeout(min(HTML_READ_TIMEOUT_SECONDS, remaining))
        read_size = min(READ_CHUNK_BYTES, MAX_HTML_BODY_BYTES - len(body) + 1)
        try:
            chunk = response.read(read_size)
        except (socket.timeout, TimeoutError):
            raise _FetchFailure("timeout") from None
        except _HeaderLimitExceeded:
            raise _FetchFailure("response_headers_too_large") from None
        except (HTTPException, IncompleteRead, OSError, ValueError):
            raise _FetchFailure("invalid_response") from None
        if not chunk:
            break
        if len(body) + len(chunk) > MAX_HTML_BODY_BYTES:
            raise _FetchFailure("response_too_large")
        body.extend(chunk)
    if not body:
        raise _FetchFailure("invalid_response")
    if content_length is not None and len(body) != content_length:
        raise _FetchFailure("invalid_response")
    return bytes(body)


def _request_one_hop(url, deadline):
    remaining = _remaining(deadline)
    try:
        destination = validate_destination(
            url,
            timeout=min(DEFAULT_DNS_TIMEOUT_SECONDS, remaining),
        )
        addresses = validated_addresses_for_connection(destination)
    except (DestinationSafetyError, OSError, TypeError, ValueError):
        raise _FetchFailure("destination_rejected") from None
    if destination.scheme != "https" or destination.port != 443:
        raise _FetchFailure("https_downgrade")
    raw_socket = None
    tls_socket = None
    response = None
    connection_error = None
    try:
        for address in addresses:
            # SECURITY: The addresses above were resolved and validated by
            # validate_destination() before this point. Every address has
            # already passed is_allowed_public_address(), which rejects
            # loopback, RFC1918 private, link-local (including cloud
            # metadata), reserved, multicast, and unspecified addresses.
            # We connect directly to these resolved IP address tuples,
            # never to the hostname again. This means the OS cannot
            # re-resolve the name between validation and connection,
            # preventing DNS rebinding attacks where a public name
            # initially resolves to a safe address but later resolves
            # to an internal one.
            remaining = _remaining(deadline)
            family, sockaddr = _socket_address(address, destination.port)
            candidate = socket.socket(family, socket.SOCK_STREAM)
            try:
                candidate.settimeout(min(HTML_CONNECT_TIMEOUT_SECONDS, remaining))
                candidate.connect(sockaddr)
            except (socket.timeout, TimeoutError):
                candidate.close()
                connection_error = socket.timeout("Pinned connect timed out.")
                continue
            except OSError as error:
                candidate.close()
                connection_error = error
                continue
            raw_socket = candidate
            break
        if raw_socket is None:
            if isinstance(connection_error, (socket.timeout, TimeoutError)):
                raise _FetchFailure("timeout") from None
            raise _FetchFailure("connection_failed") from connection_error

        remaining = _remaining(deadline)
        raw_socket.settimeout(min(HTML_READ_TIMEOUT_SECONDS, remaining))
        context = ssl.create_default_context()
        if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
            raise _FetchFailure("tls_verification_failed")
        try:
            tls_socket = context.wrap_socket(
                raw_socket,
                server_hostname=destination.hostname,
            )
        except ssl.SSLCertVerificationError:
            raise _FetchFailure("tls_verification_failed") from None
        except (socket.timeout, TimeoutError):
            raise _FetchFailure("timeout") from None
        except (ssl.SSLError, OSError):
            raise _FetchFailure("tls_failed") from None
        raw_socket = None
        tls_socket.settimeout(min(HTML_READ_TIMEOUT_SECONDS, _remaining(deadline)))

        request_path = quote(destination.path or "/", safe="/%:@!$&'()*+,;=-._~")
        request_query = quote(destination.query, safe="/?%:@!$&'()*+,;=-._~")
        target = request_path + (f"?{request_query}" if request_query else "")
        try:
            destination_ip = ipaddress.ip_address(destination.hostname)
        except ValueError:
            host_header = destination.hostname
        else:
            host_header = (
                f"[{destination_ip.compressed}]"
                if destination_ip.version == 6
                else destination_ip.compressed
            )
        request = (
            f"GET {target} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            "User-Agent: MimicTrace-Static-Analyzer/1.0\r\n"
            "Accept: text/html, application/xhtml+xml\r\n"
            "Accept-Encoding: identity\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("ascii")
        tls_socket.settimeout(min(HTML_READ_TIMEOUT_SECONDS, _remaining(deadline)))
        try:
            tls_socket.sendall(request)
        except (socket.timeout, TimeoutError):
            raise _FetchFailure("timeout") from None
        except OSError:
            raise _FetchFailure("connection_failed") from None

        response = _http_response(tls_socket, deadline)
        status = response.status
        location_values = response.headers.get_all("Location") or []
        if status in _REDIRECT_STATUSES:
            if len(location_values) != 1 or not location_values[0].strip():
                raise _FetchFailure("redirect_invalid")
            return status, location_values[0].strip(), b""
        if status not in _SUCCESS_STATUSES:
            raise _FetchFailure("http_status")

        content_types = response.headers.get_all("Content-Type") or []
        if len(content_types) != 1:
            raise _FetchFailure("unsupported_content_type")
        media_type = content_types[0].split(";", 1)[0].strip().lower()
        if media_type not in {"text/html", "application/xhtml+xml"}:
            raise _FetchFailure("unsupported_content_type")
        body = _read_bounded_body(response, tls_socket, deadline)
        return status, None, body
    finally:
        try:
            if response is not None:
                response.close()
        finally:
            try:
                if tls_socket is not None:
                    tls_socket.close()
            finally:
                if raw_socket is not None:
                    raw_socket.close()


def _fetch_document(url, deadline):
    current_url = _normalized_https_url(url)
    seen_urls = {current_url}
    redirects = 0
    while True:
        _remaining(deadline)
        status, location, content = _request_one_hop(current_url, deadline)
        if status not in _REDIRECT_STATUSES:
            return current_url, redirects, content
        if redirects >= MAX_REDIRECTS:
            raise _FetchFailure("redirect_limit")
        next_url = urljoin(current_url, location)
        try:
            next_url = _normalized_https_url(next_url)
        except _FetchFailure as error:
            if error.code == "https_downgrade":
                raise
            raise _FetchFailure("redirect_invalid") from None
        if next_url in seen_urls:
            raise _FetchFailure("redirect_loop")
        seen_urls.add(next_url)
        current_url = next_url
        redirects += 1


def _send_frame(connection, kind, payload=b""):
    frame = kind + payload
    if len(frame) > MAX_IPC_FRAME_BYTES:
        raise _FetchFailure("worker_failed")
    connection.send_bytes(frame)


def _fetch_worker(url, deadline, start_gate, send_connection):
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not start_gate.wait(remaining):
            _send_frame(send_connection, b"E", b"timeout")
            return
        final_url, redirects, body = _fetch_document(url, deadline)
        metadata = json.dumps(
            {"final_url": final_url, "redirects": redirects},
            separators=(",", ":"),
        ).encode("utf-8")
        _send_frame(send_connection, b"M", metadata)
        for offset in range(0, len(body), IPC_CHUNK_BYTES):
            _remaining(deadline)
            _send_frame(
                send_connection,
                b"B",
                body[offset:offset + IPC_CHUNK_BYTES],
            )
        _send_frame(send_connection, b"Z")
    except _FetchFailure as error:
        code = error.code if error.code in _WORKER_ERRORS else "worker_failed"
        try:
            _send_frame(send_connection, b"E", code.encode("ascii"))
        except (BrokenPipeError, OSError, _FetchFailure):
            pass
    except Exception:
        try:
            _send_frame(send_connection, b"E", b"worker_failed")
        except (BrokenPipeError, OSError, _FetchFailure):
            pass
    finally:
        send_connection.close()


def _terminate_and_reap(process):
    if process.pid is None:
        return
    if process.is_alive():
        try:
            process.terminate()
        except OSError:
            pass
    process.join(timeout=0.25)
    if process.is_alive():
        try:
            process.kill()
        except OSError:
            pass
        process.join(timeout=0.5)
    if process.is_alive():
        raise RuntimeError("HTML fetch worker could not be reaped.")


def _run_fetch_worker(url, deadline):
    context = multiprocessing.get_context("spawn")
    receive_connection, send_connection = context.Pipe(duplex=False)
    start_gate = context.Event()
    process = context.Process(
        target=_fetch_worker,
        args=(url, deadline, start_gate, send_connection),
    )
    process.daemon = False
    job = None
    started = False
    metadata = None
    body = bytearray()
    frame_count = 0
    result = None
    try:
        if os.name == "nt":
            job = _WindowsWorkerJob()
        process.start()
        started = True
        send_connection.close()
        if job is not None:
            job.assign(process.pid)
        start_gate.set()

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                result = HTMLFetchResult("error", "timeout")
                break
            if not receive_connection.poll(min(remaining, 0.1)):
                if not process.is_alive():
                    result = HTMLFetchResult("error", "worker_failed")
                    break
                continue
            try:
                frame = receive_connection.recv_bytes(MAX_IPC_FRAME_BYTES)
            except (EOFError, OSError):
                result = HTMLFetchResult("error", "worker_failed")
                break
            frame_count += 1
            if frame_count > MAX_IPC_FRAMES:
                result = HTMLFetchResult("error", "worker_failed")
                break
            if not frame:
                result = HTMLFetchResult("error", "worker_failed")
                break
            kind, payload = frame[:1], frame[1:]
            if kind == b"M":
                if metadata is not None or len(payload) > 4096:
                    result = HTMLFetchResult("error", "worker_failed")
                    break
                try:
                    metadata = json.loads(payload.decode("utf-8"))
                except (UnicodeError, ValueError):
                    result = HTMLFetchResult("error", "worker_failed")
                    break
                if (
                    not isinstance(metadata, dict)
                    or not isinstance(metadata.get("final_url"), str)
                    or len(metadata["final_url"]) > 2048
                    or isinstance(metadata.get("redirects"), bool)
                    or not isinstance(metadata.get("redirects"), int)
                    or not 0 <= metadata["redirects"] <= MAX_REDIRECTS
                ):
                    result = HTMLFetchResult("error", "worker_failed")
                    break
                try:
                    normalized_final_url = _normalized_https_url(metadata["final_url"])
                except _FetchFailure:
                    normalized_final_url = None
                if normalized_final_url != metadata["final_url"]:
                    result = HTMLFetchResult("error", "worker_failed")
                    break
            elif kind == b"B":
                if metadata is None or not payload or len(payload) > IPC_CHUNK_BYTES:
                    result = HTMLFetchResult("error", "worker_failed")
                    break
                if len(body) + len(payload) > MAX_HTML_BODY_BYTES:
                    result = HTMLFetchResult("error", "worker_failed")
                    break
                body.extend(payload)
            elif kind == b"E":
                try:
                    code = payload.decode("ascii")
                except UnicodeError:
                    code = "worker_failed"
                if code not in _WORKER_ERRORS:
                    code = "worker_failed"
                result = HTMLFetchResult("error", code)
                break
            elif kind == b"Z":
                if metadata is None or not body:
                    result = HTMLFetchResult("error", "worker_failed")
                else:
                    result = HTMLFetchResult(
                        "observed",
                        "available",
                        bytes(body),
                        metadata["final_url"],
                        metadata["redirects"],
                    )
                break
            else:
                result = HTMLFetchResult("error", "worker_failed")
                break
    except Exception:
        result = HTMLFetchResult("error", "worker_failed")
    finally:
        try:
            if started or process.pid is not None:
                _terminate_and_reap(process)
        finally:
            receive_connection.close()
            send_connection.close()
            if job is not None:
                job.close()
    return result or HTMLFetchResult("error", "worker_failed")


class _WindowsWorkerJob:
    _KILL_ON_JOB_CLOSE = 0x2000
    _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9

    def __init__(self):
        if os.name != "nt":
            raise OSError("Windows job objects are unavailable.")
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self._kernel32.CreateJobObjectW.restype = ctypes.wintypes.HANDLE
        self._kernel32.OpenProcess.restype = ctypes.wintypes.HANDLE
        self._kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
        self._kernel32.OpenProcess.argtypes = [
            ctypes.wintypes.DWORD,
            ctypes.wintypes.BOOL,
            ctypes.wintypes.DWORD,
        ]
        self._kernel32.SetInformationJobObject.argtypes = [
            ctypes.wintypes.HANDLE,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.wintypes.DWORD,
        ]
        self._kernel32.AssignProcessToJobObject.argtypes = [
            ctypes.wintypes.HANDLE,
            ctypes.wintypes.HANDLE,
        ]
        self._kernel32.CloseHandle.argtypes = [ctypes.wintypes.HANDLE]
        self._handle = self._kernel32.CreateJobObjectW(None, None)
        if not self._handle:
            raise ctypes.WinError(ctypes.get_last_error())
        info = _ExtendedLimitInformation()
        info.BasicLimitInformation.LimitFlags = self._KILL_ON_JOB_CLOSE
        if not self._kernel32.SetInformationJobObject(
            self._handle,
            self._JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
            ctypes.byref(info),
            ctypes.sizeof(info),
        ):
            error = ctypes.WinError(ctypes.get_last_error())
            self.close()
            raise error

    def assign(self, process_id):
        process_handle = self._kernel32.OpenProcess(0x0100 | 0x0001, False, process_id)
        if not process_handle:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            if not self._kernel32.AssignProcessToJobObject(
                self._handle,
                process_handle,
            ):
                raise ctypes.WinError(ctypes.get_last_error())
        finally:
            self._kernel32.CloseHandle(process_handle)

    def close(self):
        if getattr(self, "_handle", None):
            self._kernel32.CloseHandle(self._handle)
            self._handle = None


def fetch_html(url):
    if not isinstance(url, str) or not url.strip():
        return HTMLFetchResult("error", "invalid_input")
    try:
        preliminary = urlsplit(url)
    except ValueError:
        return HTMLFetchResult("error", "invalid_input")
    if preliminary.scheme.lower() == "http" and preliminary.netloc:
        return HTMLFetchResult("unavailable", "https_required")
    try:
        scheme, _, port, _, _, _ = parse_http_url(url)
    except (DestinationSafetyError, TypeError, ValueError, UnicodeError):
        return HTMLFetchResult("error", "invalid_input")
    if scheme != "https" or port != 443:
        return HTMLFetchResult("unavailable", "https_required")

    deadline = time.monotonic() + HTML_RETRIEVAL_DEADLINE_SECONDS
    try:
        return _run_fetch_worker(url, deadline)
    except Exception:
        return HTMLFetchResult("error", "worker_failed")
