"""Real loopback TLS regression: HTTP/1.0 closes the connection at headers."""
import http.server
from contextlib import contextmanager
import socketserver
import time
import importlib.util
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
SPEC = importlib.util.spec_from_file_location("tor_https_close", ROOT / "pi4/python/auto_tor.py")
tor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tor)
BODY = b'{"IP":"1.1.1.1","IsTor":true}'


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_GET(self):
        assert self.path == tor.IP_PATH
        self.send_response(200)
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *args):
        pass


class HTTPSConnectionCloseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cert, key = Path(cls.directory.name)/"cert.pem", Path(cls.directory.name)/"key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
                        "ec_paramgen_curve:P-256", "-nodes", "-days", "1",
                        "-subj", "/CN=check.torproject.org", "-addext", "subjectAltName=DNS:check.torproject.org",
                        "-keyout", str(key), "-out", str(cert)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        cls.server_context = context
        cls.client = ssl.create_default_context(cafile=str(cert))
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.server.socket = context.wrap_socket(cls.server.socket, server_side=True)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(3)
        cls.directory.cleanup()

    def test_response_body_survives_closed_connection_socket_in_both_paths(self):
        self.assertTrue(self.client.check_hostname)
        self.assertEqual(self.client.verify_mode, ssl.CERT_REQUIRED)
        def direct(address, timeout, source_address=None, phase=None):
            self.assertEqual(address, (tor.HOST, 443))
            return socket.create_connection(self.server.server_address, timeout)
        def socks(timeout):
            return socket.create_connection(self.server.server_address, timeout)
        for through_socks in (False, True):
            with self.subTest(socks=through_socks), \
                    patch.object(tor, "ipv4_connection", side_effect=direct), \
                    patch.object(tor, "socks_socket", side_effect=socks), \
                    patch.object(tor.ssl, "create_default_context", return_value=self.client):
                self.assertEqual(tor.HTTPS(socks=through_socks, timeout=5)._get(tor.IP_PATH, 1024), BODY)


    @contextmanager
    def handshake_endpoint(self, aborts):
        attempts = []
        context = self.server_context
        class Endpoint(socketserver.BaseRequestHandler):
            def handle(inner):
                attempts.append(time.monotonic())
                if len(attempts) <= aborts:
                    inner.request.shutdown(socket.SHUT_RDWR)
                    return
                try:
                    with context.wrap_socket(inner.request, server_side=True) as stream:
                        stream.settimeout(2)
                        request = bytearray()
                        while b"\r\n\r\n" not in request and len(request) < 8192:
                            block = stream.recv(1024)
                            if not block: return
                            request.extend(block)
                        stream.sendall(b"HTTP/1.0 200 OK\r\nConnection: close\r\nContent-Length: "
                                       + str(len(BODY)).encode() + b"\r\n\r\n" + BODY)
                except ssl.SSLError:
                    pass  # Expected peer alert in the certificate-rejection fixture.
        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Endpoint)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server.server_address, attempts
        finally:
            server.shutdown(); server.server_close(); thread.join(3)

    def get_from_endpoint(self, endpoint, socks=False, client=None):
        def connect(address, timeout, source_address=None, phase=None):
            self.assertEqual(address, (tor.HOST, 443))
            return socket.create_connection(endpoint, timeout)
        with patch.object(tor, "ipv4_connection", side_effect=connect), \
                patch.object(tor, "socks_socket", side_effect=lambda timeout: socket.create_connection(endpoint, timeout)), \
                patch.object(tor.ssl, "create_default_context", return_value=client or self.client):
            return tor.HTTPS(socks=socks, timeout=3)._get(tor.IP_PATH, 1024)

    def test_one_real_tls_handshake_eof_then_success_uses_fresh_connection(self):
        for socks in (False, True):
            with self.subTest(socks=socks), self.handshake_endpoint(aborts=1) as (endpoint, attempts):
                self.assertEqual(self.get_from_endpoint(endpoint, socks=socks), BODY)
                self.assertEqual(len(attempts), 2)

    def test_permanent_handshake_eof_stops_after_three_attempts(self):
        with self.handshake_endpoint(aborts=99) as (endpoint, attempts):
            started = time.monotonic()
            with self.assertRaisesRegex(tor.Error, "three transport attempts"):
                self.get_from_endpoint(endpoint)
            self.assertEqual(len(attempts), 3)
            self.assertLess(time.monotonic() - started, 3)

    def test_certificate_failure_is_never_retried(self):
        untrusted = ssl.create_default_context()
        with self.handshake_endpoint(aborts=0) as (endpoint, attempts):
            with self.assertRaisesRegex(tor.Error, "HTTPS certificate"):
                self.get_from_endpoint(endpoint, client=untrusted)
            self.assertEqual(len(attempts), 1)

    def test_attempts_share_one_deadline(self):
        fetcher = tor.HTTPS(timeout=1)
        with patch.object(tor.time, "monotonic", side_effect=[0, 0.1, 0.7, 1.1]), \
                patch.object(fetcher, "_get_once", side_effect=tor._RetryableTransportError("reset")) as once:
            with self.assertRaisesRegex(tor.Error, "total deadline"):
                fetcher._get(tor.IP_PATH, 1024)
        self.assertEqual(once.call_count, 2)
        self.assertTrue(all(call.args[2] == 1 for call in once.call_args_list))

    def test_non_transport_failures_are_not_retried(self):
        fetcher = tor.HTTPS()
        for message in ("HTTP status", "invalid response", "truncated response"):
            with self.subTest(message=message), \
                    patch.object(fetcher, "_get_once", side_effect=tor.Error(message)) as once:
                with self.assertRaisesRegex(tor.Error, message):
                    fetcher._get(tor.IP_PATH, 1024)
                self.assertEqual(once.call_count, 1)


    def test_connect_reset_retains_retryable_transport_classification(self):
        from unittest.mock import Mock
        stream = Mock()
        stream.connect.side_effect = ConnectionResetError(104, "fixture reset")
        with patch.object(tor.socket, "getaddrinfo", return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443))]), \
                patch.object(tor.socket, "socket", return_value=stream):
            with self.assertRaises(tor._RetryableTransportError):
                tor.ipv4_connection((tor.HOST, 443), 1)
        stream.close.assert_called_once()
