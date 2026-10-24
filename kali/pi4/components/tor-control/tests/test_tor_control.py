from contextlib import contextmanager
import copy
import datetime as dt
import importlib.util
import io
import hashlib
import hmac
import json
import os
from pathlib import Path
import ssl
import socket
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[4]
SPEC = importlib.util.spec_from_file_location("auto_tor", ROOT / "pi4/python/auto_tor.py")
tor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tor)
NOW = dt.datetime(2026, 10, 19, 18, 0, tzinfo=dt.timezone.utc)


def entry(node="A", address="1.1.1.1", status="2026-10-19 17:00:00", observed="2026-10-19 17:10:00"):
    return (f"ExitNode {node * 40}\nPublished 2026-10-18 21:00:00\n"
            f"LastStatus {status}\nExitAddress {address} {observed}\n").encode()


class Fetcher:
    def __init__(self, raw=None, ip="1.1.1.1", is_tor=True):
        self.raw = raw if raw is not None else entry()
        self.ip, self.is_tor, self.calls = ip, is_tor, []

    def get(self, path, limit):
        self.calls.append((path, limit))
        if path == tor.LIST_PATH:
            if isinstance(self.raw, Exception):
                raise self.raw
            return self.raw
        return json.dumps({"IP": self.ip, "IsTor": self.is_tor}).encode()


class MemoryStore:
    def __init__(self):
        self.value, self.writes, self.describes = {"old": True}, 0, 0

    @contextmanager
    def locked(self):
        yield

    def replace(self, value):
        self.value = copy.deepcopy(value)
        self.writes += 1

    def describe(self):
        self.describes += 1
        return "Exit list: not downloaded\nExit list path: /var/lib/automations/tor-exits.json"


class ParseTests(unittest.TestCase):
    def test_parse_source_times_deduplicate_and_keep_latest(self):
        result = tor.parse_exit_list(entry() + entry("B", observed="2026-10-19 17:30:00"), NOW)
        self.assertEqual(result["addresses"], {"1.1.1.1": "2026-10-19T17:30:00Z"})
        self.assertEqual(result["source_at"], "2026-10-19T17:00:00Z")
        self.assertEqual(result["fetched_at"], "2026-10-19T18:00:00Z")
        self.assertEqual(result["coverage"], "observed-ipv4")

    def test_fresh_download_cannot_revive_old_source(self):
        with self.assertRaisesRegex(tor.Error, "older than six hours"):
            tor.parse_exit_list(entry(status="2026-10-19 11:59:59"), NOW)

    def test_old_observations_are_excluded_not_currently_verified(self):
        raw = entry() + entry("B", "8.8.8.8", observed="2026-10-18 17:59:59")
        self.assertEqual(set(tor.parse_exit_list(raw, NOW)["addresses"]), {"1.1.1.1"})

    def test_all_old_observations_fail(self):
        with self.assertRaisesRegex(tor.Error, "no IPv4 observations"):
            tor.parse_exit_list(entry(observed="2026-10-18 17:59:59"), NOW)

    def test_stale_relay_status_does_not_count_with_recent_other_relay(self):
        result = tor.parse_exit_list(entry() + entry("B", "8.8.8.8", status="2026-10-18 17:59:59"), NOW)
        self.assertEqual(set(result["addresses"]), {"1.1.1.1"})

    def test_future_source_or_observation_fails(self):
        for raw in (entry(status="2026-10-19 18:05:01"), entry(observed="2026-10-19 18:05:01")):
            with self.subTest(raw=raw), self.assertRaisesRegex(tor.Error, "future-dated"):
                tor.parse_exit_list(raw, NOW)

    def test_empty_html_unknown_truncated_and_duplicate_fail(self):
        for raw in (b"", b"<html>Error</html>", entry() + b"foo bar\n", entry().split(b"ExitAddress")[0], entry() * 2):
            with self.subTest(raw=raw), self.assertRaises(tor.Error):
                tor.parse_exit_list(raw, NOW)

    def test_private_multicast_scoped_invalid_addresses_fail(self):
        for value in ("127.0.0.1", "10.78.0.1", "224.0.0.1", "::1", "fe80::1%eth0", "not-an-ip", "1.1.1.1\n"):
            with self.subTest(value=value), self.assertRaises(tor.Error):
                tor.public_ip(value)

    def test_unknown_ipv6_source_format_fails(self):
        with self.assertRaisesRegex(tor.Error, "unsupported address-family"):
            tor.parse_exit_list(entry(address="2606:4700:4700::1111"), NOW)

    def test_size_line_and_record_limits(self):
        for raw in (b"a" * (tor.MAX_LIST + 1), entry() + b"z" * 257):
            with self.subTest(size=len(raw)), self.assertRaises(tor.Error):
                tor.parse_exit_list(raw, NOW)
        with patch.object(tor, "MAX_RECORDS", 1), self.assertRaises(tor.Error):
            tor.parse_exit_list(entry() + entry("B"), NOW)


class CheckTests(unittest.TestCase):
    def test_each_check_downloads_and_replaces_same_store(self):
        fetcher, store = Fetcher(), MemoryStore()
        for _ in range(2):
            result = tor.check_exit(fetcher, store, now=NOW)
            self.assertEqual(result["result"], "VERIFIED")
        self.assertEqual(store.writes, 2)
        self.assertEqual([x[0] for x in fetcher.calls], [tor.LIST_PATH, tor.IP_PATH] * 2)

    def test_explicit_ip_does_not_measure_own_address(self):
        fetcher, store = Fetcher(), MemoryStore()
        result = tor.check_exit(fetcher, store, "8.8.8.8", NOW)
        self.assertEqual(result["result"], "NOT LISTED")
        self.assertEqual(fetcher.calls, [(tor.LIST_PATH, tor.MAX_LIST)])

    def test_download_error_preserves_old_file_and_never_checks_it(self):
        fetcher, store = Fetcher(tor.Error("HTTP error")), MemoryStore()
        with self.assertRaisesRegex(tor.Error, "No previous list was used"):
            tor.check_exit(fetcher, store, now=NOW)
        self.assertEqual(store.value, {"old": True})
        self.assertEqual(store.writes, 0)
        self.assertEqual(fetcher.calls, [(tor.LIST_PATH, tor.MAX_LIST)])

    def test_bad_source_preserves_old_file_without_ip_lookup(self):
        fetcher, store = Fetcher(entry(status="2026-10-19 11:00:00")), MemoryStore()
        with self.assertRaises(tor.Error):
            tor.check_exit(fetcher, store, now=NOW)
        self.assertEqual(store.writes, 0)
        self.assertEqual(fetcher.calls, [(tor.LIST_PATH, tor.MAX_LIST)])

    def test_ipv6_is_error_after_fresh_fetch_not_false_negative(self):
        fetcher, store = Fetcher(), MemoryStore()
        with self.assertRaisesRegex(tor.Error, "IPv6 address cannot be checked"):
            tor.check_exit(fetcher, store, "2606:4700:4700::1111", NOW)
        self.assertEqual(store.writes, 1)
        self.assertEqual(fetcher.calls, [(tor.LIST_PATH, tor.MAX_LIST)])

    def test_invalid_ip_fails_before_fetch(self):
        fetcher = Fetcher()
        with self.assertRaises(tor.Error):
            tor.check_exit(fetcher, MemoryStore(), "http://evil.invalid", NOW)
        self.assertEqual(fetcher.calls, [])

    def test_ip_json_is_strict_and_public(self):
        for raw in (b'{"IP":"1.1.1.1","IsTor":"true"}',
                    b'{"IP":"127.0.0.1","IsTor":true}', b'{"IP":"1.1.1.1","IP":"8.8.8.8","IsTor":true}'):
            fetcher = type("JSONFetcher", (), {"get": lambda self, *args: raw})()
            with self.subTest(raw=raw), self.assertRaises(tor.Error):
                tor.observe_ip(fetcher)


class StoreTests(unittest.TestCase):
    def test_atomic_replace_keeps_one_file_and_no_temp_files(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "owned" / "tor-exits.json"
            store = tor.ExitStore(path)
            with patch.object(tor, "trusted_directory"), patch.object(tor, "trusted_read", side_effect=lambda p, *a: p.read_bytes()):
                store.replace({"old": True})
                store.replace({"new": True})
            self.assertEqual(json.loads(path.read_bytes()), {"new": True})
            self.assertEqual([x.name for x in path.parent.iterdir()], ["tor-exits.json"])
            self.assertEqual(path.stat().st_mode & 0o777, 0o644)

    def test_rename_error_preserves_old_and_removes_temporary(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tor-exits.json"
            path.write_bytes(b"old")
            store = tor.ExitStore(path)
            with patch.object(tor, "trusted_directory"), patch.object(tor, "trusted_read", side_effect=lambda p, *a: p.read_bytes()), \
                 patch.object(tor.os, "replace", side_effect=OSError("failure")):
                with self.assertRaises(OSError):
                    store.replace({"new": True})
            self.assertEqual(path.read_bytes(), b"old")
            self.assertEqual([x.name for x in path.parent.iterdir()], ["tor-exits.json"])

    def test_concurrent_change_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "tor-exits.json"
            path.write_bytes(b"external")
            store = tor.ExitStore(path)
            with patch.object(tor, "trusted_directory"), patch.object(store, "current", side_effect=[b"old", b"external"]):
                with self.assertRaisesRegex(tor.Error, "concurrently"):
                    store.replace({"new": True})
            self.assertEqual(path.read_bytes(), b"external")
            self.assertEqual([x.name for x in path.parent.iterdir()], ["tor-exits.json"])

    def test_missing_status_never_creates_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing.json"
            with patch.object(tor, "trusted_directory"):
                self.assertIn("not downloaded", tor.ExitStore(path).describe())
            self.assertFalse(path.exists())


class HTTPTests(unittest.TestCase):
    def test_start_failure_closes_pipes_without_joining_unstarted_worker(self):
        receive, send, worker = Mock(), Mock(), Mock()
        worker.start.side_effect = OSError("fixture start failure")
        context = Mock()
        context.Pipe.return_value = receive, send
        context.Process.return_value = worker
        with patch.object(tor.multiprocessing, "get_context", return_value=context), \
             self.assertRaisesRegex(OSError, "fixture start failure"):
            tor.HTTPS().get(tor.LIST_PATH, 100)
        receive.close.assert_called_once_with()
        send.close.assert_called_once_with()
        worker.close.assert_called_once_with()
        worker.join.assert_not_called()
        worker.terminate.assert_not_called()

    def test_total_deadline_kills_and_reaps_stalled_request_without_network(self):
        before = {child.pid for child in tor.multiprocessing.active_children()}
        started = time.monotonic()
        with patch.object(tor.HTTPS, "_get", side_effect=lambda *args: time.sleep(20)):
            with self.assertRaisesRegex(tor.Error, "total deadline"):
                tor.HTTPS(timeout=0.05).get(tor.LIST_PATH, 100)
        self.assertLess(time.monotonic() - started, 3)
        self.assertEqual({child.pid for child in tor.multiprocessing.active_children()}, before)

    def test_bounded_worker_returns_bytes_and_safe_errors(self):
        with patch.object(tor.HTTPS, "_get", return_value=b"fixture"):
            self.assertEqual(tor.HTTPS(timeout=2).get(tor.LIST_PATH, 100), b"fixture")
        with patch.object(tor.HTTPS, "_get", side_effect=tor.Error("fixture error")), self.assertRaisesRegex(tor.Error, "fixture error"):
            tor.HTTPS(timeout=2).get(tor.LIST_PATH, 100)

    def test_current_route_measurement_uses_ipv4_without_ipv6_attempt(self):
        stream = FakeSocket(b"")
        stream.connect = lambda peer: self.assertEqual(peer, ("1.1.1.1", 443))
        with patch.object(tor.socket, "getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443))]) as resolve, \
             patch.object(tor.socket, "socket", return_value=stream):
            self.assertIs(tor.ipv4_connection((tor.HOST, 443), 20), stream)
        resolve.assert_called_once_with(tor.HOST, 443, socket.AF_INET, socket.SOCK_STREAM)

    class Response:
        def __init__(self, status=200, data=b"x", headers=None):
            self.status, self.data, self.headers = status, data, headers or {}
        def getheader(self, key, default=None):
            return self.headers.get(key, default)
        def read(self, limit):
            result, self.data = self.data[:limit], self.data[limit:]
            return result
        read1 = read

    class Connection:
        def __init__(self, response):
            self.response, self.requests, self.closed = response, [], False
            self.sock = None
        def connect(self):
            pass
        def request(self, *args, **kwargs):
            self.requests.append((args, kwargs))
        def getresponse(self):
            return self.response
        def close(self):
            self.closed = True

    def test_fixed_https_host_verified_tls_no_redirect(self):
        connection = self.Connection(self.Response(status=302, headers={"Location": "http://evil.invalid/"}))
        with patch.object(tor.http.client, "HTTPSConnection", return_value=connection) as factory:
            with self.assertRaises(tor.Error):
                tor.HTTPS()._get(tor.LIST_PATH, 100)
        self.assertEqual(factory.call_args.args, (tor.HOST, 443))
        context = factory.call_args.kwargs["context"]
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        self.assertEqual(len(connection.requests), 1)
        self.assertTrue(connection.closed)

    def test_unrecognized_path_has_no_network_call(self):
        with patch.object(tor.http.client, "HTTPSConnection") as factory:
            with self.assertRaises(tor.Error):
                tor.HTTPS()._get("https://evil.invalid/", 100)
        factory.assert_not_called()

    def test_size_empty_encoding_rejected(self):
        for response in (self.Response(data=b""), self.Response(data=b"12345"),
                         self.Response(headers={"Content-Length": "9999"}),
                         self.Response(headers={"Content-Encoding": "gzip"})):
            with self.subTest(response=response):
                connection = self.Connection(response)
                with patch.object(tor.http.client, "HTTPSConnection", return_value=connection), self.assertRaises(tor.Error):
                    tor.HTTPS()._get(tor.LIST_PATH, 4)
                self.assertTrue(connection.closed)

    def test_truncated_and_slow_body_are_errors(self):
        connection = self.Connection(self.Response(data=b"x", headers={"Content-Length": "2"}))
        with patch.object(tor.http.client, "HTTPSConnection", return_value=connection), self.assertRaisesRegex(tor.Error, "truncated"):
            tor.HTTPS()._get(tor.LIST_PATH, 100)
        connection = self.Connection(self.Response(data=b"x"))
        with patch.object(tor.http.client, "HTTPSConnection", return_value=connection), \
             patch.object(tor.time, "monotonic", side_effect=[0, 21]), self.assertRaisesRegex(tor.Error, "deadline"):
            tor.HTTPS(timeout=20)._get(tor.LIST_PATH, 100)


class FakeRuntime:
    def __init__(self):
        self.calls = []
    def status(self):
        self.calls.append("status")
        return {"mode": "off", "phase": "off", "ready": False, "interface": "wlan0", "error": None}
    @contextmanager
    def operation(self, mode):
        self.calls.append(("operation", mode))
        try:
            yield self
        except BaseException:
            self.calls.append("block-on-error")
            raise
    def activate(self, *args):
        self.calls.append(("activate", args))
    def ready(self):
        self.calls.append("ready")
    def recover(self):
        self.calls.append("recover")
    def block(self):
        self.calls.append("block")
    def deactivate(self):
        self.calls.append("deactivate")


class FakePlatform:
    def __init__(self, runtime, fail=False):
        self.runtime, self.fail = runtime, fail
    def account(self):
        return 991
    def definition(self):
        pass
    def active(self):
        return False
    def generation(self):
        return ("a" * 32, 123) if self.active() else None
    def recovery_enabled(self):
        return True
    def recovery_start(self):
        self.runtime.calls.append("recovery-start")
    def recovery_stop(self):
        self.runtime.calls.append("recovery-stop")
    def rotation(self):
        return {"active": False, "seconds": None}
    def rotation_stop(self):
        self.runtime.calls.append("rotation-stop")
    def rotation_start(self, seconds):
        self.runtime.calls.append(("rotation-start", seconds))
    def start(self):
        self.runtime.calls.append("start")
    def stop(self):
        self.runtime.calls.append("stop")
    def wait_ready(self):
        self.runtime.calls.append("observe")
        if self.fail:
            raise tor.Error("bootstrap failed")
        return {"ip": "1.1.1.1", "observed_at": "now", "tor_reported": True}


class CLITests(unittest.TestCase):
    def test_installed_definition_hashes_match_payloads(self):
        names = {path: path.name for path in tor.DEFINITION_HASHES}
        for path, name in names.items():
            data = next(candidate for group in ("common", "pi4") if (candidate := ROOT / group / "components/tor-control/files" / name).is_file()).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), tor.DEFINITION_HASHES[path])
            with patch.object(tor, "trusted_read", return_value=data):
                tor.installed_definition(path)
            with patch.object(tor, "trusted_read", return_value=data + b"# foreign change\n"), self.assertRaises(tor.Error):
                tor.installed_definition(path)

    def test_check_status_no_list_download_or_membership(self):
        runtime, fetcher, store = FakeRuntime(), Fetcher(), MemoryStore()
        with patch.object(tor.os, "geteuid", return_value=0), patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(tor.main(["--check", "--status"], runtime=runtime, platform=FakePlatform(runtime), fetcher=fetcher, store=store), 0)
        self.assertEqual(fetcher.calls, [(tor.IP_PATH, 16384)])
        self.assertEqual(store.writes, 0)
        self.assertEqual(store.describes, 1)
        self.assertEqual(runtime.calls, ["status"])

    def test_help_unprivileged_no_runtime_or_network(self):
        with patch.object(tor.os, "geteuid", return_value=1000), patch.object(tor, "load_egress") as loader, \
             patch.object(tor.HTTPS, "get") as request, patch("sys.stdout", new_callable=io.StringIO):
            with self.assertRaises(SystemExit) as end:
                tor.main(["--help"])
        self.assertEqual(end.exception.code, 0)
        loader.assert_not_called()
        request.assert_not_called()

    def test_invalid_combinations_do_not_access_network(self):
        for argv in (["--check", "--on"], ["--ip", "1.1.1.1"], ["--check", "--status", "--ip", "1.1.1.1"]):
            with self.subTest(argv=argv), patch.object(tor.HTTPS, "get") as request, self.assertRaises(tor.Error):
                tor.main(argv)
            request.assert_not_called()

    def test_activation_guard_before_service_and_ready_after_probe(self):
        runtime = FakeRuntime()
        with patch.object(tor.os, "geteuid", return_value=0), patch("sys.stdout", new_callable=io.StringIO):
            tor.main(["--on"], runtime=runtime, platform=FakePlatform(runtime))
        self.assertEqual(runtime.calls, [("operation", "tor"), "status", ("activate", (991, 19040, 19053)), "recovery-start", "start", "observe", "ready"])

    def test_repeated_on_observes_without_restart_or_replacing_guard(self):
        runtime, fetcher = FakeRuntime(), Fetcher()
        platform = FakePlatform(runtime)
        state = {"mode": "tor", "phase": "active", "ready": True, "interface": "wlan0", "error": None}
        with patch.object(tor.os, "geteuid", return_value=0), patch("sys.stdout", new_callable=io.StringIO), \
             patch.object(runtime, "status", return_value=state), patch.object(platform, "active", return_value=True):
            tor.main(["--on"], runtime=runtime, platform=platform, fetcher=fetcher)
        self.assertEqual(runtime.calls, [("operation", "tor"), "recovery-start"])
        self.assertEqual(fetcher.calls, [(tor.IP_PATH, 16384)])

    def test_configured_route_with_dead_service_is_not_successful_status(self):
        runtime, fetcher = FakeRuntime(), Fetcher()
        state = {"mode": "tor", "phase": "active", "ready": True, "interface": "wlan0", "error": None}
        with patch.object(tor.os, "geteuid", return_value=0), patch("sys.stdout", new_callable=io.StringIO), \
             patch.object(runtime, "status", return_value=state), self.assertRaisesRegex(tor.Error, "not active"):
            tor.main(["--status"], runtime=runtime, platform=FakePlatform(runtime), fetcher=fetcher)
        self.assertEqual(fetcher.calls, [])

    def test_bootstrap_failure_leaves_guard_without_restore(self):
        runtime = FakeRuntime()
        with patch.object(tor.os, "geteuid", return_value=0), self.assertRaises(tor.Error):
            tor.main(["--on"], runtime=runtime, platform=FakePlatform(runtime, fail=True))
        self.assertEqual(runtime.calls[-1], "block-on-error")
        self.assertNotIn("ready", runtime.calls)
        self.assertNotIn("deactivate", runtime.calls)

    def test_orphan_service_is_not_adopted_or_reconfigured(self):
        runtime, platform = FakeRuntime(), FakePlatform(None)
        with patch.object(tor.os, "geteuid", return_value=0), patch.object(platform, "active", return_value=True), \
             patch.object(platform, "account") as account, self.assertRaisesRegex(tor.Error, "without matching routing"):
            tor.main(["--on"], runtime=runtime, platform=platform)
        account.assert_not_called()
        self.assertFalse(any(isinstance(call, tuple) and call[0] == "activate" for call in runtime.calls))

    def test_off_blocks_then_stops_before_restoring(self):
        runtime = FakeRuntime()
        with patch.object(tor.os, "geteuid", return_value=0), patch("sys.stdout", new_callable=io.StringIO):
            tor.main(["--off"], runtime=runtime, platform=FakePlatform(runtime))
        self.assertEqual(runtime.calls, [("operation", "tor"), "rotation-stop", "recovery-stop", "block", "stop", "deactivate"])

    def test_fixed_service_is_inert_and_separate(self):
        service = (ROOT / "pi4/components/tor-control/files/automations-tor.service").read_text()
        config = (ROOT / "pi4/components/tor-control/files/torrc").read_text()
        self.assertNotIn("[Install]", service)
        self.assertIn("User=auto-tor", service)
        self.assertIn("--defaults-torrc /dev/null", service)
        self.assertIn("ClientUseIPv6 0", config)
        self.assertIn("SocksPort 127.0.0.1:19050", config)
        self.assertNotIn("0.0.0.0", config)
        self.assertNotIn("ORPort", config)


class FakeSocket:
    def __init__(self, reply):
        self.reply, self.sent, self.closed = reply, [], False
    def sendall(self, data):
        self.sent.append(data)
    def recv(self, limit):
        if not self.reply:
            raise socket.timeout()
        data, self.reply = self.reply[:limit], self.reply[limit:]
        return data
    def settimeout(self, timeout):
        pass
    def close(self):
        self.closed = True


COOKIE, CLIENT_NONCE, SERVER_NONCE = b"c" * 32, b"n" * 32, b"s" * 32


def control_reply(final=b"250 OK\r\n650 SIGNAL NEWNYM\r\n", server_hash=None):
    digest = server_hash or hmac.digest(b"Tor safe cookie authentication server-to-controller hash",
                                      COOKIE + CLIENT_NONCE + SERVER_NONCE, "sha256")
    return (b"250 AUTHCHALLENGE SERVERHASH=" + digest.hex().encode() + b" SERVERNONCE=" +
            SERVER_NONCE.hex().encode() + b"\r\n250 OK\r\n250 OK\r\n" + final)


class RotationTests(unittest.TestCase):
    def test_interval_units_and_bounds(self):
        for value, expected in (("30s", 30), ("60s", 60), ("1m", 60), ("10m", 600), ("24h", 86400), ("86400s", 86400)):
            self.assertEqual(tor.interval(value), expected)
        for value in ("29s", "0m", "25h", "10", "1.5m", "-1h", "1H", "01m", "1m;id"):
            with self.subTest(value=value), self.assertRaises(tor.Error):
                tor.interval(value)

    def test_safecookie_authenticates_server_and_confirms_action(self):
        stream = FakeSocket(control_reply())
        control = tor.Control(stream, COOKIE, nonce=CLIENT_NONCE)
        control.authenticate()
        control.newnym()
        self.assertEqual(stream.sent[-1], b"SIGNAL NEWNYM\r\n")
        self.assertEqual(stream.sent[-2], b"SETEVENTS SIGNAL\r\n")
        self.assertNotIn(COOKIE.hex().encode(), b"".join(stream.sent))
        expected = hmac.digest(b"Tor safe cookie authentication controller-to-server hash",
                              COOKIE + CLIENT_NONCE + SERVER_NONCE, "sha256")
        self.assertIn(b"AUTHENTICATE " + expected.hex().encode() + b"\r\n", stream.sent)

    def test_wrong_server_proof_does_not_disclose_authentication(self):
        stream = FakeSocket(control_reply(server_hash=b"x" * 32))
        with self.assertRaisesRegex(tor.Error, "identity check"):
            tor.Control(stream, COOKIE, nonce=CLIENT_NONCE).authenticate()
        self.assertEqual(len(stream.sent), 1)

    def test_acknowledged_but_ignored_newnym_is_not_success(self):
        stream = FakeSocket(control_reply(final=b"250 OK\r\n"))
        control = tor.Control(stream, COOKIE, nonce=CLIENT_NONCE)
        control.authenticate()
        with self.assertRaisesRegex(tor.Error, "rate limit"):
            control.newnym()

    def test_event_before_ack_is_supported(self):
        stream = FakeSocket(control_reply(final=b"650 SIGNAL NEWNYM\r\n250 OK\r\n"))
        control = tor.Control(stream, COOKIE, nonce=CLIENT_NONCE)
        control.authenticate()
        control.newnym()

    def test_reply_line_limit(self):
        with self.assertRaisesRegex(tor.Error, "size limit"):
            tor.Control(FakeSocket(b"a" * 9000), COOKIE).line(tor.time.monotonic() + 2)

    def test_shared_rotation_record_rate_limits_before_second_signal(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(tor, "ROTATION_LOCK", Path(directory) / "rotation.lock"), \
             patch.object(tor.secrets, "token_bytes", return_value=CLIENT_NONCE), \
             patch.object(tor.pwd, "getpwnam", return_value=SimpleNamespace(pw_gid=os.getegid())):
            stream = FakeSocket(control_reply())
            tor.rotate_client(identity=lambda: (os.geteuid(), COOKIE), connector=lambda: stream, monotonic=lambda: 100)
            self.assertTrue(stream.closed)
            with self.assertRaisesRegex(tor.Error, "rate-limited"):
                tor.rotate_client(identity=lambda: (os.geteuid(), COOKIE), connector=lambda: self.fail("Must not connect"), monotonic=lambda: 105)
            retry = FakeSocket(control_reply())
            tor.rotate_client(identity=lambda: (os.geteuid(), COOKIE), connector=lambda: retry, monotonic=lambda: 111)
            self.assertEqual(retry.sent[-1], b"SIGNAL NEWNYM\r\n")

    def test_manual_rotation_reports_same_ip_without_claiming_change(self):
        runtime, fetcher = FakeRuntime(), Fetcher()
        platform = FakePlatform(runtime)
        state = {"mode": "tor", "phase": "active", "ready": True, "interface": "wlan0", "error": None}
        with patch.object(tor.os, "geteuid", return_value=0), patch("sys.stdout", new_callable=io.StringIO) as output, \
             patch.object(runtime, "status", return_value=state), patch.object(platform, "active", return_value=True), \
             patch.object(tor, "rotate_client") as rotate:
            tor.main(["--rotate"], runtime=runtime, platform=platform, fetcher=fetcher)
        rotate.assert_called_once()
        self.assertIn("1.1.1.1", output.getvalue())
        self.assertIn("not guaranteed", output.getvalue())
        self.assertNotIn("start", runtime.calls)
        self.assertNotIn("deactivate", runtime.calls)

    def test_rate_limit_error_does_not_block_healthy_existing_route(self):
        runtime, platform = FakeRuntime(), FakePlatform(None)
        state = {"mode": "tor", "phase": "active", "ready": True, "interface": "wlan0", "error": None}
        with patch.object(tor.os, "geteuid", return_value=0), patch.object(runtime, "status", return_value=state), \
             patch.object(platform, "active", return_value=True), patch.object(tor, "rotate_client", side_effect=tor.Error("rate-limited")), \
             self.assertRaisesRegex(tor.Error, "rate-limited"):
            tor.main(["--rotate"], runtime=runtime, platform=platform)
        self.assertNotIn("block-on-error", runtime.calls)

    def test_on_combined_interval_and_stop_timer_only(self):
        runtime = FakeRuntime()
        with patch.object(tor.os, "geteuid", return_value=0), patch("sys.stdout", new_callable=io.StringIO):
            tor.main(["--on", "--rotate-every", "10m"], runtime=runtime, platform=FakePlatform(runtime))
        self.assertEqual(runtime.calls[-1], ("rotation-start", 600))
        runtime.calls.clear()
        with patch.object(tor.os, "geteuid", return_value=0), patch("sys.stdout", new_callable=io.StringIO):
            tor.main(["--rotation-off"], runtime=runtime, platform=FakePlatform(runtime))
        self.assertEqual(runtime.calls, [("operation", "tor"), "rotation-stop"])

    def test_worker_is_nonroot_waits_then_rotates_silently(self):
        account = type("Account", (), {"pw_uid": 991})()
        calls = []
        def sleep(seconds):
            calls.append(("sleep", seconds))
            if len(calls) > 1:
                raise StopIteration()
        with patch.object(tor.os, "geteuid", return_value=991), patch.object(tor.pwd, "getpwnam", return_value=account), \
             patch("sys.stdout", new_callable=io.StringIO) as stdout, patch("sys.stderr", new_callable=io.StringIO) as stderr:
            with self.assertRaises(StopIteration):
                tor.rotation_worker(60, rotate=lambda: calls.append("rotate"), sleep=sleep)
        self.assertEqual(calls[:2], [("sleep", 60), "rotate"])
        self.assertEqual(stdout.getvalue() + stderr.getvalue(), "")
        with patch.object(tor.os, "geteuid", return_value=0), patch.object(tor.pwd, "getpwnam", return_value=account), self.assertRaises(tor.Error):
            tor.rotation_worker(60)

    def test_rotation_stop_absent_is_idempotent(self):
        platform = tor.Platform()
        with patch.object(platform, "run", return_value="LoadState=not-found\nActiveState=inactive\n") as run:
            platform.rotation_stop()
        self.assertEqual(run.call_count, 1)

    def test_foreign_rotation_unit_rejected(self):
        platform = tor.Platform()
        with patch.object(platform, "run", return_value="LoadState=loaded\nTransient=no\n"), self.assertRaises(tor.Error):
            platform.rotation_stop()


if __name__ == "__main__":
    unittest.main()
