"""Recovery against the real shared-routing state machine; no external network."""
import copy
from contextlib import ExitStack, contextmanager
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


tor = load("tor_recovery_test", ROOT / "pi4/python/auto_tor.py")
fixture = load("recovery_routing_fixture", ROOT / "pi4/components/anonymity-runtime/tests/test_egress.py")
egress = fixture.egress


class Service:
    def __init__(self, runtime, network):
        self.r, self.network = runtime, network
        self.enabled, self.invocation, self.starts = True, None, 0

    def recovery_enabled(self):
        return self.enabled

    def definition(self):
        pass

    def generation(self):
        return self.invocation

    def start(self):
        assert self.r.state()["phase"] == "recovering"
        self.starts += 1
        self.invocation = (str(self.starts).zfill(32), 777)
        self.network.privacy_active = True


class Fetcher:
    def __init__(self, callback=None, tor_request=True):
        self.callback, self.tor_request, self.calls = callback, tor_request, 0

    def get(self, path, limit):
        assert path == tor.IP_PATH
        self.calls += 1
        if self.callback:
            self.callback()
        return json.dumps({"IP": "1.1.1.1", "IsTor": self.tor_request}).encode()


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.network = fixture.Platform(Path(self.temp.name))
        helper = self.network.path("usr/local/libexec/automations-support/egress.py")
        helper.parent.mkdir(parents=True)
        helper.write_bytes((ROOT / "pi4/python/egress.py").read_bytes())
        helper.chmod(0o644)
        self.r = egress.Runtime(fixture.share, self.network,
                               lambda name: types.SimpleNamespace(pw_uid=60001))
        self.network.change("lan")
        with self.r.operation("tor") as op:
            op.activate(60001, 19040, 19053)
            op.ready()
        self.service = Service(self.r, self.network)
        self.stdout = patch("sys.stdout", new_callable=io.StringIO)
        self.stdout.start()
        self.addCleanup(self.stdout.stop)

    def assert_closed_bootstrap(self):
        self.assertEqual(self.r.state()["phase"], "recovering")
        egress.check_objects(self.network.fw, self.r.state())
        self.assertFalse(self.r.status()["ready"])
        rules = [v for k, v in egress.objects(self.r.state()) if k == "rule"]
        self.assertTrue(any(v["comment"] == "auto-privacy:transport-ip" for v in rules))
        for chain in ("egress", "recovery_input"):
            for protocol in ("tcp", "udp"):
                self.assertTrue(any(v["comment"] == "auto-privacy:recovery-close-" + chain + "-" + protocol
                                    and v["expr"][-1] == egress.DROP for v in rules))

    def test_crashed_daemon_restarts_behind_gate_then_verified_path_opens(self):
        fetcher = Fetcher(self.assert_closed_bootstrap)
        self.assertEqual(tor.recovery_step(self.r, self.service, fetcher), "recovered")
        self.assertTrue(self.r.status()["ready"])
        self.assertEqual(self.service.starts, 1)
        self.assertEqual(fetcher.calls, 1)
        self.assertEqual(tor.recovery_step(self.r, self.service, fetcher), "active")
        self.assertEqual(self.service.starts, 1)
        self.assertEqual(fetcher.calls, 1)

    def test_busy_first_lock_defers_internal_worker_without_side_effects(self):
        before = copy.deepcopy(self.network.fw), self.r.state()
        self.network.calls.clear()
        fetcher = Fetcher()
        with self.network.lock(), patch.object(tor.os, "geteuid", return_value=0):
            self.assertEqual(tor.main(["--recovery-worker"], self.service, self.r, fetcher), 0)
        self.assertEqual(before, (self.network.fw, self.r.state()))
        self.assertEqual(self.network.calls, [])
        self.assertEqual(self.service.starts, 0)
        self.assertEqual(fetcher.calls, 0)
        self.assertFalse(self.r.held)

    def test_busy_after_probe_defers_without_opening_the_guard(self):
        with ExitStack() as locks, patch.object(tor.os, "geteuid", return_value=0):
            fetcher = Fetcher(lambda: locks.enter_context(self.network.lock()))
            self.assertEqual(tor.main(["--recovery-worker"], self.service, self.r, fetcher), 0)
            self.assert_closed_bootstrap()
        self.assertEqual(self.service.starts, 1)
        self.assertEqual(fetcher.calls, 1)
        self.assertEqual(tor.recovery_step(self.r, self.service, Fetcher()), "recovered")

    def test_worker_does_not_skip_an_untyped_lock_error(self):
        before = copy.deepcopy(self.network.fw), self.r.state()
        @contextmanager
        def invalid_lock():
            raise fixture.share.Error("Another sharing operation is running.")
            yield
        with patch.object(self.network, "lock", invalid_lock), patch.object(tor.os, "geteuid", return_value=0):
            with self.assertRaises(egress.Error) as caught:
                tor.main(["--recovery-worker"], self.service, self.r, Fetcher())
        self.assertIs(type(caught.exception), egress.Error)
        self.assertEqual(before, (self.network.fw, self.r.state()))
        self.assertEqual(self.service.starts, 0)

    def test_worker_error_after_entry_still_blocks_and_fails(self):
        with patch.object(self.service, "definition", side_effect=fixture.share.Busy("Failed after entry.")), \
                patch.object(tor.os, "geteuid", return_value=0):
            with self.assertRaises(egress.Error) as caught:
                tor.main(["--recovery-worker"], self.service, self.r, Fetcher())
        self.assertIs(type(caught.exception), egress.Error)
        self.assertEqual(self.r.state()["phase"], "blocked")
        egress.check_objects(self.network.fw, self.r.state())
        self.assertEqual(self.service.starts, 0)

    def test_public_on_and_off_do_not_silently_skip_a_busy_lock(self):
        before = copy.deepcopy(self.network.fw), self.r.state()
        for action in ("--on", "--off"):
            with self.subTest(action=action), self.network.lock(), patch.object(tor.os, "geteuid", return_value=0):
                with self.assertRaises(egress.Busy):
                    tor.main([action], self.service, self.r, Fetcher())
        self.assertEqual(before, (self.network.fw, self.r.state()))

    def test_failed_https_retries_without_restart_or_direct_fallback(self):
        def fail():
            self.assert_closed_bootstrap()
            raise tor.Error("HTTPS temporarily unavailable")
        for _ in range(3):
            with self.assertRaisesRegex(tor.Error, "temporarily"):
                tor.recovery_step(self.r, self.service, Fetcher(fail))
            self.assert_closed_bootstrap()
        self.assertEqual(self.service.starts, 1)
        self.assertEqual(tor.recovery_step(self.r, self.service, Fetcher()), "recovered")

    def test_non_tor_response_never_opens_gate(self):
        with self.assertRaisesRegex(tor.Error, "not verified"):
            tor.recovery_step(self.r, self.service, Fetcher(tor_request=False))
        self.assert_closed_bootstrap()

    def test_off_during_probe_cannot_be_undone_by_late_success(self):
        def off():
            with self.r.operation("tor") as op:
                self.service.enabled = False
                op.block()
                self.service.invocation = None
                self.network.privacy_active = False
                op.deactivate()
        self.assertEqual(tor.recovery_step(self.r, self.service, Fetcher(off)), "superseded")
        self.assertIsNone(self.r.state())
        self.assertFalse(egress.relevant(self.network.fw))
        self.assertEqual(tor.recovery_step(self.r, self.service, Fetcher()), "off")
        self.assertEqual(self.service.starts, 1)

    def test_stop_and_new_start_during_probe_cannot_reuse_old_success(self):
        def newer():
            with self.r.operation("tor") as op:
                op.block()
                self.network.privacy_active = False
                op.deactivate()
                op.activate(60001, 19040, 19053)
                op.recover()
                self.service.start()
        self.assertEqual(tor.recovery_step(self.r, self.service, Fetcher(newer)), "superseded")
        self.assert_closed_bootstrap()
        self.assertEqual(self.service.starts, 2)

    def test_service_change_during_probe_requires_another_verification(self):
        def changed():
            self.service.invocation = ("f" * 32, 999)
        self.assertEqual(tor.recovery_step(self.r, self.service, Fetcher(changed)), "superseded")
        self.assert_closed_bootstrap()

    def test_timer_disabled_during_probe_keeps_gate_closed(self):
        def disabled():
            self.service.enabled = False
        self.assertEqual(tor.recovery_step(self.r, self.service, Fetcher(disabled)), "superseded")
        self.assert_closed_bootstrap()

    def test_no_matching_state_or_timer_never_starts_daemon(self):
        self.service.enabled = False
        before = copy.deepcopy(self.network.fw)
        self.assertEqual(tor.recovery_step(self.r, self.service, Fetcher()), "off")
        self.assertEqual(before, self.network.fw)
        self.assertEqual(self.service.starts, 0)

    def test_foreign_firewall_cannot_be_adopted_by_recovery(self):
        self.network.fw["nftables"].append({"rule": egress.rule("egress", [egress.ACCEPT], "foreign")})
        before = copy.deepcopy(self.network.fw)
        with self.assertRaises(egress.Error):
            tor.recovery_step(self.r, self.service, Fetcher())
        self.assertEqual(before, self.network.fw)
        self.assertEqual(self.service.starts, 0)

    def test_lost_uplink_keeps_blocked_until_same_verified_uplink_returns(self):
        with patch.object(self.network, "healthy", return_value=False), self.assertRaises(tor.Error):
            tor.recovery_step(self.r, self.service, Fetcher())
        self.assertEqual(self.r.state()["phase"], "blocked")
        self.assertEqual(self.service.starts, 0)
        self.assertEqual(tor.recovery_step(self.r, self.service, Fetcher()), "recovered")

    def test_ready_write_failure_rolls_back_closed_firewall(self):
        with self.r.operation("tor") as op:
            op.recover()
        original = self.r.save
        def fail_active(new, old):
            if new["phase"] == "active":
                raise OSError("simulated storage failure")
            return original(new, old)
        with patch.object(self.r, "save", side_effect=fail_active), self.assertRaises(OSError):
            with self.r.operation("tor") as op:
                op.ready()
        self.assertEqual(self.r.state()["phase"], "blocked")
        egress.check_objects(self.network.fw, self.r.state())

    def test_guard_and_share_preserve_local_control_admissions(self):
        self.assertEqual(tor.recovery_step(self.r, self.service, Fetcher()), "recovered")
        with self.r.operation("tor") as op:
            op.recover()
        rules = [v for k, v in egress.objects(self.r.state()) if k == "rule" and v["chain"] == "egress"]
        local = [r for r in rules if r["comment"].startswith("auto-privacy:local-")
                 and not r["comment"].startswith("auto-privacy:local-dnat")]
        self.assertEqual([r["expr"] for r in local], egress.local_exceptions())
        self.assertTrue(self.network.healthy(self.network.load()))


class RecoveryUnitTests(unittest.TestCase):
    def test_timer_is_opt_in_and_daemon_restart_cannot_bypass_probe(self):
        folder = ROOT / "pi4/components/tor-control/files"
        unit = (folder / tor.SERVICE).read_text()
        recovery = (folder / tor.RECOVERY_SERVICE).read_text()
        timer = (ROOT / "common/components/tor-control/files" / tor.RECOVERY_TIMER).read_text()
        self.assertIn("Restart=no", unit)
        self.assertIn("RuntimeDirectoryPreserve=yes", unit)
        self.assertIn("--recovery-worker", recovery)
        self.assertIn("Type=oneshot", recovery)
        for content in (unit, recovery, timer):
            self.assertNotIn("[Install]", content)
            self.assertNotIn("WantedBy=", content)

    def test_worker_is_private_root_only_entrypoint(self):
        with patch.object(tor.os, "geteuid", return_value=1000), patch.object(tor, "load_egress") as loader:
            with self.assertRaisesRegex(tor.Error, "root"):
                tor.main(["--recovery-worker"])
            loader.assert_not_called()
        for extra in (["--on"], ["--off"], ["--rotate-every", "30s"], ["--rotation-worker", "30"]):
            with self.assertRaises(tor.Error):
                tor.main(["--recovery-worker", *extra])

    def test_restart_identity_uses_invocation_not_only_reused_pid(self):
        raw = "ActiveState=active\nMainPID=777\nInvocationID=" + "a" * 32 + "\n"
        with patch.object(tor.Platform, "run", return_value=raw):
            self.assertEqual(tor.Platform().generation(), ("a" * 32, 777))
        with patch.object(tor.Platform, "run", return_value=raw.replace("a" * 32, "")):
            with self.assertRaisesRegex(tor.Error, "invocation"):
                tor.Platform().generation()


if __name__ == "__main__":
    unittest.main()
