"""Focused refresh regressions. Fixtures are not native TCP/leak evidence."""
import copy
import importlib.util
import io
import json
import os
import re
from pathlib import Path
import tempfile
import types
import unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


base = load("watch_share_fixture", HERE / "test_share_control.py")
share = base.share
egress = load("watch_egress", ROOT / "pi4/python/egress.py")


class Fixture(base.Fixture):
    def __init__(self, root):
        super().__init__(root)
        self.loaded_unit = self.running_unit = ""

    def command(self, args, input_text=None, accepted=(0,)):
        if args[:2] == ["/usr/bin/systemctl", "show"] and args[2] in (share.WATCH_SERVICE, share.WATCH_TIMER):
            self.calls.append((args[:], input_text))
            return "FragmentPath=/etc/systemd/system/" + args[2] + "\nDropInPaths=" + getattr(self, "watch_override", "") + "\nNeedDaemonReload=no\n"
        if args[:2] in (["/usr/bin/systemctl", "start"], ["/usr/bin/systemctl", "stop"]) and args[2] == share.WATCH_TIMER:
            self.calls.append((args[:], input_text))
            self.watching = args[1] == "start"
            return ""
        if args[0].endswith("ss") and self.active:
            self.calls.append((args[:], input_text))
            addresses = set()
            for part in re.findall(r"--listen-address=([^ ]+)", self.running_unit):
                addresses.update(part.split(","))
            if "--interface=ctrl0" in self.running_unit:
                addresses.add(self.selection["control6"]["linklocal"] + "%ctrl0")
            return "".join('LISTEN 0 32 ' + ('[' + a + ']' if ':' in a else a) + ':1053 *:* users:(("dnsmasq",pid=123,fd=4))\n' for a in addresses)
        if args[:2] == ["/usr/bin/systemctl", "daemon-reload"]:
            self.loaded_unit = self.read(share.UNIT) if self.path(share.UNIT).exists() else ""
        if args[:2] == ["/usr/bin/systemctl", "start"] and args[2] == share.SERVICE:
            self.running_unit = self.loaded_unit
        if args == ["/usr/sbin/ip", "-j", "address", "show"]:
            rows = json.loads(super().command(args, input_text, accepted))
            if self.selection["ipv6"]:
                rows[1]["addr_info"] += [{"family": "inet6", "local": address, "prefixlen": 64}
                                         for address in self.selection["ipv6"]["addresses"]]
            return json.dumps(rows)
        if args[:3] == ["/usr/bin/systemctl", "show", "automations-tor.service"]:
            self.calls.append((args[:], input_text))
            return "MainPID=" + ("777" if self.tor_active else "0") + "\nActiveState=" + ("active" if self.tor_active else "inactive") + "\n"
        if args[:3] == ["/usr/sbin/ip", "-4", "route"] or args[:3] == ["/usr/sbin/ip", "-6", "route"]:
            routes = self.routes6 if args[1] == "-6" else self.routes
            if args[3] == "replace":
                if self.fail and self.fail(args):
                    self.fail = None
                    raise share.Error("Injected route replacement failure")
                result = super().command(args[:3] + ["add"] + args[4:], input_text, accepted)
                self.calls[-1] = (args[:], input_text)
                row = routes.pop()
                routes[:] = [x for x in routes if (x.get("type", "unicast"), x["dst"], x["metric"]) !=
                             (row.get("type", "unicast"), row["dst"], row["metric"])]
                routes.append(row)
                return result
            if args[3] == "del":
                self.calls.append((args[:], input_text))
                metric = int(args[args.index("metric") + 1])
                routes[:] = [x for x in routes if not (x["dst"] == args[4] and x["metric"] == metric)]
                return ""
        if args[:2] == ["/usr/bin/systemctl", "restart"]:
            self.calls.append((args[:], input_text))
            self.active = True
            self.running_unit = self.loaded_unit
            return ""
        return super().command(args, input_text, accepted)


class WatchTests(unittest.TestCase):
    def make(self, tor=False, ipv6=False):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        p = Fixture(Path(temporary.name))
        p.tor_active = tor
        if ipv6:
            p.selection["ipv6"] = dict(addresses=["2001:db8:1::2"], address="2001:db8:1::2",
                                       network="2001:db8:1::/64", gateway="fe80::1")
            p.selection["dns"].append("2001:db8:1::1")
        helper = p.path("usr/local/libexec/automations-support/egress.py")
        helper.parent.mkdir(parents=True)
        helper.write_bytes((ROOT / "pi4/python/egress.py").read_bytes())
        helper.chmod(0o644)
        p.change("lan")
        runtime = egress.Runtime(share, p, lambda name: types.SimpleNamespace(pw_uid=60001))
        if tor:
            with runtime.operation("tor") as op:
                op.activate(60001, 19040, 19053)
                op.ready()
        p.calls.clear()
        return p, runtime

    def tick(self, p):
        with redirect_stdout(io.StringIO()):
            with p.lock():
                return p.watch_once()

    def refresh(self, p):
        self.assertEqual(self.tick(p), "pending")
        self.assertEqual(self.tick(p), "refreshed")

    def assert_no_disruption(self, p):
        for args, data in p.calls:
            self.assertFalse(args[0].endswith("conntrack"), args)
            self.assertFalse(args[:2] == ["/usr/bin/systemctl", "stop"], args)
            self.assertFalse(args[:2] == ["/usr/bin/systemctl", "restart"], args)
            self.assertFalse(args[:2] == ["/usr/bin/systemctl", "start"], args)
            self.assertFalse("flush" in args, args)
            if args[0].endswith("nft") and data:
                self.assertNotIn(share.GATE, data)
        self.assertFalse(p.path(share.REFRESH_STATE).exists())

    def assert_consistent(self, p, runtime, tor=False):
        state = p.load()
        self.assertTrue(p.healthy(state))
        self.assertEqual(state["selection"], p.selection)
        self.assertEqual(p.read(share.DNS_SERVERS), share.servers_text(p.selection, tor=tor))
        if tor:
            self.assertEqual(runtime.state()["selection"], p.selection)
            self.assertEqual(runtime.state()["phase"], "active")
            egress.check_objects(p.fw, runtime.state())
        self.assertFalse(p.gate_present())

    def test_steady_ticks_do_not_reconfigure_or_signal(self):
        for tor in (False, True):
            p, r = self.make(tor)
            before = copy.deepcopy(p.fw)
            for _ in range(4):
                self.assertEqual(self.tick(p), "active")
            self.assertEqual(before, p.fw)
            self.assert_no_disruption(p)
            self.assertFalse(any(args[:2] == ["/usr/bin/systemctl", "kill"] for args, _ in p.calls))

    def test_dns_add_remove_replace_with_and_without_tor(self):
        for tor in (False, True):
            with self.subTest(tor=tor):
                p, r = self.make(tor, ipv6=True)
                for servers in (["192.168.1.1", "2001:db8:1::99"], ["192.168.1.1"], ["1.1.1.1"]):
                    p.selection["dns"] = servers
                    p.calls.clear()
                    self.refresh(p)
                    self.assert_consistent(p, r, tor)
                    self.assert_no_disruption(p)
                    self.assertFalse(any(args[0].endswith("ip") and ("replace" in args or "del" in args or "add" in args)
                                         for args, _ in p.calls))

    def test_transient_dns_and_invalid_metadata_leave_working_state(self):
        p, r = self.make(True)
        before = copy.deepcopy(p.fw), p.load(), r.state(), p.read(share.DNS_SERVERS)
        p.selection["dns"] = ["8.8.8.8"]
        self.assertEqual(self.tick(p), "pending")
        p.selection["dns"] = copy.deepcopy(base.SELECTION["dns"])
        self.assertEqual(self.tick(p), "active")
        p.selection["dns"] = []
        self.assertEqual(self.tick(p), "unavailable")
        self.assertEqual(before, (p.fw, p.load(), r.state(), p.read(share.DNS_SERVERS)))
        self.assert_no_disruption(p)

    def test_new_address_and_gateway_preserve_privacy_phase_and_owned_policy(self):
        for tor in (False, True):
            p, r = self.make(tor)
            p.selection.update(address="192.168.2.3", network="192.168.2.0/24", gateway="192.168.2.1", dns=["192.168.2.1"])
            self.refresh(p)
            self.assert_consistent(p, r, tor)
            self.assert_no_disruption(p)

    def test_ipv6_prefix_change_and_capability_loss_return_then_off(self):
        for tor in (False, True):
            p, r = self.make(tor, ipv6=True)
            owned = p.load()["owned_addresses"]
            p.selection["ipv6"] = dict(addresses=["2001:db8:2::2"], address="2001:db8:2::2",
                                        network="2001:db8:2::/64", gateway="fe80::2")
            p.selection["dns"] = ["192.168.1.1", "2001:db8:2::1"]
            self.refresh(p)
            self.assert_consistent(p, r, tor)
            self.assert_no_disruption(p)
            restored = copy.deepcopy(p.selection)
            p.selection["ipv6"] = None
            p.selection["dns"] = ["192.168.1.1"]
            self.refresh(p)
            self.assert_consistent(p, r, tor)
            self.assertEqual(set(p.load()["owned_addresses"]), set(owned))
            p.selection = restored
            self.refresh(p)
            self.assert_consistent(p, r, tor)
            if tor:
                with r.operation("tor") as op:
                    op.block()
                    p.tor_active = False
                    op.deactivate()
            p.change("off")
            self.assertEqual(p.addresses6, [])
            self.assertTrue(all(value == "0" for value in p.ipv6_settings().values()))

    def test_ipv6_becomes_available_after_ipv4_only_start(self):
        p, r = self.make(True)
        p.selection["ipv6"] = dict(addresses=["2001:db8:2::2"], address="2001:db8:2::2",
                                    network="2001:db8:2::/64", gateway="fe80::1")
        self.refresh(p)
        self.assert_consistent(p, r, True)
        self.assertEqual(len(p.load()["owned_addresses"]), 2)

    def test_missing_preferred_source_after_reconnect_is_repaired_without_flush(self):
        p, r = self.make(True)
        for row in p.routes:
            if row.get("dev") == "eth0":
                row.pop("prefsrc", None)
        self.refresh(p)
        self.assert_consistent(p, r, True)
        self.assert_no_disruption(p)

    def test_unknown_rule_or_unit_refused_without_network_mutation(self):
        for kind in ("firewall", "route", "unit", "servers"):
            with self.subTest(kind=kind):
                p, r = self.make(True)
                if kind == "firewall":
                    value = copy.deepcopy(p.fw["nftables"][-1])
                    value["rule"]["comment"] = "foreign-rule"
                    p.fw["nftables"].append(value)
                elif kind == "route":
                    p.routes[1]["prefsrc"] = "192.168.1.99"
                else:
                    p.path(share.UNIT if kind == "unit" else share.DNS_SERVERS).write_text("foreign\n")
                p.selection["dns"] = ["8.8.8.8"]
                before = copy.deepcopy(p.fw), copy.deepcopy(p.routes), p.load(), r.state()
                self.assertEqual(self.tick(p), "pending")
                self.assertEqual(self.tick(p), "failed")
                self.assertEqual(before, (p.fw, p.routes, p.load(), r.state()))
                self.assert_no_disruption(p)

    def test_busy_tick_and_off_do_not_reenable(self):
        p, r = self.make()
        with p.lock(), patch.object(p, "watch_definition", return_value=True):
            self.assertEqual(share.main(["--internal-watch"], p, 0), 0)
        p.change("off")
        self.assertEqual(self.tick(p), "off")
        self.assertIsNone(p.load())

    def test_dns_failure_rolls_back_and_retry_succeeds_without_blocking_tor(self):
        for operation in ("nft-check", "nft-apply", "hup", "share-save", "privacy-save"):
            with self.subTest(operation=operation):
                p, r = self.make(True)
                old, privacy = p.load(), r.state()
                p.selection["dns"] = ["8.8.8.8"]
                original = p.run
                fired = []
                def fail(args, text=None, accepted=(0,)):
                    match = ((operation == "nft-check" and "--check" in args) or
                             (operation == "nft-apply" and args[:3] == ["/usr/sbin/nft", "--json", "-f"]) or
                             (operation == "hup" and "--signal=HUP" in args))
                    if match and not fired:
                        fired.append(True)
                        raise share.Error("Injected update failure")
                    return original(args, text, accepted)
                p.run = fail
                original_write = p.write
                def fail_write(relative, text, expected=None, mode=0o600):
                    if operation == "share-save" and relative == share.STATE and not fired:
                        fired.append(True)
                        raise OSError("Injected state failure")
                    return original_write(relative, text, expected, mode)
                p.write = fail_write
                real_replace = os.replace
                def fail_replace(source, destination):
                    if operation == "privacy-save" and str(destination).endswith("automations-anonymity/state.json") and not fired:
                        fired.append(True)
                        raise OSError("Injected privacy publication failure")
                    return real_replace(source, destination)
                with patch("os.replace", side_effect=fail_replace):
                    self.assertEqual(self.tick(p), "pending")
                    self.assertEqual(self.tick(p), "failed")
                self.assertTrue(fired)
                self.assertEqual(p.load(), old)
                self.assertEqual(r.state(), privacy)
                egress.check_objects(p.fw, privacy)
                self.assert_no_disruption(p)
                self.refresh(p)
                self.assert_consistent(p, r, True)

    def test_unprivileged_internal_watch_is_clean_error(self):
        with redirect_stderr(io.StringIO()) as output:
            self.assertEqual(share.main(["--internal-watch"], uid=1000), 1)
        self.assertNotIn("Traceback", output.getvalue())

    def test_interrupted_mutations_resume_on_the_next_serialized_operation(self):
        # Abrupt process death has no Python cleanup. Once the chosen boundary
        # is reached, fail every subsequent access too, including rollback.
        class PowerLoss(BaseException):
            pass
        for point in ("routes", "servers", "firewall", "hup", "share", "privacy"):
            with self.subTest(point=point):
                tor = point != "servers"
                p, r = self.make(tor)
                p.selection.update(address="192.168.2.3", network="192.168.2.0/24", gateway="192.168.2.1", dns=["192.168.2.1"])
                fired = []
                run, write, replace = p.run, p.write, os.replace
                def crash_run(args, text=None, accepted=(0,)):
                    if fired:
                        raise PowerLoss()
                    result = run(args, text, accepted)
                    if ((point == "routes" and "replace" in args) or
                        (point == "firewall" and args[:3] == ["/usr/sbin/nft", "--json", "-f"]) or
                        (point == "hup" and "--signal=HUP" in args)):
                        fired.append(True)
                        raise PowerLoss()
                    return result
                def crash_write(relative, text, expected=None, mode=0o600):
                    if fired:
                        raise PowerLoss()
                    result = write(relative, text, expected, mode)
                    if (point == "servers" and relative == share.DNS_SERVERS or
                        point == "share" and relative == share.STATE):
                        fired.append(True)
                        raise PowerLoss()
                    return result
                def crash_replace(source, destination):
                    if fired:
                        raise PowerLoss()
                    result = replace(source, destination)
                    if point == "privacy" and str(destination).endswith("automations-anonymity/state.json"):
                        fired.append(True)
                        raise PowerLoss()
                    return result
                p.run, p.write = crash_run, crash_write
                with patch("os.replace", side_effect=crash_replace), self.assertRaises(PowerLoss):
                    with p.lock():
                        p.refresh_support().refresh(p, p.load(), p.selection)
                self.assertTrue(fired)
                self.assertTrue(p.path(share.REFRESH_STATE).exists())
                p.run, p.write = run, write
                self.assertEqual(self.tick(p), "active")
                self.assert_consistent(p, r, tor)
                self.assert_no_disruption(p)

    def test_unfinished_intent_does_not_adopt_foreign_objects(self):
        p, r = self.make(True)
        p.selection["dns"] = ["8.8.8.8"]
        original = p.run
        def fail(args, text=None, accepted=(0,)):
            if "--signal=HUP" in args:
                raise share.Error("Reload and rollback both unavailable")
            return original(args, text, accepted)
        p.run = fail
        self.assertEqual(self.tick(p), "pending")
        self.assertEqual(self.tick(p), "failed")
        self.assertTrue(p.path(share.REFRESH_STATE).exists())
        p.run = original
        p.routes[1]["prefsrc"] = "192.168.1.99"
        before = copy.deepcopy(p.fw), copy.deepcopy(p.routes), p.load(), r.state()
        with self.assertRaises(share.Error):
            with p.lock():
                self.fail("Unsafe intent must not enter the CLI operation")
        self.assertEqual(before, (p.fw, p.routes, p.load(), r.state()))

    def test_pending_change_does_not_change_interface_or_client_sources(self):
        for field, value in (("interface", "wlan0"), ("sources", [])):
            p, r = self.make(True)
            p.selection[field] = value
            p.select = lambda mode, interface=None: copy.deepcopy(p.selection)
            before = copy.deepcopy(p.fw), p.load(), r.state()
            self.assertIn(self.tick(p), ("unavailable", "unrecognized"))
            self.assertEqual(before, (p.fw, p.load(), r.state()))
            self.assert_no_disruption(p)

    def test_another_address_change_during_an_interrupted_refresh_does_not_stick(self):
        p, r = self.make(True)
        p.selection.update(address="192.168.2.3", network="192.168.2.0/24", gateway="192.168.2.1", dns=["192.168.2.1"])
        run = p.run
        failed = []
        def interrupted(args, text=None, accepted=(0,)):
            if "replace" in args and not failed:
                failed.append(True)
                raise OSError("Interrupted route update")
            return run(args, text, accepted)
        p.run = interrupted
        self.assertEqual(self.tick(p), "pending")
        self.assertEqual(self.tick(p), "failed")
        self.assertTrue(p.path(share.REFRESH_STATE).exists())
        p.run = run
        p.selection.update(address="192.168.3.4", network="192.168.3.0/24", gateway="192.168.3.1", dns=["192.168.3.1"])
        self.assertEqual(self.tick(p), "pending")
        self.assertEqual(self.tick(p), "refreshed")
        self.assert_consistent(p, r, True)
        self.assert_no_disruption(p)

    def test_capability_recovery_reloads_a_published_but_not_loaded_unit(self):
        class PowerLoss(BaseException):
            pass
        for ipv6 in (False, True):
            for point in ("unit", "before-reload", "after-reload"):
                with self.subTest(ipv6=ipv6, point=point):
                    p, r = self.make(True, ipv6)
                    p.selection["ipv6"] = (None if ipv6 else dict(addresses=["2001:db8:2::2"], address="2001:db8:2::2",
                                                                 network="2001:db8:2::/64", gateway="fe80::1"))
                    if ipv6:
                        p.selection["dns"] = ["192.168.1.1"]
                    run, write = p.run, p.write
                    dead = []
                    def fault_run(args, text=None, accepted=(0,)):
                        if dead or point == "before-reload" and args[:2] == ["/usr/bin/systemctl", "daemon-reload"]:
                            dead.append(True)
                            raise PowerLoss()
                        result = run(args, text, accepted)
                        if point == "after-reload" and args[:2] == ["/usr/bin/systemctl", "daemon-reload"]:
                            dead.append(True)
                            raise PowerLoss()
                        return result
                    def fault_write(relative, text, expected=None, mode=0o600):
                        result = write(relative, text, expected, mode)
                        if point == "unit" and relative == share.UNIT:
                            dead.append(True)
                            raise PowerLoss()
                        return result
                    p.run, p.write = fault_run, fault_write
                    with self.assertRaises(PowerLoss):
                        with p.lock():
                            p.refresh_support().refresh(p, p.load(), p.selection)
                    p.run, p.write = run, write
                    self.assertTrue(dead)
                    self.assertEqual(self.tick(p), "active")
                    self.assert_consistent(p, r, True)
                    self.assertEqual(p.loaded_unit, share.unit_text(p.selection))
                    self.assertEqual(p.running_unit, p.loaded_unit)

    def test_installed_timer_lifecycle_and_overrides_are_verified(self):
        p, r = self.make()
        for name, text in ((share.WATCH_SERVICE, share.WATCH_SERVICE_TEXT), (share.WATCH_TIMER, share.WATCH_TIMER_TEXT)):
            packaged = ROOT / "pi4/components/share-control/files" / name
            self.assertEqual(packaged.read_text(), text)
            path = p.path("etc/systemd/system/" + name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
            path.chmod(0o644)
        self.assertIn("already active", p.change("lan"))
        self.assertTrue(p.watching)
        before = copy.deepcopy(p.fw)
        p.watch_override = "/etc/systemd/system/unrecognized.conf"
        with self.assertRaises(share.Error):
            p.watch_start()
        self.assertEqual(before, p.fw)
        p.watch_override = ""
        p.change("off")
        self.assertFalse(p.watching)
        self.assertEqual(self.tick(p), "off")

    def test_failed_update_returns_failed_worker_exit(self):
        p, r = self.make()
        with patch.object(p, "watch_definition", return_value=True), patch.object(p, "watch_once", return_value="failed"):
            self.assertEqual(share.main(["--internal-watch"], p, 0), 1)

    def test_unsafe_watch_or_intent_link_never_changes_its_target_or_network(self):
        for relative in (share.WATCH_STATE, share.REFRESH_STATE):
            p, r = self.make(True)
            target = p.path("foreign.json")
            target.write_text("foreign-data\n")
            p.path(relative).symlink_to(target)
            before = copy.deepcopy(p.fw), p.load(), r.state()
            with self.assertRaises(share.Error):
                if relative == share.WATCH_STATE:
                    p.watch_record()
                else:
                    with p.lock():
                        self.fail("Untrusted intent entered the operation")
            self.assertEqual(before, (p.fw, p.load(), r.state()))
            self.assertEqual(target.read_text(), "foreign-data\n")

    def test_refresh_preserves_all_client_source_combinations_with_tor(self):
        for sources in ([], ["ctrl0"], ["autoap0"], ["ctrl0", "autoap0"]):
            with self.subTest(sources=sources):
                p, r = self.make()
                p.change("off")
                for version in (4, 6):
                    path = p.path("proc/sys/net/ipv" + str(version) + "/conf/autoap0/forwarding")
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("0\n")
                p.guest_role = lambda: copy.deepcopy(share.GUEST)
                p.change("lan", sources=sources)
                with r.operation("tor") as op:
                    op.activate(60001, 19040, 19053)
                    op.ready()
                p.calls.clear()
                p.selection["dns"] = ["8.8.8.8"]
                self.refresh(p)
                selected = p.load()["selection"]
                self.assertEqual(selected["sources"], sources)
                self.assertEqual(selected["guest"], share.GUEST)
                self.assertEqual(selected, r.state()["selection"])
                self.assertTrue(p.healthy(p.load()))
                egress.check_objects(p.fw, r.state())
                self.assert_no_disruption(p)


if __name__ == "__main__":
    unittest.main()
