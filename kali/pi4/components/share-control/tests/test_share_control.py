"""Offline fixtures only: no real firewall, interface, service or Pi access."""
from contextlib import redirect_stdout, redirect_stderr
import copy
import importlib.util
import io
import json
import os
import subprocess
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
SPEC = importlib.util.spec_from_file_location("auto_share", ROOT / "pi4/python/auto_share.py")
share = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(share)
SELECTION = dict(mode="lan", interface="eth0", address="192.168.1.2", network="192.168.1.0/24",
                 gateway="192.168.1.1", dns=["192.168.1.1", "1.1.1.1"], ipv6=None,
                 control6=dict(network="fd12:3456:789a:1::/64", address="fd12:3456:789a:1::1", linklocal="fe80::789a"))


def baseline(ssh=True):
    objects = [{"table": {"family": "inet", "name": "pi4"}}]
    objects += [{"chain": {"family": "inet", "table": "pi4", "name": name, "type": "filter", "hook": name,
                           "prio": 0, "policy": policy}} for name, policy in (("input", "drop"), ("forward", "drop"), ("output", "accept"))]
    objects += [{"rule": {"family": "inet", "table": "pi4", "chain": "input", "expr": copy.deepcopy(expr), "handle": n + 10}}
                for n, expr in enumerate(share.BASE_INPUT + ([share.SSH_INPUT] if ssh else []))]
    return {"nftables": objects}


class Fixture(share.Platform):
    def __init__(self, root):
        super().__init__(root, self.command, os.getuid())
        self.calls, self.rules, self.routes = [], [], []
        self.rules6, self.routes6, self.addresses6 = [], [], []
        self.probe_count = 0
        self.fw = baseline()
        self.active = False
        self.fail = None
        self.selection = copy.deepcopy(SELECTION)
        self.extra_interfaces = []
        self.foreign_rules = []
        self.handle = 100
        for name, content in {**share.CONFIGS, "etc/os-release": "ID=kali\n", "etc/machine-id": "1234567890abcdef1234567890abcdef\n",
                              "proc/123/status": "Uid:\t65534\t65534\t65534\t65534\n",
                              "proc/sys/net/ipv4/conf/ctrl0/forwarding": "0\n",
                              "proc/sys/net/ipv4/conf/eth0/forwarding": "0\n",
                              "proc/sys/net/ipv4/conf/wlan0/forwarding": "0\n"}.items():
            path = self.path(name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        self.path("run/systemd/system").mkdir(parents=True)
        for name in ("all", "default", "lo", "ctrl0", "eth0", "wlan0"):
            for prop in ("forwarding", "disable_ipv6"):
                path = self.path("proc/sys/net/ipv6/conf/" + name + "/" + prop)
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("0\n")

    def control_ipv6(self):
        return copy.deepcopy(SELECTION["control6"])

    def discover_ipv6(self, name):
        return copy.deepcopy(self.selection["ipv6"]), [x for x in self.selection["dns"] if ":" in x]

    def probe_ipv6(self, selected):
        self.probe_count += 1
        return self.select(selected["mode"], selected["interface"])

    def withdraw_ra(self, selected):
        self.calls.append((["fixture-withdraw-ra"], None))

    def write_ipv6_forwarding(self, name, value):
        if name == "all":
            for path in self.path("proc/sys/net/ipv6/conf").glob("*/forwarding"):
                if path.parent.name != "default": path.write_text(value + "\n")
        super().write_ipv6_forwarding(name, value)

    def command(self, args, input_text=None, accepted=(0,)):
        self.calls.append((args[:], input_text))
        if self.fail and self.fail(args):
            self.fail = None
            raise share.Error("Simulated system command failure.")
        if args[0].endswith("ss"):
            if self.active:
                import re
                addresses = set()
                for part in re.findall(r"--listen-address=([^ ]+)", self.read(share.UNIT)):
                    addresses.update(part.split(","))
                if "--interface=ctrl0" in self.read(share.UNIT):
                    addresses.add(self.selection["control6"]["linklocal"] + "%ctrl0")
                return "".join('LISTEN 0 32 ' + ('[' + a + ']' if ':' in a else a) + ':1053 *:* users:(("dnsmasq",pid=123,fd=4))\n' for a in addresses)
            return ""
        if args[0].endswith("dnsmasq") or args[0].endswith("conntrack"):
            return ""
        if args[0].endswith("nmcli"):
            return "100 (connected)" if "GENERAL.STATE" in args else "\n".join(x for x in self.selection["dns"] if ":" not in x)
        if args[0].endswith("systemctl"):
            if args[1] == "show":
                exists = self.path(share.UNIT).exists()
                return ("LoadState=" + ("loaded" if exists else "not-found") + "\nActiveState=" +
                        ("active" if self.active else "inactive") + "\nMainPID=" + ("123" if self.active else "0") +
                        "\nFragmentPath=" + ("/" + share.UNIT if exists else "") + "\nDropInPaths=\n")
            if args[1] == "start": self.active = True
            if args[1] == "stop": self.active = False
            return ""
        if args[0].endswith("nft"):
            if "list" in args:
                return json.dumps(self.fw)
            if "--check" in args: return ""
            value = json.loads(input_text)
            objects = copy.deepcopy(self.fw["nftables"])
            for command in value["nftables"]:
                operation, data = next(iter(command.items()))
                kind, obj = next(iter(data.items()))
                if operation in ("add", "insert"):
                    obj = copy.deepcopy(obj)
                    self.handle += 1
                    obj["handle"] = self.handle
                    if operation == "insert":
                        index = next(i for i, x in enumerate(objects) if "rule" in x and x["rule"].get("chain") == obj["chain"])
                        objects.insert(index, {kind: obj})
                    else:
                        objects.append({kind: obj})
                elif operation == "delete" and kind == "rule":
                    objects = [x for x in objects if x.get("rule", {}).get("handle") != obj["handle"]]
                elif operation == "delete" and kind == "table":
                    objects = [x for x in objects if not any(v.get("table") == obj["name"] or
                               k == "table" and v.get("name") == obj["name"] for k, v in x.items())]
                elif operation == "flush":
                    objects = [x for x in objects if not (x.get("rule", {}).get("table") == obj["table"] and
                               x.get("rule", {}).get("chain") == obj["name"])]
                elif operation == "delete" and kind == "chain":
                    objects = [x for x in objects if not (x.get("chain", {}).get("table") == obj["table"] and
                               x.get("chain", {}).get("name") == obj["name"])]
                else:
                    raise AssertionError(command)
            self.fw = {"nftables": objects}
            return ""
        if args[0].endswith("ip"):
            if args == ["/usr/sbin/ip", "-j", "address", "show"]:
                return json.dumps([
                    {"ifname":"ctrl0", "flags":["UP"], "operstate":"UP", "addr_info":[
                        {"family":"inet", "local":share.ADDRESS, "prefixlen":24}] + self.addresses6},
                    {"ifname":self.selection["interface"], "flags":["UP", "LOWER_UP"], "operstate":"UP", "addr_info":[
                        {"family":"inet", "local":self.selection["address"], "prefixlen":24}]}])
            family = 6 if "-6" in args else 4
            routes = self.routes6 if family == 6 else self.routes
            rules = self.rules6 if family == 6 else self.rules
            if "address" in args and "-j" in args:
                if family == 6:
                    return json.dumps([{"ifname": "ctrl0", "flags": ["UP"], "addr_info": self.addresses6}])
                return json.dumps([{"ifname": "ctrl0", "flags": ["UP"], "addr_info": [
                    {"family": "inet", "local": share.ADDRESS, "prefixlen": 24}]}])
            if "address" in args:
                operation, address = args[3:5]
                plain,prefix = address.split("/")
                if operation == "add": self.addresses6.append({"family": "inet6", "local": plain, "prefixlen": int(prefix)})
                elif operation == "del": self.addresses6 = [x for x in self.addresses6 if x["local"] != plain]
                else: raise AssertionError(args)
                return ""
            if "-j" in args and "rule" in args:
                return json.dumps([{"priority": p, "src": "all", "table": t} for p,t in
                    ((0,"local"),(32766,"main"),(32767,"default"))] + rules + self.foreign_rules)
            if "-j" in args and "route" in args:
                if "default" in args:
                    selected = self.selection if family == 4 else self.selection["ipv6"]
                    return json.dumps([{"gateway": selected["gateway"], "dev": self.selection["interface"]}] if selected else [])
                return json.dumps(routes)
            if "route" in args and "add" in args:
                values = args[4:]
                row = {"table": share.TABLE, "protocol": "static", "dst": values[0], "metric": int(values[-1])}
                if values[0] == "unreachable": row.update(type="unreachable", dst="default")
                else:
                    row["dev"] = values[values.index("dev") + 1]
                    if "src" in values: row["prefsrc"] = values[values.index("src") + 1]
                    if "via" in values: row["gateway"] = values[values.index("via") + 1]
                    elif family == 4: row["scope"] = "link"
                routes.append(row)
                return ""
            if "rule" in args and "add" in args:
                priority = int(args[args.index("priority") + 1]);table = args[-1]
                row = {"priority": priority, "src":"all", "table": int(table) if table.isdigit() else table}
                if "iif" in args: row["iif"] = args[args.index("iif") + 1]
                if "to" in args: row["dst"] = args[args.index("to") + 1]
                rules.append(row)
                return ""
            if "rule" in args and "del" in args:
                priority = int(args[args.index("priority") + 1])
                rules[:] = [r for r in rules if r["priority"] != priority]
            elif "route" in args and "flush" in args: routes.clear()
            else: raise AssertionError(args)
            return ""
        raise AssertionError(args)

    def interfaces(self):
        selected = self.selection
        return [{"name": selected["interface"], "mode": selected["mode"], "up": True,
                 "operstate": "up",
                 "addresses": [{"local": selected["address"], "prefixlen": 24}]}] + self.extra_interfaces


class ShareTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.system = Fixture(Path(self.directory.name))

    def assert_off(self):
        share.firewall_check(self.system.fw)
        self.assertEqual(self.system.routes, [])
        self.assertEqual(self.system.rules, [])
        self.assertEqual(self.system.rules6, [])
        self.assertEqual(self.system.routes6, [])
        self.assertFalse(any(x.get("table", {}).get("name") == share.GATE for x in self.system.fw["nftables"]))
        self.assertFalse(self.system.active)
        self.assertFalse(self.system.path(share.STATE).exists())
        self.assertFalse(self.system.path(share.UNIT).exists())
        self.assertEqual(self.system.forwarding("ctrl0"), "0")

    def test_enable_and_off_preserve_core_files_and_ssh(self):
        original = copy.deepcopy(self.system.fw)
        files = {name: self.system.read(name) for name in share.CONFIGS}
        self.system.change("lan")
        self.assertTrue(self.system.healthy(self.system.load()))
        self.system.change("off")
        self.assert_off()
        self.assertEqual(original, self.system.fw)
        self.assertEqual(files, {name: self.system.read(name) for name in share.CONFIGS})
        self.assertFalse(any("ip_forward" in " ".join(cmd) for cmd, _ in self.system.calls))

    def test_idempotent_enable_does_not_restart_dns_or_duplicate_rules(self):
        self.system.change("lan")
        before = copy.deepcopy(self.system.fw)
        self.system.calls.clear()
        self.assertIn("already active", self.system.change("lan"))
        self.assertEqual(before, self.system.fw)
        self.assertFalse(any(cmd[1:2] == ["start"] for cmd, _ in self.system.calls))

    def test_off_is_idempotent_without_conntrack(self):
        self.system.change("off")
        self.system.change("off")
        self.assert_off()
        self.assertFalse(any(cmd[0].endswith("conntrack") for cmd, _ in self.system.calls))

    def test_switch_failure_restores_previous_working_selection(self):
        original = copy.deepcopy(SELECTION)
        replacement = dict(mode="wifi", interface="wlan0", address="192.168.2.2", network="192.168.2.0/24",
                           gateway="192.168.2.1", dns=["192.168.2.1"], ipv6=None, control6=copy.deepcopy(SELECTION["control6"]))
        self.system.select = lambda mode, interface=None: copy.deepcopy(original if mode == "lan" else replacement)
        self.system.change("lan")
        self.system.fail = lambda cmd: cmd[0].endswith("systemctl") and cmd[1] == "start"
        with self.assertRaises(share.Error): self.system.change("wifi")
        self.assertEqual(self.system.load()["selection"], original)
        self.assertTrue(self.system.healthy(self.system.load()))
        self.assertEqual(self.system.forwarding("wlan0"), "0")

    def test_successful_switch_has_only_new_uplink_and_off_restores_original_values(self):
        original = copy.deepcopy(SELECTION)
        replacement = dict(mode="wifi", interface="wlan0", address="192.168.2.2", network="192.168.2.0/24",
                           gateway="192.168.2.1", dns=["192.168.2.1"], ipv6=None, control6=copy.deepcopy(SELECTION["control6"]))
        self.system.select = lambda mode, interface=None: copy.deepcopy(original if mode == "lan" else replacement)
        self.system.change("lan")
        self.system.change("wifi")
        self.assertEqual(self.system.load()["selection"], replacement)
        share.firewall_check(self.system.fw, replacement)
        self.assertEqual(self.system.forwarding("eth0"), "0")
        self.system.change("off")
        self.assert_off()
        self.assertEqual(self.system.forwarding("wlan0"), "0")

    def test_dns_service_start_failure_rolls_back_routes_and_files(self):
        self.system.fail = lambda cmd: cmd[0].endswith("systemctl") and cmd[1] == "start"
        with self.assertRaises(share.Error): self.system.change("lan")
        self.assert_off()

    def test_missing_conntrack_dependency_blocks_activation(self):
        self.system.fail = lambda cmd: cmd[0].endswith("conntrack")
        with self.assertRaises(share.Error): self.system.change("lan")
        self.assert_off()

    def test_firewall_failure_rolls_back_started_dns(self):
        self.system.fail = lambda cmd: cmd[0].endswith("nft") and "-f" in cmd
        with self.assertRaises(share.Error): self.system.change("lan")
        self.assert_off()

    def test_route_failure_does_not_leave_unreachable_route(self):
        self.system.fail = lambda cmd: cmd[0].endswith("ip") and "route" in cmd and "via" in cmd
        with self.assertRaises(share.Error): self.system.change("lan")
        self.assert_off()

    def test_ctrl_c_after_first_forwarding_write_restores_both_interfaces(self):
        original = self.system.forwarding
        armed = True
        def interrupt(name, value=None):
            nonlocal armed
            result = original(name, value)
            if armed and name == "ctrl0" and value == "1":
                armed = False
                raise KeyboardInterrupt
            return result
        self.system.forwarding = interrupt
        with self.assertRaises(KeyboardInterrupt): self.system.change("lan")
        self.assert_off()
        self.assertEqual(original("eth0"), "0")

    def test_unknown_platform_rejected_before_any_mutation(self):
        self.system.path("etc/os-release").write_text("ID=debian\n")
        with self.assertRaises(share.Error): self.system.change("lan")
        self.assertEqual(self.system.calls, [])

    def test_changed_control_config_is_not_overwritten(self):
        path = self.system.path("etc/dnsmasq.d/pi4-control.conf")
        path.write_text(path.read_text() + "\nserver=9.9.9.9\n")
        before = path.read_text()
        with self.assertRaises(share.Error): self.system.change("lan")
        self.assertEqual(path.read_text(), before)
        self.assert_off()

    def test_multiple_matching_adapters_require_interface(self):
        self.system.extra_interfaces = [{"name": "eth1", "mode": "lan", "up": True, "addresses": []}]
        with self.assertRaisesRegex(share.Error, "Several"): self.system.change("lan")
        self.system.change("lan", "eth0")
        self.assertTrue(self.system.healthy(self.system.load()))

    def test_no_adapter_and_ctrl0_are_never_selected(self):
        for mode, interface in (("wifi", None), ("lan", "ctrl0")):
            with self.assertRaisesRegex(share.Error, "No matching"): self.system.change(mode, interface)

    def test_unknown_input_rule_refused_even_with_valid_comment(self):
        self.system.fw["nftables"].append({"rule": share.rule("pi4", "input", [share.ACCEPT], "auto-share:dns-udp-v1")})
        with self.assertRaises(share.Error): self.system.change("lan")
        self.assertFalse(self.system.path(share.STATE).exists())

    def test_reserved_policy_collision_refused(self):
        self.system.rules = [{"priority": share.PRIORITY, "table": "main", "src": "all"}]
        with self.assertRaises(share.Error): self.system.change("lan")
        self.assertFalse(self.system.path(share.STATE).exists())

    def test_custom_policy_rule_refused(self):
        self.system.foreign_rules = [{"priority": 100, "src": "all", "table": 100}]
        with self.assertRaises(share.Error): self.system.change("lan")

    def test_off_does_not_delete_modified_owned_rules(self):
        self.system.change("lan")
        target = next(x["rule"] for x in self.system.fw["nftables"] if x.get("rule", {}).get("comment") == "auto-share:out-ip-v2")
        target["expr"] = [share.ACCEPT]
        before = copy.deepcopy(self.system.fw)
        with self.assertRaises(share.Error): self.system.change("off")
        self.assertTrue(all(item in self.system.fw["nftables"] for item in before["nftables"]))
        self.assertTrue(self.system.path(share.STATE).exists())

    def test_failed_cleanup_retains_recoverable_state(self):
        self.system.change("lan")
        self.system.fail = lambda cmd: cmd[0].endswith("conntrack")
        with self.assertRaises(share.Error): self.system.change("off")
        self.assertTrue(self.system.path(share.STATE).exists())
        share.firewall_check(self.system.fw)
        self.system.change("off")
        self.assert_off()

    def test_external_unit_edit_is_not_removed(self):
        self.system.change("lan")
        path = self.system.path(share.UNIT)
        path.write_text("foreign edit\n")
        with self.assertRaises(share.Error): self.system.change("off")
        self.assertEqual(path.read_text(), "foreign edit\n")

    def test_runtime_state_symlink_is_refused(self):
        folder = self.system.path(share.STATE).parent
        folder.mkdir(mode=0o700)
        target = self.system.path("target")
        target.write_text("do not modify")
        self.system.path(share.STATE).symlink_to(target)
        with self.assertRaises(share.Error): self.system.change("lan")
        self.assertEqual(target.read_text(), "do not modify")

    def test_per_interface_previous_forwarding_is_restored(self):
        self.system.forwarding("eth0", "1")
        self.system.change("lan")
        self.system.change("off")
        self.assertEqual(self.system.forwarding("eth0"), "1")
        self.assertEqual(self.system.forwarding("ctrl0"), "0")

    def test_off_restores_when_adapter_disappeared(self):
        self.system.change("lan")
        self.system.path("proc/sys/net/ipv4/conf/eth0/forwarding").unlink()
        self.system.routes = [r for r in self.system.routes if r.get("type") == "unreachable"]
        self.system.change("off")
        self.assert_off()

    def test_status_is_actual_and_lists_interfaces(self):
        output = io.StringIO()
        with redirect_stdout(output): self.system.status()
        self.assertIn("Sharing: off", output.getvalue())
        self.assertIn("eth0 (lan, admin up, operational up, 192.168.1.2)", output.getvalue())
        self.system.change("lan")
        self.system.active = False
        with redirect_stdout(output): self.system.status()
        self.assertIn("degraded", output.getvalue())

    def test_status_separates_admin_up_from_disconnected_wifi_and_ethernet(self):
        # Exercise real sysfs discovery and JSON parsing, not the interface fixture.
        for name in ("eth0", "wlan0"):
            device = self.system.path("sys/class/net/" + name + "/device")
            device.mkdir(parents=True)
            if name == "wlan0":
                (device / "idVendor").write_text("148f")
                (device / "idProduct").write_text("3572")
                (device.parent / "phy80211").mkdir()
            else:
                (device.parent / "type").write_text("1")
        original_ip = self.system.ip
        records = [{"ifname": name, "flags": ["UP"], "operstate": "DOWN", "addr_info": []}
                   for name in ("ctrl0", "eth0", "wlan0")]
        self.system.ip = lambda *args: records if args == ("-j", "address", "show") else original_ip(*args)
        self.system.interfaces = lambda: share.Platform.interfaces(self.system)
        original_run = self.system.run
        self.system.run = lambda args, *rest, **kwargs: ("30 (disconnected)" if args[0].endswith("nmcli")
                                                       else original_run(args, *rest, **kwargs))
        output = io.StringIO()
        with redirect_stdout(output):
            self.system.status()
        self.assertIn("Control interface: ctrl0 (admin up, operational down, no IPv4 address)", output.getvalue())
        for name, mode in (("eth0", "lan"), ("wlan0", "wifi")):
            self.assertIn(f"{name} ({mode}, admin up, operational down, no IPv4 address)", output.getvalue())
        self.assertEqual(output.getvalue().count("Connection: not connected"), 2)
        self.assertFalse(self.system.rules or self.system.routes or self.system.active)

    def test_operational_state_unknown_is_not_inferred_from_admin_up(self):
        for value in (None, "UNKNOWN", "unexpected", ["UP"]):
            with self.subTest(value=value):
                self.assertEqual(share.operational_state({"flags": ["UP"], "operstate": value}), "unknown")

    @unittest.skipUnless(os.name == "posix", "Installed executable smoke test requires a POSIX kernel")
    def test_packaged_payload_help_executes_via_its_shebang(self):
        manifest = json.loads((ROOT / "common/components/share-control/component.json").read_text(encoding="utf-8"))
        payload = next(item for item in manifest["files"] if item["destination"] == "usr/local/libexec/automations/share")
        installed = Path(self.directory.name) / "installed-share"
        # Preserve payload bytes exactly, and apply the manifest mode like the installer.
        # Deliberately execute the file itself: invoking python would hide a CRLF shebang.
        installed.write_bytes((ROOT / payload["source"]).read_bytes())
        installed.chmod(int(payload["mode"], 8))
        result = subprocess.run([str(installed), "--help"], capture_output=True, text=True,
                                timeout=5, env=share.ENV, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        for option in ("--wifi", "--lan", "--off", "--status", "--to"):
            self.assertIn(option, result.stdout)
        self.assertEqual(self.system.calls, [])

    def test_help_requires_no_root_or_system_calls(self):
        output = io.StringIO()
        with redirect_stdout(output), self.assertRaises(SystemExit) as exit_context:
            share.main(["--help"], self.system, uid=1000)
        self.assertEqual(exit_context.exception.code, 0)
        self.assertIn("--wifi", output.getvalue())
        self.assertIn("--to NAME", output.getvalue())
        self.assertNotIn("--interface", output.getvalue())
        self.assertEqual(self.system.calls, [])

    def test_nonroot_change_refused(self):
        with redirect_stderr(io.StringIO()): self.assertEqual(share.main(["--lan"], self.system, uid=1000), 77)
        self.assertEqual(self.system.calls, [])

    def test_no_raw_command_output_disclosed_on_error(self):
        def bad(*args, **kwargs): raise OSError("secret-fixture-password")
        self.system.run = bad
        output = io.StringIO()
        with redirect_stderr(output): self.assertEqual(share.main(["--status"], self.system, uid=0), 1)
        self.assertNotIn("secret-fixture-password", output.getvalue())

    def test_dns_is_interface_bound_and_no_main_config_loaded(self):
        text = share.unit_text(SELECTION)
        self.assertIn("--servers-file=/run/auto-share-dns.servers", text)
        self.assertIn("server=192.168.1.1@eth0@192.168.1.2\n", share.servers_text(SELECTION))
        self.assertIn("--conf-file=/dev/null", text)
        self.assertIn("--no-resolv", text)
        self.assertIn("--host-record=pi4,10.78.0.1", text)
        self.assertNotIn("ExecStartPre", text)

    def test_invalid_upstream_overlap_or_dns_rejected(self):
        for key, value in (("gateway", "10.78.0.8"), ("dns", ["::1"]), ("dns", []), ("interface", "ctrl0"),
                           ("interface", "eth0;echo"), ("network", "0.0.0.0/0")):
            selected = copy.deepcopy(SELECTION)
            selected[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(share.Error): share.validate_selection(selected)


    def dual_stack(self):
        self.system.selection["ipv6"] = dict(address="2001:db8:1::2", addresses=["2001:db8:1::2"],
                                             network="2001:db8:1::/64", gateway="fe80::1")
        self.system.selection["dns"] += ["fe80::1%eth0", "2001:db8:1::53"]
        return self.system.selection

    def test_native_dstlen_rule_equivalence_does_not_accept_different_prefix(self):
        for dst, bits in (("fe80::", 10), ("ff00::", 8)):
            native = dict(priority=17854, src="all", dst=dst, dstlen=bits, table="main")
            self.assertEqual(share.Platform.normalize_rule(native)["dst"], dst + "/" + str(bits))
        self.system.change("lan")
        self.system.rules6[0]["dst"] = "fe80::"
        self.system.rules6[0]["dstlen"] = 10
        self.assertTrue(self.system.healthy(self.system.load()))
        self.system.rules6[0]["dstlen"] = 64
        with self.assertRaises(share.Error): self.system.routes_check(self.system.selection)

    def test_dual_stack_restores_every_forwarding_value_and_owned_addresses(self):
        self.dual_stack()
        self.system.write_ipv6_forwarding("wlan0", "1")
        original = self.system.ipv6_settings()
        self.system.change("lan")
        state = self.system.load()
        self.assertEqual(len(state["owned_addresses"]), 2)
        self.assertEqual(self.system.ipv6_settings(), {**original, "all":"1", "ctrl0":"1", "eth0":"1"})
        self.assertTrue(self.system.healthy(state))
        unit = self.system.read(share.UNIT)
        self.assertIn("--enable-ra", unit)
        self.assertIn("--no-dhcpv4-interface=ctrl0", unit)
        self.assertIn("server=fe80::1%eth0@eth0\n", self.system.read(share.DNS_SERVERS))
        self.system.change("off")
        self.assert_off()
        self.assertEqual(self.system.ipv6_settings(), original)
        self.assertEqual(self.system.addresses6, [])
        self.assertTrue(any(cmd == ["fixture-withdraw-ra"] for cmd,_ in self.system.calls))

    def test_empty_native_ipv6_address_array_can_be_initialized(self):
        self.dual_stack()
        real_ip = self.system.ip
        self.system.ip = lambda *args: ([] if args == ("-j", "-6", "address", "show", "dev", "ctrl0") and not self.system.addresses6
                                       else real_ip(*args))
        self.system.change("lan")
        self.assertEqual(len(self.system.addresses6), 2)
        self.system.change("off")
        self.assert_off()

    def test_completed_ipv4_only_probe_blocks_ipv6_without_ra_or_global_forwarding(self):
        before = self.system.ipv6_settings()
        self.system.change("lan")
        self.assertEqual(self.system.probe_count, 1)
        self.assertEqual(self.system.ipv6_settings(), before)
        self.assertEqual(self.system.addresses6, [])
        self.assertNotIn("--enable-ra", self.system.read(share.UNIT))
        self.assertEqual(len(self.system.routes6), 1)
        self.assertEqual(self.system.routes6[0]["type"], "unreachable")
        text = io.StringIO()
        with redirect_stdout(text): self.system.status()
        self.assertIn("completed discovery", text.getvalue())

    def test_probe_failure_is_not_downgraded_to_ipv4_success(self):
        def fail(selected): raise share.Error("Probe failed")
        self.system.probe_ipv6 = fail
        with self.assertRaisesRegex(share.Error, "Probe failed"): self.system.change("lan")
        self.assert_off()

    def test_preexisting_control_ipv6_addresses_are_never_adopted_or_removed(self):
        self.dual_stack()
        foreign = {"family":"inet6", "local":self.system.selection["control6"]["address"], "prefixlen":64}
        self.system.addresses6 = [foreign.copy()]
        with self.assertRaisesRegex(share.Error, "not adopted"): self.system.change("lan")
        self.assert_off()
        self.assertEqual(self.system.addresses6, [foreign])

    def test_second_address_failure_rolls_back_only_confirmed_first_add(self):
        self.dual_stack()
        self.system.fail = lambda cmd: cmd[:4] == ["/usr/sbin/ip", "-6", "address", "add"] and "fd12:3456:789a:1::1/64" in cmd
        with self.assertRaises(share.Error): self.system.change("lan")
        self.assertEqual(self.system.addresses6, [])
        self.assert_off()

    def test_dad_failure_restores_owned_addresses_and_reports_collision(self):
        self.dual_stack()
        original = self.system.run
        def run(cmd, *args, **kwargs):
            result = original(cmd, *args, **kwargs)
            if cmd[:4] == ["/usr/sbin/ip", "-6", "address", "add"]:
                self.system.addresses6[-1]["dadfailed"] = True
            return result
        self.system.run = run
        with self.assertRaisesRegex(share.Error, "collision"): self.system.change("lan")
        self.assert_off()
        self.assertEqual(self.system.addresses6, [])

    def test_ipv6_hot_unplug_restores_other_interfaces_and_preserves_new_interface(self):
        self.dual_stack()
        before = self.system.ipv6_settings()
        self.system.change("lan")
        for path in self.system.path("proc/sys/net/ipv6/conf/eth0").iterdir(): path.unlink()
        self.system.path("proc/sys/net/ipv6/conf/eth0").rmdir()
        self.system.path("proc/sys/net/ipv4/conf/eth0/forwarding").unlink()
        new = self.system.path("proc/sys/net/ipv6/conf/usb1/forwarding")
        new.parent.mkdir()
        new.write_text("1\n")
        self.system.routes6 = [x for x in self.system.routes6 if x.get("dev") != "eth0"]
        self.system.routes = [x for x in self.system.routes if x.get("dev") != "eth0"]
        self.system.change("off")
        self.assert_off()
        self.assertEqual(self.system.ipv6_settings(), {**{k:v for k,v in before.items() if k != "eth0"}, "usb1":"1"})

    def test_partial_global_forwarding_write_failure_restores_original_snapshot(self):
        self.dual_stack()
        self.system.write_ipv6_forwarding("wlan0", "1")
        before = self.system.ipv6_settings()
        original = self.system.write_ipv6_forwarding
        fired = False
        def fail(name, value):
            nonlocal fired
            original(name, value)
            if name == "all" and value == "1" and not fired:
                fired = True
                raise KeyboardInterrupt()
        self.system.write_ipv6_forwarding = fail
        with self.assertRaises(KeyboardInterrupt): self.system.change("lan")
        self.assert_off()
        self.assertEqual(self.system.ipv6_settings(), before)

    def test_changed_live_forwarding_refuses_overwrite_and_retains_guard(self):
        self.dual_stack()
        self.system.change("lan")
        self.system.write_ipv6_forwarding("wlan0", "1")
        with self.assertRaisesRegex(share.Error, "changed externally"): self.system.change("off")
        self.assertTrue(self.system.gate_present())
        self.assertEqual(self.system.ipv6_settings()["wlan0"], "1")
        self.assertTrue(self.system.load()["ready"])

    def test_ready_state_with_guard_is_degraded_and_reapply_can_recover(self):
        self.system.change("lan")
        self.system.gate(True)
        self.assertFalse(self.system.healthy(self.system.load()))
        self.system.change("lan")
        self.assertTrue(self.system.healthy(self.system.load()))
        self.assertFalse(self.system.gate_present())

    def test_incomplete_state_status_does_not_claim_successful_ipv6_probe(self):
        self.system.change("lan")
        state = self.system.load()
        state["ready"] = False
        self.system.save(state)
        output = io.StringIO()
        with redirect_stdout(output): self.system.status()
        self.assertIn("activation or cleanup is incomplete", output.getvalue())
        self.assertNotIn("completed discovery", output.getvalue())

    def test_ipv6_unsupported_nft_is_fatal_and_rolls_back_all_resources(self):
        self.dual_stack()
        self.system.fail = lambda cmd: cmd[0].endswith("nft") and "--check" in cmd
        with self.assertRaises(share.Error): self.system.change("lan")
        self.assert_off()
        self.assertEqual(self.system.addresses6, [])

    def test_wrong_dns_helper_uid_does_not_activate(self):
        self.system.path("proc/123/status").write_text("Uid:\t0\t0\t0\t0\n")
        with patch.object(share.time, "sleep") as sleep, self.assertRaisesRegex(share.Error, "UID.*startup timeout"):
            self.system.change("lan")
        self.assertEqual(sleep.call_count, 19)
        self.assert_off()

    def test_ipv6_only_uplink_is_rejected_before_mutation(self):
        original = self.system.ip
        self.system.ip = lambda *args: ([] if args == ("-j", "-4", "route", "show", "default", "dev", "eth0") else original(*args))
        with self.assertRaisesRegex(share.Error, "IPv6-only uplinks are not supported"): self.system.change("lan")
        self.assert_off()
        self.assertEqual(self.system.probe_count, 0)


    def test_partial_cleanup_does_not_overwrite_foreign_default_forwarding(self):
        self.dual_stack()
        self.system.change("lan")
        state = self.system.load()
        state["ready"] = False
        self.system.save(state)
        self.system.write_ipv6_forwarding("default", "1")
        with self.assertRaisesRegex(share.Error, "edited externally"): self.system.change("off")
        self.assertEqual(self.system.ipv6_settings()["default"], "1")
        self.assertTrue(self.system.gate_present())

    def test_status_never_reports_off_with_orphaned_guard(self):
        self.system.gate(True)
        with self.assertRaisesRegex(share.Error, "guard remains without state"):
            self.system.status()
        self.assertTrue(self.system.gate_present())
        self.system.change("off")
        self.assert_off()

    def test_status_does_not_solicit_router_or_mutate_network(self):
        self.dual_stack()
        self.system.change("lan")
        self.system.calls.clear()
        probes = self.system.probe_count
        before = copy.deepcopy(self.system.fw)
        with redirect_stdout(io.StringIO()): self.system.status()
        self.assertEqual(self.system.probe_count, probes)
        self.assertEqual(self.system.fw, before)
        for command,_ in self.system.calls:
            self.assertFalse(any(word in command for word in ("add", "del", "flush", "start", "stop", "daemon-reload")))


    def test_ipv6_dns_native_colons_are_requested_without_nmcli_escaping(self):
        def ip(*args):
            if "address" in args:
                return [{"ifname":"eth0", "addr_info":[{"family":"inet6", "local":"2001:db8:1::2", "prefixlen":64, "scope":"global"}]}]
            return [{"dst":"default", "gateway":"fe80::1", "dev":"eth0", "metric":600}]
        def run(args, *rest, **kwargs):
            self.assertEqual(args, ["/usr/bin/nmcli", "--escape", "no", "-g", "IP6.DNS", "device", "show", "eth0"])
            return "fe80::1 | 2001:db8:1::53\nfe80::1%eth0\n"
        self.system.ip, self.system.run = ip, run
        v6,dns = share.Platform.discover_ipv6(self.system, "eth0")
        self.assertEqual(v6["address"], "2001:db8:1::2")
        self.assertEqual(dns, ["fe80::1%eth0", "2001:db8:1::53"])


    def test_ra_explicitly_admits_only_control_interface_and_checks_scoped_listener(self):
        selected = self.dual_stack()
        text = share.unit_text(selected)
        interfaces = [word for word in text.split() if word.startswith("--interface=")]
        self.assertEqual(interfaces, ["--interface=ctrl0"])
        self.assertNotIn("--interface=", share.unit_text(SELECTION))
        self.system.change("lan")
        self.assertTrue(self.system.service_check(selected))
        original = self.system.run
        def foreign_listener(args, *rest, **kwargs):
            output = original(args, *rest, **kwargs)
            if args[0].endswith("ss"):
                output = output.replace("fe80::789a%ctrl0", "fe80::789a%eth0")
            return output
        self.system.run = foreign_listener
        self.assertFalse(self.system.service_check(selected))

    def test_upstream_dns_listener_is_not_allowed_by_ra_binding(self):
        selected = self.dual_stack()
        self.system.change("lan")
        original = self.system.run
        def extra_listener(args, *rest, **kwargs):
            output = original(args, *rest, **kwargs)
            if args[0].endswith("ss"):
                output += 'LISTEN 0 32 [2001:db8:1::2]:1053 *:* users:(("dnsmasq",pid=123,fd=9))\n'
            return output
        self.system.run = extra_listener
        self.assertFalse(self.system.service_check(selected))



    def test_native_tcp_scope_and_udp_unscoped_control_listener(self):
        selected = self.dual_stack()
        self.system.change("lan")
        fixture = json.loads((Path(__file__).parent / "fixtures/native-dns-listeners.json").read_text())
        process = self.system.path("proc/" + str(fixture["pid"]) + "/status")
        process.parent.mkdir(parents=True)
        process.write_text("Uid:\t65534\t65534\t65534\t65534\n")
        service = self.system.service()
        service["MainPID"] = str(fixture["pid"])
        self.system.service = lambda: service
        original = self.system.run
        def native(args, *rest, **kwargs):
            if args[0].endswith("ss"):
                return fixture["inputs"][args[-1]]
            return original(args, *rest, **kwargs)
        self.system.run = native
        self.assertTrue(self.system.service_check(selected))
        for protocol, old, new in (
                ("-ltnp", "%ctrl0", "%eth0"),
                ("-ltnp", "%ctrl0", ""),
                ("-lunp", "[fe80::789a]", "[fe80::789a]%eth0"),
                ("-lunp", "[fe80::789a]", "[fe80::1234]"),
                ("-lunp", "[fe80::789a]", "[::]"),
                ("-lunp", "pid=175950,", "pid=175951,")):
            with self.subTest(protocol=protocol, replacement=new):
                saved = fixture["inputs"][protocol]
                fixture["inputs"][protocol] = saved.replace(old, new)
                self.assertFalse(self.system.service_check(selected))
                fixture["inputs"][protocol] = saved



    def test_native_nmcli_dns_array_separators_and_normalization(self):
        # NM 1.56.1 emits the same pipe-separated format for IP4.DNS/IP6.DNS.
        # Documentation addresses replace the actual guest-router addresses.
        self.assertEqual(share.nm_dns_servers("192.0.2.53 | 198.51.100.53\n192.0.2.53\n", 4, "wlan0"),
                         ["192.0.2.53", "198.51.100.53"])
        self.assertEqual(share.nm_dns_servers("fd12:3456:789a:1::53 | 2001:db8:1::53\nfe80::1%wlan0\nfe80::1\n", 6, "wlan0"),
                         ["fd12:3456:789a:1::53", "2001:db8:1::53", "fe80::1%wlan0"])
        self.assertEqual(share.nm_dns_servers("2001:0db8:1:0::53|2001:db8:1::53\n", 6, "wlan0"), ["2001:db8:1::53"])
        for version in (4, 6):
            self.assertEqual(share.nm_dns_servers("\n  \n", version, "wlan0"), [])

    def test_invalid_nmcli_dns_metadata_has_bounded_contextual_error(self):
        invalid = [
            (4, "192.0.2.53 |"), (4, "| 192.0.2.53"), (4, "192.0.2.53 || 198.51.100.53"),
            (4, "192.0.2.53 198.51.100.53"), (4, "192.0.2.53,198.51.100.53"),
            (4, "192.0.2.53%wlan0"), (4, "::1"), (4, "127.0.0.1"), (4, "10.78.0.1"),
            (6, "fe80::1%eth0"), (6, "fe80::1%wlan0%other"), (6, "2001:db8::53%wlan0"),
            (6, "2001:db8::53 |"), (6, "fe80::1 | malformed-metadata"), (6, "192.0.2.53"),
            (6, "::1"), (6, "::"), (6, "ff02::1"), (6, "x" * 8193),
            (4, " | ".join("192.0.2." + str(n) for n in range(1, 18))),
        ]
        for version, raw in invalid:
            with self.subTest(version=version, raw=raw[:80]), self.assertRaises(share.Error) as caught:
                share.nm_dns_servers(raw, version, "wlan0")
            self.assertEqual(str(caught.exception),
                             f"Cannot read IPv{version} DNS servers from NetworkManager: invalid address list or scope.")

    def test_native_ipv4_dns_list_is_used_by_upstream_selection(self):
        original = self.system.run
        def native(args, *rest, **kwargs):
            if "IP4.DNS" in args:
                self.assertEqual(args, ["/usr/bin/nmcli", "--escape", "no", "-g", "IP4.DNS", "device", "show", "eth0"])
                return "192.168.1.1 | 1.1.1.1\n192.168.1.1\n"
            return original(args, *rest, **kwargs)
        self.system.run = native
        self.assertEqual(self.system.select("lan")["dns"], ["192.168.1.1", "1.1.1.1"])

    def test_bad_new_dns_metadata_keeps_existing_sharing_state(self):
        self.system.change("lan")
        before = (self.system.load(), copy.deepcopy(self.system.fw), copy.deepcopy(self.system.routes))
        original = self.system.run
        def malformed(args, *rest, **kwargs):
            if "IP4.DNS" in args:
                return "192.168.1.1 | malformed-metadata"
            return original(args, *rest, **kwargs)
        self.system.run = malformed
        with self.assertRaisesRegex(share.Error, "Cannot read IPv4 DNS servers from NetworkManager") as caught:
            self.system.change("lan")
        self.assertNotIn("off", str(caught.exception).lower())
        self.assertTrue(self.system.active)
        self.assertEqual((self.system.load(), self.system.fw, self.system.routes), before)



    def test_cleanup_removes_ipv6_routes_before_their_preferred_source(self):
        self.dual_stack()
        self.system.change("lan")
        original = self.system.ipv6_addresses
        def native_address_removal(state, enabled):
            if not enabled:
                # Native Linux erases prefsrc when its source address disappears.
                # No owned routes may remain at this point in the fixed cleanup.
                self.assertEqual(self.system.routes6, [])
            return original(state, enabled)
        self.system.ipv6_addresses = native_address_removal
        self.system.change("off")
        self.assert_off()
        self.assertEqual(self.system.addresses6, [])

    def partial_cleanup_without_control_source(self):
        selected = self.dual_stack()
        self.system.change("lan")
        state = self.system.load()
        state["ready"] = False
        self.system.ipv6_addresses(state, False)
        self.system.save(state)
        for route in self.system.routes6:
            if route.get("dev") == "ctrl0":
                route.pop("prefsrc", None)
        return selected, state

    def test_recover_old_partial_cleanup_with_confirmed_absent_control_source(self):
        selected, state = self.partial_cleanup_without_control_source()
        with self.assertRaisesRegex(share.Error, "Changed or duplicate reserved routing objects"):
            self.system.routes_check(selected)
        self.system.change("off")
        self.assert_off()
        self.assertEqual(self.system.addresses6, [])

    def test_recovery_route_exception_requires_absence_and_completed_address_cleanup(self):
        selected, state = self.partial_cleanup_without_control_source()
        for mutation in ("ready", "owned", "present", "metric", "wrong_source", "upstream_source"):
            with self.subTest(mutation=mutation):
                trial = copy.deepcopy(state)
                original_routes = copy.deepcopy(self.system.routes6)
                original_addresses = copy.deepcopy(self.system.addresses6)
                if mutation == "ready": trial["ready"] = True
                elif mutation == "owned": trial["owned_addresses"] = [selected["control6"]["address"] + "/64"]
                elif mutation == "present":
                    self.system.addresses6 = [{"family":"inet6", "local":selected["control6"]["address"], "prefixlen":64}]
                else:
                    route = next(row for row in self.system.routes6 if row.get("dev") == "ctrl0")
                    if mutation == "metric": route["metric"] = 11
                    elif mutation == "wrong_source": route["prefsrc"] = "fd12:3456:789a:1::99"
                    else:
                        route = next(row for row in self.system.routes6 if row.get("dev") == "eth0" and "prefsrc" in row)
                        route["prefsrc"] = "2001:db8:1::99"
                with self.assertRaisesRegex(share.Error, "Changed or duplicate reserved routing objects"):
                    self.system.routes_check(selected, trial)
                self.system.routes6 = original_routes
                self.system.addresses6 = original_addresses



    def test_startup_waits_for_actual_dnsmasq_privilege_drop(self):
        process = self.system.path("proc/123/status")
        process.write_text("Uid:\t0\t0\t0\t0\n")
        def drop_privileges(_delay):
            self.assertFalse(self.system.load()["ready"])
            self.assertEqual(self.system.forwarding("ctrl0"), "0")
            process.write_text("Uid:\t65534\t65534\t65534\t65534\n")
        with patch.object(share.time, "sleep", side_effect=drop_privileges) as sleep:
            self.system.change("lan")
        self.assertEqual(sleep.call_count, 1)
        self.assertTrue(self.system.healthy(self.system.load()))

    def test_startup_retries_process_appearing_with_expected_uid(self):
        process = self.system.path("proc/123/status")
        process.unlink()
        def appear(_delay):
            process.write_text("Uid:\t65534\t65534\t65534\t65534\n")
        with patch.object(share.time, "sleep", side_effect=appear) as sleep:
            self.system.change("lan")
        self.assertEqual(sleep.call_count, 1)
        self.assertTrue(self.system.healthy(self.system.load()))

    def test_live_dns_uid_validation_is_not_relaxed_by_startup_retry(self):
        self.system.change("lan")
        self.system.path("proc/123/status").write_text("Uid:\t0\t0\t0\t0\n")
        with patch.object(share.time, "sleep") as sleep, self.assertRaisesRegex(share.Error, "expected UID"):
            self.system.service_check(self.system.selection)
        sleep.assert_not_called()



    def test_native_uplink_loss_off_and_reconnected_reapply(self):
        states = json.loads((Path(__file__).parent / "fixtures/native-uplink-route-loss.json").read_text())["states"]
        for stage in ("carrier_down", "address_removed", "reconnected"):
            with self.subTest(stage=stage):
                selected = self.dual_stack()
                self.system.change("lan")
                native = states[stage]
                for family in (4, 6):
                    rows = self.system.routes if family == 4 else self.system.routes6
                    prefix = selected["network"] if family == 4 else selected["ipv6"]["network"]
                    rows[:] = [row for row in rows if row.get("dst") != prefix]
                    rows.extend(copy.deepcopy(native["routes" + str(family)]))
                original_ip = self.system.ip
                def actual_interfaces(*args):
                    rows = original_ip(*args)
                    if args == ("-j", "address", "show"):
                        return [row for row in rows if row.get("ifname") != "eth0"] + [copy.deepcopy(native["interface"])]
                    return rows
                self.system.ip = actual_interfaces
                with self.assertRaises(share.Error): self.system.healthy(self.system.load())
                if stage == "reconnected":
                    self.system.change("lan")
                    self.assertTrue(self.system.healthy(self.system.load()))
                self.system.change("off")
                self.assert_off()
                self.system.ip = original_ip
                self.system.selection = copy.deepcopy(SELECTION)

    def test_cleanup_rejects_linkdown_if_real_uplink_is_up_and_other_route_edits(self):
        self.dual_stack()
        self.system.change("lan")
        state = self.system.load()
        state["ready"] = False
        route = next(row for row in self.system.routes6 if row.get("dev") == "eth0" and "prefsrc" in row)
        route["flags"] = ["linkdown"]
        with self.assertRaisesRegex(share.Error, "Unexpected route flags"):
            self.system.routes_check(self.system.selection, state)
        route["flags"] = []
        route.pop("prefsrc")
        route["metric"] = 11
        with self.assertRaisesRegex(share.Error, "Changed or duplicate reserved routing objects"):
            self.system.routes_check(self.system.selection, state)


class SourceLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.system=Fixture(Path(self.temp.name))

    def detached_guest_state(self):
        selection = copy.deepcopy(SELECTION)
        selection.update(guest=dict(share.GUEST), sources=["ctrl0"])
        for family in (4, 6):
            routes, rules = self.system.route_plan(selection, family)
            setattr(self.system, "routes6" if family == 6 else "routes", [copy.deepcopy(row) for _, row in routes])
            setattr(self.system, "rules6" if family == 6 else "rules", [copy.deepcopy(row) for _, row in rules])
        row = next(row for row in self.system.rules if row.get("iif") == share.GUEST["interface"])
        row["iif_detached"] = None
        return {"selection": selection, "ready": False, "owned_addresses": []}, row

    def test_detached_owned_guest_rule_is_cleanup_only_and_removed_without_missing_device_name(self):
        state, row = self.detached_guest_state()
        with self.assertRaisesRegex(share.Error, "Unrecognized"):
            self.system.routes_check(state["selection"])
        self.system.routes_check(state["selection"], state)
        self.system.remove_routes(state["selection"], state)
        command = next(args for args, _ in self.system.calls if args[:4] == ["/usr/sbin/ip", "-4", "rule", "del"]
                       and str(row["priority"]) in args)
        self.assertNotIn("iif", command)
        self.assertFalse(self.system.rules or self.system.rules6 or self.system.routes or self.system.routes6)

    def test_detached_flag_never_admits_foreign_or_modified_rule(self):
        for mutation in ({"priority": 17858}, {"table": 100}, {"src": "192.0.2.3"},
                         {"iif": "other"}, {"iif_detached": True}, {"unexpected": None}):
            state, row = self.detached_guest_state()
            row.update(mutation)
            with self.subTest(mutation=mutation), self.assertRaises(share.Error):
                self.system.routes_check(state["selection"], state)

    def test_detached_guest_rule_with_live_interface_or_duplicate_priority_is_refused(self):
        state, row = self.detached_guest_state()
        original = self.system.ip
        self.system.ip = lambda *args: ([{"ifname": share.GUEST["interface"]}]
            if args == ("-j", "address", "show") else original(*args))
        with self.assertRaisesRegex(share.Error, "Unrecognized"):
            self.system.routes_check(state["selection"], state)
        self.system.ip = original
        self.system.rules.append({key: value for key, value in row.items() if key != "iif_detached"})
        with self.assertRaisesRegex(share.Error, "Ambiguous"):
            self.system.routes_check(state["selection"], state)

    def test_cli_missing_sources_never_changes_network_or_reads_redirected_input(self):
        stdin=io.StringIO('ctrl0\n');err=io.StringIO()
        with patch('sys.stdin',stdin),redirect_stderr(err):
            self.assertEqual(share.main(['--lan','--to','eth0'],self.system,uid=0),1)
        self.assertEqual(stdin.tell(),0)
        self.assertIn('--from',err.getvalue())
        self.assertFalse(self.system.path(share.STATE).exists())
        self.assertEqual(self.system.calls,[])

    def test_cli_explicit_source_activates_and_survives_status_then_cleans(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(share.main(['--lan','--to','eth0','--from','ctrl0'],self.system,uid=0),0)
            self.assertEqual(share.main(['--status'],self.system,uid=0),0)
        self.assertEqual(self.system.load()['selection']['sources'],['ctrl0'])
        self.assertTrue(self.system.healthy(self.system.load()))
        self.system.change('off')
        self.assertIsNone(self.system.load())
        share.firewall_check(self.system.fw)
        self.system.routes_check()

    def test_legacy_uplink_alias_uses_the_same_selection(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(share.main(['--lan','--interface','eth0','--from','ctrl0'],self.system,uid=0),0)
        self.assertEqual(self.system.load()['selection']['interface'],'eth0')
        self.assertEqual(self.system.load()['selection']['sources'],['ctrl0'])
        self.assertTrue(self.system.healthy(self.system.load()))
        self.system.change('off')

    def test_duplicate_or_inapplicable_uplink_selector_never_changes_network(self):
        for argv in (['--status','--to','eth0'],
                     ['--lan','--to','eth0','--interface','wlan0','--from','ctrl0']):
            with self.subTest(argv=argv),redirect_stderr(io.StringIO()),self.assertRaises(SystemExit) as caught:
                share.main(argv,self.system,uid=0)
            self.assertEqual(caught.exception.code,64)
            self.assertFalse(self.system.calls)
            self.assertIsNone(self.system.load())

    def test_invalid_or_unavailable_source_cannot_replace_existing_selection(self):
        self.system.change('lan','eth0',['ctrl0'])
        before=copy.deepcopy(self.system.load()),copy.deepcopy(self.system.fw),list(self.system.routes)
        for value in ('ctrl0,wlan1','eth0','ctrl0,',''):
            with redirect_stderr(io.StringIO()):
                self.assertEqual(share.main(['--lan','--from',value],self.system,uid=0),1)
            self.assertEqual((self.system.load(),self.system.fw,self.system.routes),before)


if __name__ == "__main__":
    unittest.main()
