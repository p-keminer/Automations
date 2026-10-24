import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
SPEC = importlib.util.spec_from_file_location("auto_ssh_module", ROOT / "pi4/python/auto_ssh.py")
ssh = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ssh)


class System:
    def __init__(self, root, enabled=False):
        self.root = root
        self.enabled = enabled
        self.listener = enabled
        self.unit_dependency = enabled
        self.calls = []
        self.extra_rules = []
        self.ctrl = True
        self.fail = None
        self.extra_listener = None
        self.dropins = ""
        self.loops = True
        for path, text in ((ssh.CONFIG, ssh.config_text(enabled)), (ssh.FIREWALL, ssh.firewall_text(enabled)),
                           (ssh.UNIT, ssh.UNIT_ON if enabled else ssh.UNIT_OFF)):
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
            target.chmod(0o644 if path == ssh.UNIT else 0o600)
        (root / "run").mkdir()
        (root / "proc/net").mkdir(parents=True)
        for name in ("tcp", "tcp6"):
            (root / "proc/net" / name).write_text("sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n")

    def nft_json(self):
        rules = copy.deepcopy(ssh.RULES) + ([copy.deepcopy(ssh.SSH_RULE)] if self.enabled else [])
        rules += self.extra_rules
        return {"nftables": [{"metainfo": {"json_schema_version": 1}},
                {"chain": {"family": "inet", "table": "pi4", "name": "input", "type": "filter",
                           "hook": "input", "prio": 0, "policy": "drop"}},
                *[{"rule": {"family": "inet", "table": "pi4", "chain": "input", "handle": 10 + index, "expr": value}}
                  for index, value in enumerate(rules)]]}

    def __call__(self, args, input_text=None):
        self.calls.append((args, input_text))
        if args[:3] == ["systemctl", "show", ssh.SERVICE]:
            return "\n".join(["ActiveState=active", "SubState=running", "MainPID=123",
                "FragmentPath=/" + ssh.UNIT, "DropInPaths=" + self.dropins,
                "ExecStart={ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D -e -f /etc/pi4/sshd_config ; ignore_errors=no ; }",
                "KillMode=process", "Requires=" + ("nftables.service" if self.unit_dependency else ""),
                "After=network.target cloud-config.service" + (" nftables.service" if self.unit_dependency else "")])
        if args[:3] == ["nft", "--json", "--handle"]:
            return json.dumps(self.nft_json())
        if args == ["ss", "-H", "-ltnp"]:
            values = (["127.0.0.1:2222"] if self.loops else []) + (["0.0.0.0:22"] if self.listener else [])
            if self.extra_listener:
                values.append(self.extra_listener)
            return "\n".join(f'LISTEN 0 128 {address} 0.0.0.0:* users:(("sshd",pid=123,fd=3))' for address in values)
        if args == ["ip", "-json", "address", "show"]:
            return json.dumps(([{"ifname": "ctrl0", "operstate": "UP", "flags": ["UP"],
                                 "addr_info": [{"local": "10.78.0.1", "prefixlen": 24}]}] if self.ctrl else []) +
                              [{"ifname": "wlan0", "operstate": "DOWN", "addr_info": []}])
        if args[:3] == ["/usr/sbin/sshd", "-t", "-f"]:
            if self.fail == "sshd-check":
                raise ssh.Error("sshd candidate rejected")
            assert "ListenAddress 127.0.0.1:2222" in Path(args[-1]).read_text()
            return ""
        if args[:3] == ["nft", "--check", "--file"]:
            if self.fail == "nft-check":
                raise ssh.Error("nft candidate rejected")
            return ""
        if args == ["nft", "--file", "-"]:
            if self.fail == "nft-apply-once":
                self.fail = None
                raise ssh.Error("live rule failed")
            if input_text == 'add rule inet pi4 input iifname "ctrl0" tcp dport 22 accept\n':
                self.enabled = True
            elif input_text == "delete rule inet pi4 input handle 17\n":
                self.enabled = False
            else:
                raise AssertionError("Unexpected nft modification: " + input_text)
            return ""
        if args == ["systemctl", "daemon-reload"]:
            self.unit_dependency = "Requires=nftables.service" in (self.root / ssh.UNIT).read_text()
            return ""
        if args == ["systemctl", "kill", "--kill-whom=main", "--signal=HUP", ssh.SERVICE]:
            if self.fail in ("hup-once", "hup-always"):
                if self.fail == "hup-once":
                    self.fail = None
                raise ssh.Error("HUP failed")
            self.listener = ssh.DIRECT_LISTENER in (self.root / ssh.CONFIG).read_text()
            return ""
        raise AssertionError("Unexpected command: " + repr(args))


class ControlTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.system = System(self.root)
        self.platform = ssh.Platform(self.root, self.system, os.geteuid(), lambda delay: None)

    def assertNoChanges(self):
        commands = [args for args, _ in self.system.calls]
        self.assertNotIn(["nft", "--file", "-"], commands)
        self.assertFalse(any(args[:2] == ["systemctl", "kill"] for args in commands))
        self.assertEqual((self.root / ssh.CONFIG).read_text(), ssh.CONFIG_OFF)

    def native_firewall(self):
        return json.loads((Path(__file__).parent / "fixtures/nft-1.1.7-pi4-input.json").read_text())

    def test_native_nft_1_1_7_array_state_membership(self):
        native = self.native_firewall()
        self.assertEqual(ssh.live_ssh_handle(native), 12)
        # Recognition must not mutate the supplied observation.
        self.assertEqual(native, self.native_firewall())
        native["nftables"].pop()
        self.assertIsNone(ssh.live_ssh_handle(native))

    def add_share_rules(self, data):
        data = copy.deepcopy(data)
        data['nftables'][2:2] = [
            {'rule': {'family': 'inet', 'table': 'pi4', 'chain': 'input', 'handle': 40 + index,
                      'expr': copy.deepcopy(expression), 'comment': ssh.SHARE_DNS_TAGS[index]}}
            for index, expression in enumerate(ssh.SHARE_DNS_RULES)]
        return data

    def test_sharing_dns_rules_coexist_with_ssh_toggles(self):
        original = self.system.nft_json
        self.system.nft_json = lambda: self.add_share_rules(original())
        state, changed = self.platform.change(True)
        self.assertTrue(changed and state['enabled'])
        state, changed = self.platform.change(False)
        self.assertTrue(changed and not state['enabled'])
        self.assertEqual(self.system.nft_json()['nftables'][2]['rule']['comment'], ssh.SHARE_DNS_TAGS[0])

    def test_sharing_tag_cannot_allow_broader_or_different_access(self):
        good = self.add_share_rules(self.native_firewall())
        self.assertEqual(ssh.live_ssh_handle(good), 12)
        for change in ('source', 'port', 'interface', 'order', 'missing-tag', 'duplicate'):
            data = copy.deepcopy(good)
            rule = data['nftables'][2]['rule']
            if change == 'source':
                rule['expr'][1]['match']['right']['prefix']['len'] = 0
            elif change == 'port':
                rule['expr'][3]['match']['right'] = 22
            elif change == 'interface':
                rule['expr'][0]['match']['right'] = 'wlan0'
            elif change == 'order':
                data['nftables'][2:4] = reversed(data['nftables'][2:4])
            elif change == 'missing-tag':
                rule.pop('comment')
            else:
                data['nftables'].append(copy.deepcopy(data['nftables'][2]))
            with self.subTest(change=change), self.assertRaises(ssh.Error):
                ssh.live_ssh_handle(data)

    def share_v2_contract(self):
        # Generated from the separately owned share component's final input-rule
        # contract, not from the SSH validator's expected expressions. Native
        # nft spelling is checked separately when the hardware fixture exists.
        return json.loads((Path(__file__).parent / "fixtures/share-v2-contract-input.json").read_text())

    def test_share_v2_final_and_admission_shapes_are_recognized(self):
        complete = self.share_v2_contract()
        self.assertEqual(ssh.live_ssh_handle(complete, {"wlan0"}), 12)
        admission = copy.deepcopy(complete)
        admission["nftables"] = [item for item in admission["nftables"]
            if item.get("rule", {}).get("comment") not in ssh.SHARE_DNS_TAGS + ssh.SHARE_DNS6_TAGS]
        self.assertEqual(ssh.live_ssh_handle(admission, {"wlan0"}), 12)
        ipv4_only = copy.deepcopy(complete)
        ipv4_only["nftables"] = [item for item in ipv4_only["nftables"]
            if item.get("rule", {}).get("comment") not in ssh.SHARE_DNS6_TAGS]
        self.assertEqual(ssh.live_ssh_handle(ipv4_only, {"wlan0"}), 12)

    def test_share_v2_native_icmp_type_names_and_set_order_are_equivalent(self):
        data = self.share_v2_contract()
        names = {number: name for name, number in ssh.ICMP6_NAMES.items()}
        for item in data["nftables"]:
            for part in item.get("rule", {}).get("expr", []):
                value = part.get("match", {})
                if value.get("left") == {"payload": {"protocol": "icmpv6", "field": "type"}}:
                    right = value["right"]
                    if isinstance(right, int):
                        value["right"] = names[right]
                    else:
                        value["right"] = {"set": [names[number] for number in reversed(right["set"])]}
                        value["op"] = "in"
        self.assertEqual(ssh.live_ssh_handle(data, {"wlan0"}), 12)

    def test_share_v2_actual_namespace_nft_input_fixture(self):
        # Native nft 1.0.9 output from an isolated namespace; only the input
        # chain and its rules were extracted, with no expression rewriting.
        data = json.loads((Path(__file__).parent / "fixtures/share-v2-native-input.json").read_text())
        self.assertEqual(ssh.live_ssh_handle(data, {"eth0"}), 13)
        data["nftables"].pop()  # Same native shape with direct SSH off.
        self.assertIsNone(ssh.live_ssh_handle(data, {"eth0"}))

    def test_share_v2_rules_survive_actual_ssh_switch_path(self):
        extra = [item for item in self.share_v2_contract()["nftables"]
                 if item.get("rule", {}).get("comment", "").startswith("auto-share:")]
        original = self.system.nft_json

        def nft():
            data = original()
            data["nftables"][2:2] = copy.deepcopy(extra)
            return data

        self.system.nft_json = nft
        self.assertTrue(self.platform.change(True)[0]["enabled"])
        self.assertFalse(self.platform.change(False)[0]["enabled"])
        self.assertEqual(nft()["nftables"][2:2 + len(extra)], extra)

    def sharing_state(self):
        selected = {"mode": "wifi", "interface": "wlan0", "address": "192.168.2.2", "network": "192.168.2.0/24",
                    "gateway": "192.168.2.1", "dns": ["192.168.2.1"],
                    "ipv6": {"address": "2001:db8:1::2", "addresses": ["2001:db8:1::2"],
                             "network": "2001:db8:1::/64", "gateway": "fe80::1"},
                    "control6": {"network": "fd78:1234:5678:9abc::/64", "address": "fd78:1234:5678:9abc::1",
                                 "linklocal": "fe80::1234"}}
        return {"version": 2, "selection": selected, "forwarding": {"ctrl0": "0", "wlan0": "0"},
                "ipv6_forwarding": {"all": "0", "default": "0", "ctrl0": "0", "wlan0": "0"},
                "owned_addresses": [selected["control6"]["address"] + "/64", "fe80::1234/64"],
                "ready": True, "steps": ["gate", "addresses", "routes", "unit", "firewall", "forwarding"]}

    def store_sharing_state(self, state):
        path = self.root / ssh.SHARE_STATE
        path.parent.mkdir(mode=0o700, exist_ok=True)
        path.write_text(json.dumps(state))
        path.chmod(0o600)
        return path

    def missing_upstream_firewall(self, *, admission=False):
        extras = [item for item in self.share_v2_contract()["nftables"]
                  if item.get("rule", {}).get("comment", "").startswith("auto-share:")]
        if admission:
            extras = [item for item in extras if item["rule"]["comment"] in ssh.SHARE_V6_TAGS]
        original = self.system.nft_json
        def nft():
            data = original()
            data["nftables"][2:2] = copy.deepcopy(extras)
            return data
        self.system.nft_json = nft
        def run(args, input_text=None):
            result = self.system(args, input_text)
            if args == ["ip", "-json", "address", "show"]:
                return json.dumps([item for item in json.loads(result) if item["ifname"] != "wlan0"])
            return result
        self.platform.run = run
        return extras

    def test_unplugged_shared_upstream_allows_status_and_exact_ssh_toggles(self):
        extras = self.missing_upstream_firewall()
        path = self.store_sharing_state(self.sharing_state())
        before = path.read_bytes()
        self.assertFalse(self.platform.inspect()["enabled"])
        self.assertTrue(self.platform.change(True)[0]["enabled"])
        self.assertFalse(self.platform.change(False)[0]["enabled"])
        self.assertEqual(self.system.nft_json()["nftables"][2:2 + len(extras)], extras)
        self.assertEqual(path.read_bytes(), before)
        self.assertTrue(self.system.loops)

    def test_unplugged_admission_accepts_its_incomplete_but_owned_state(self):
        self.missing_upstream_firewall(admission=True)
        state = self.sharing_state()
        state.update(ready=False, steps=["gate", "admission"], owned_addresses=[])
        state["selection"]["ipv6"] = None
        self.store_sharing_state(state)
        self.assertFalse(self.platform.inspect()["enabled"])

    def test_missing_share_state_never_trusts_an_absent_interface(self):
        self.missing_upstream_firewall()
        with self.assertRaises(FileNotFoundError):
            self.platform.change(True)
        self.assertNoChanges()

    def test_unplugged_upstream_rejects_foreign_state_and_scope(self):
        self.missing_upstream_firewall()
        for bad in ("version", "interface", "control", "mode", "wide-prefix", "different-prefix", "dns-target",
                    "no-ipv6", "no-own-step", "extra-field", "forwarding", "owned-address", "dns-type"):
            state = self.sharing_state()
            selected = state["selection"]
            if bad == "version": state["version"] = 1
            elif bad == "interface": selected["interface"] = "eth0"
            elif bad == "control": selected["interface"] = "ctrl0"
            elif bad == "mode": selected["mode"] = "bridge"
            elif bad == "wide-prefix": selected["control6"]["network"] = "fd78:1234:5678::/48"
            elif bad == "different-prefix":
                selected["control6"].update(network="fd12:3456:789a:1::/64", address="fd12:3456:789a:1::1")
                state["owned_addresses"] = []
            elif bad == "dns-target": selected["control6"]["address"] = "fd78:1234:5678:9abc::2"
            elif bad == "no-ipv6": selected["ipv6"] = None; state["owned_addresses"] = []
            elif bad == "no-own-step": state["steps"] = ["gate"]
            elif bad == "extra-field": state["unrecognized"] = True
            elif bad == "forwarding": state["forwarding"]["wlan0"] = "2"
            elif bad == "owned-address": state["owned_addresses"].append("2001:db8::2/64")
            elif bad == "dns-type": selected["dns"] = [42]
            self.store_sharing_state(state)
            with self.subTest(bad=bad), self.assertRaises(ssh.Error):
                self.platform.change(True)
            self.assertNoChanges()

    def test_unplugged_upstream_rejects_unsafe_state_metadata(self):
        self.missing_upstream_firewall()
        path = self.store_sharing_state(self.sharing_state())
        for mode in (0o644, 0o660, 0o666):
            path.chmod(mode)
            with self.subTest(mode=mode), self.assertRaises(ssh.Error): self.platform.handle()
        path.chmod(0o600)
        path.parent.chmod(0o755)
        with self.assertRaises(ssh.Error): self.platform.handle()
        path.parent.chmod(0o700)
        sibling = path.with_name("state-hardlink")
        os.link(path, sibling)
        with self.assertRaises(ssh.Error): self.platform.handle()
        sibling.unlink()
        original = path.read_text()
        path.unlink()
        sibling.write_text(original)
        sibling.chmod(0o600)
        path.symlink_to(sibling)
        with self.assertRaises(ssh.Error): self.platform.handle()
        self.assertNoChanges()

    def test_unplugged_upstream_rejects_oversized_or_invalid_json_state(self):
        self.missing_upstream_firewall()
        path = self.store_sharing_state(self.sharing_state())
        path.write_text(" " * 65537)
        with self.assertRaises(ssh.Error): self.platform.handle()
        path.write_text("{")
        with self.assertRaises(ValueError): self.platform.handle()
        self.assertNoChanges()

    def test_unplugged_state_does_not_relax_actual_rule_validation(self):
        self.missing_upstream_firewall()
        self.store_sharing_state(self.sharing_state())
        original = self.system.nft_json
        def broadened():
            data = original()
            next(x["rule"] for x in data["nftables"] if x.get("rule", {}).get("comment") ==
                 ssh.SHARE_V6_TAGS[0])["expr"][1]["match"]["right"]["prefix"]["len"] = 0
            return data
        self.system.nft_json = broadened
        with self.assertRaises(ssh.Error): self.platform.change(True)
        self.assertNoChanges()

    def test_present_upstream_does_not_require_optional_share_state(self):
        extras = [item for item in self.share_v2_contract()["nftables"]
                  if item.get("rule", {}).get("comment", "").startswith("auto-share:")]
        original = self.system.nft_json
        def nft():
            data = original(); data["nftables"][2:2] = copy.deepcopy(extras); return data
        self.system.nft_json = nft
        self.assertFalse(self.platform.inspect()["enabled"])
        self.assertFalse((self.root / ssh.SHARE_STATE).exists())

    def test_share_v2_broadened_or_incomplete_scopes_are_rejected(self):
        for bad in ("unknown-interface", "control-upstream", "hoplimit", "ra-source", "extra-type", "dhcp-source",
                    "wrong-upstream", "global-dns", "wide-dns", "wrong-dns-target", "wrong-port",
                    "order", "missing-rule", "duplicate-rule", "dns6-without-dns4"):
            data = self.share_v2_contract()
            rules = data["nftables"]
            ra, nd, errors, mld, control, dns = [rules[i]["rule"] for i in (4, 5, 6, 7, 9, 10)]
            if bad == "unknown-interface":
                external = set()
            else:
                external = {"wlan0"}
            if bad == "control-upstream":
                ra["expr"][0]["match"]["right"] = "ctrl0"
            elif bad == "hoplimit":
                ra["expr"][2]["match"]["right"] = 64
            elif bad == "ra-source":
                ra["expr"][1]["match"]["right"]["prefix"]["len"] = 0
            elif bad == "extra-type":
                errors["expr"][1]["match"]["right"]["set"].append(128)
            elif bad == "dhcp-source":
                rules[8]["rule"]["expr"][2]["match"]["right"] = 53
            elif bad == "wrong-upstream":
                nd["expr"][0]["match"]["right"] = "eth0"
            elif bad == "global-dns":
                dns["expr"][1]["match"]["right"]["prefix"]["addr"] = "2001:db8::"
            elif bad == "wide-dns":
                dns["expr"][1]["match"]["right"]["prefix"]["len"] = 48
            elif bad == "wrong-dns-target":
                dns["expr"][2]["match"]["right"] = "fd78:1234:5678:9abc::2"
            elif bad == "wrong-port":
                dns["expr"][3]["match"]["right"] = 22
            elif bad == "order":
                rules[4:6] = reversed(rules[4:6])
            elif bad == "missing-rule":
                rules.pop(7)
            elif bad == "duplicate-rule":
                rules.insert(9, copy.deepcopy(rules[4]))
            elif bad == "dns6-without-dns4":
                del rules[2:4]
            with self.subTest(bad=bad), self.assertRaises(ssh.Error):
                ssh.live_ssh_handle(data, external)

    def test_native_conntrack_states_accept_equivalent_order_only(self):
        native = self.native_firewall()
        match = native["nftables"][3]["rule"]["expr"][0]["match"]
        match["right"] = ["related", "established"]
        self.assertEqual(ssh.live_ssh_handle(native), 12)
        for states in (["established", "related", "new"], ["established", "new"],
                       ["established", "invalid"], ["established", "established"],
                       ["established"], ["related", {"set": ["established"]}]):
            with self.subTest(states=states):
                match["right"] = states
                with self.assertRaisesRegex(ssh.Error, "live input chain"):
                    ssh.live_ssh_handle(native)

    def test_native_state_array_is_not_generalized_to_other_expressions(self):
        native = self.native_firewall()
        match = native["nftables"][3]["rule"]["expr"][0]["match"]
        match["left"] = {"meta": {"key": "iifname"}}
        with self.assertRaisesRegex(ssh.Error, "live input chain"):
            ssh.live_ssh_handle(native)

    def test_enable_is_control_only_and_keeps_loopback(self):
        state, changed = self.platform.change(True)
        self.assertTrue(changed)
        self.assertTrue(state["enabled"])
        self.assertEqual((self.root / ssh.CONFIG).read_text().count("127.0.0.1:2222"), 1)
        self.assertTrue(self.system.unit_dependency)
        nft_writes = [text for args, text in self.system.calls if args == ["nft", "--file", "-"]]
        self.assertEqual(nft_writes, ['add rule inet pi4 input iifname "ctrl0" tcp dport 22 accept\n'])
        self.assertFalse(any("restart" in args or "stop" in args for args, _ in self.system.calls))
        self.assertEqual(os.stat(self.root / ssh.CONFIG).st_mode & 0o777, 0o600)

    def test_disable_removes_only_new_direct_access(self):
        self.platform.change(True)
        self.system.calls.clear()
        state, changed = self.platform.change(False)
        self.assertTrue(changed)
        self.assertFalse(state["enabled"])
        self.assertTrue(self.system.loops)
        self.assertTrue(self.system.unit_dependency)
        self.assertEqual((self.root / ssh.CONFIG).read_text(), ssh.CONFIG_OFF)
        nft_writes = [text for args, text in self.system.calls if args == ["nft", "--file", "-"]]
        self.assertEqual(nft_writes, ["delete rule inet pi4 input handle 17\n"])
        self.assertFalse(any("conntrack" in args or "restart" in args or "stop" in args for args, _ in self.system.calls))

    def test_both_states_are_idempotent(self):
        self.assertFalse(self.platform.change(False)[1])
        self.assertNoChanges()
        self.platform.change(True)
        self.system.calls.clear()
        before = (self.root / ssh.CONFIG).stat().st_mtime_ns
        self.assertFalse(self.platform.change(True)[1])
        self.assertEqual(before, (self.root / ssh.CONFIG).stat().st_mtime_ns)
        self.assertFalse(any(args[:2] == ["systemctl", "kill"] for args, _ in self.system.calls))

    def test_unknown_persistent_rule_is_rejected(self):
        path = self.root / ssh.FIREWALL
        path.write_text(path.read_text().replace('iifname "lo" accept', 'iifname "eth0" accept'))
        with self.assertRaisesRegex(ssh.Error, "Persistent firewall"):
            self.platform.change(True)
        self.assertNoChanges()

    def test_unknown_live_access_cannot_be_hidden_by_known_rule(self):
        self.system.extra_rules = [[ssh.iif("eth0"), ssh.ALLOW]]
        with self.assertRaisesRegex(ssh.Error, "live input chain"):
            self.platform.change(True)
        self.assertNoChanges()

    def test_unknown_sshd_include_is_rejected(self):
        path = self.root / ssh.CONFIG
        path.write_text(path.read_text() + "Include /etc/ssh/custom.conf\n")
        with self.assertRaisesRegex(ssh.Error, "Unsupported SSH configuration"):
            self.platform.change(True)
        self.assertFalse(any(args[:2] == ["systemctl", "kill"] for args, _ in self.system.calls))

    def test_changed_security_option_is_rejected(self):
        path = self.root / ssh.CONFIG
        path.write_text(path.read_text().replace("PermitRootLogin no", "PermitRootLogin yes"))
        with self.assertRaisesRegex(ssh.Error, "Unsupported SSH configuration"):
            self.platform.change(True)

    def test_unknown_loaded_override_is_rejected(self):
        self.system.dropins = "/etc/systemd/system/pi4-shell.service.d/custom.conf"
        with self.assertRaisesRegex(ssh.Error, "overrides"):
            self.platform.change(True)
        self.assertNoChanges()

    def test_symlink_and_group_writable_configuration_are_rejected(self):
        path = self.root / ssh.CONFIG
        path.chmod(0o620)
        with self.assertRaisesRegex(ssh.Error, "Unsafe ownership"):
            self.platform.change(True)
        path.chmod(0o600)
        original = path.with_name("saved")
        path.rename(original)
        path.symlink_to(original)
        with self.assertRaisesRegex(ssh.Error, "symlink"):
            self.platform.change(True)

    def test_missing_control_interface_does_not_enable_ssh(self):
        self.system.ctrl = False
        with self.assertRaisesRegex(ssh.Error, "Control interface"):
            self.platform.change(True)
        self.assertNoChanges()

    def test_disable_works_when_control_interface_disappears(self):
        self.platform.change(True)
        self.system.ctrl = False
        self.assertFalse(self.platform.change(False)[0]["enabled"])

    def test_unexpected_ipv6_listener_is_rejected(self):
        self.system.extra_listener = "[::]:22"
        with self.assertRaisesRegex(ssh.Error, "unexpected process or address"):
            self.platform.change(True)
        self.assertNoChanges()

    def test_no_loopback_listener_is_rejected(self):
        self.system.loops = False
        with self.assertRaisesRegex(ssh.Error, "Guacamole loopback"):
            self.platform.change(True)
        self.assertNoChanges()

    def test_persistent_runtime_drift_is_not_silently_repaired(self):
        self.system.enabled = True
        with self.assertRaisesRegex(ssh.Error, "Persistent and running"):
            self.platform.change(False)
        self.assertNoChanges()

    def test_candidate_validation_failure_changes_nothing(self):
        for failure in ("sshd-check", "nft-check"):
            with self.subTest(failure=failure):
                self.system.fail = failure
                with self.assertRaises(ssh.Error):
                    self.platform.change(True)
                self.assertNoChanges()
                self.assertFalse(list(self.root.rglob(".auto-ssh-*")))

    def test_live_rule_failure_rolls_back_all_files(self):
        self.system.fail = "nft-apply-once"
        with self.assertRaisesRegex(ssh.Error, "previous state restored"):
            self.platform.change(True)
        self.assertFalse(self.system.enabled)
        self.assertFalse(self.system.listener)
        self.assertEqual((self.root / ssh.CONFIG).read_text(), ssh.CONFIG_OFF)
        self.assertEqual((self.root / ssh.FIREWALL).read_text(), ssh.FIREWALL_OFF)
        self.assertEqual((self.root / ssh.UNIT).read_text(), ssh.UNIT_OFF)

    def test_hup_failure_restores_firewall_and_configuration(self):
        self.system.fail = "hup-once"
        with self.assertRaisesRegex(ssh.Error, "previous state restored"):
            self.platform.change(True)
        self.assertFalse(self.platform.inspect()["enabled"])
        self.assertFalse(self.system.unit_dependency)

    def test_failed_rollback_is_explicit(self):
        self.system.fail = "hup-always"
        with self.assertRaisesRegex(ssh.Error, "Rollback incomplete"):
            self.platform.change(True)

    def test_failure_after_atomic_replace_still_restores_file(self):
        original = self.platform.atomic_write
        raised = False

        def write(path, text, **kwargs):
            nonlocal raised
            original(path, text, **kwargs)
            if path == ssh.CONFIG and not raised:
                raised = True
                raise OSError("simulated directory fsync error")

        self.platform.atomic_write = write
        with self.assertRaisesRegex(ssh.Error, "previous state restored"):
            self.platform.change(True)
        self.assertEqual((self.root / ssh.CONFIG).read_text(), ssh.CONFIG_OFF)

    def test_keyboard_interrupt_after_write_restores_previous_state(self):
        original = self.platform.atomic_write
        raised = False

        def write(path, text, **kwargs):
            nonlocal raised
            original(path, text, **kwargs)
            if path == ssh.CONFIG and not raised:
                raised = True
                raise KeyboardInterrupt()

        self.platform.atomic_write = write
        with self.assertRaisesRegex(ssh.Error, "previous state restored: Operation interrupted"):
            self.platform.change(True)
        self.assertFalse(self.platform.inspect()["enabled"])
        self.assertEqual((self.root / ssh.UNIT).read_text(), ssh.UNIT_OFF)

    def test_rollback_does_not_overwrite_concurrent_edit(self):
        original = self.platform.hup
        raised = False
        attempts = 0
        marker = ssh.CONFIG_OFF + "# external administrator edit\n"

        def hup():
            nonlocal raised, attempts
            attempts += 1
            if not raised:
                raised = True
                (self.root / ssh.CONFIG).write_text(marker)
                raise ssh.Error("Concurrent edit during HUP")
            original()

        self.platform.hup = hup
        with self.assertRaisesRegex(ssh.Error, "Rollback incomplete.*Concurrent external edit"):
            self.platform.change(True)
        self.assertEqual((self.root / ssh.CONFIG).read_text(), marker)
        self.assertEqual(attempts, 1, "Rollback must not HUP an externally edited SSH configuration")

    def test_rollback_checks_restored_sshd_config_before_hup(self):
        attempts = 0

        def hup():
            nonlocal attempts
            attempts += 1
            self.system.fail = "sshd-check"
            raise ssh.Error("Initial HUP failed")

        self.platform.hup = hup
        with self.assertRaisesRegex(ssh.Error, "Rollback incomplete.*restore SSH listeners: sshd candidate rejected"):
            self.platform.change(True)
        self.assertEqual(attempts, 1)
        self.assertEqual((self.root / ssh.CONFIG).read_text(), ssh.CONFIG_OFF)

    def test_rollback_never_reloads_concurrently_edited_unit(self):
        attempts = 0
        marker = ssh.UNIT_ON + "# concurrent administrator unit change\n"

        def hup():
            nonlocal attempts
            attempts += 1
            (self.root / ssh.UNIT).write_text(marker)
            raise ssh.Error("Initial HUP failed after external unit change")

        self.platform.hup = hup
        with self.assertRaisesRegex(ssh.Error, "Rollback incomplete.*daemon-reload was skipped"):
            self.platform.change(True)
        self.assertEqual((self.root / ssh.UNIT).read_text(), marker)
        self.assertEqual(attempts, 1)
        reloads = [args for args, _ in self.system.calls if args == ["systemctl", "daemon-reload"]]
        self.assertEqual(len(reloads), 1, "Only the initial validated unit may be loaded")

    def test_atomic_write_preserves_ownership_and_mode(self):
        before = (self.root / ssh.CONFIG).stat()
        self.platform.atomic_write(ssh.CONFIG, ssh.CONFIG_OFF)
        after = (self.root / ssh.CONFIG).stat()
        self.assertEqual((after.st_uid, after.st_gid, after.st_mode), (before.st_uid, before.st_gid, before.st_mode))

    def test_atomic_write_checks_expected_content(self):
        with self.assertRaisesRegex(ssh.Error, "Concurrent external edit"):
            self.platform.atomic_write(ssh.CONFIG, ssh.config_text(True), expected="different previous text")
        self.assertEqual((self.root / ssh.CONFIG).read_text(), ssh.CONFIG_OFF)

    def test_atomic_write_detects_edit_during_staging(self):
        path = self.root / ssh.CONFIG
        external = ssh.CONFIG_OFF + "# concurrent edit\n"
        with patch.object(ssh.os, "fsync", side_effect=lambda fd: path.write_text(external)):
            with self.assertRaisesRegex(ssh.Error, "before replacing"):
                self.platform.atomic_write(ssh.CONFIG, ssh.config_text(True), expected=ssh.CONFIG_OFF)
        self.assertEqual(path.read_text(), external)
        self.assertFalse(list(path.parent.glob(".auto-ssh-*")))

    def test_safe_lock_serializes_operations(self):
        with self.platform.lock():
            with self.assertRaisesRegex(ssh.Error, "Another SSH control"):
                with self.platform.lock():
                    pass

    def test_lock_does_not_follow_symlink(self):
        (self.root / "run/automations-ssh.lock").symlink_to(self.root / ssh.CONFIG)
        with self.assertRaises(OSError):
            with self.platform.lock():
                pass
        self.assertEqual((self.root / ssh.CONFIG).read_text(), ssh.CONFIG_OFF)

    def test_status_reports_actual_interfaces(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            ssh.print_status(self.platform.inspect())
        self.assertIn("Direct SSH: disabled", output.getvalue())
        self.assertIn("Interface ctrl0: UP, 10.78.0.1/24", output.getvalue())
        self.assertIn("Interface wlan0: DOWN, no address", output.getvalue())
        self.assertNoChanges()

    def test_help_needs_no_root_and_actions_are_exclusive(self):
        with patch.object(ssh.os, "geteuid", return_value=1000), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit) as result:
                ssh.main(["--help"])
            self.assertEqual(result.exception.code, 0)
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as result:
                ssh.main(["--on", "--off"])
            self.assertEqual(result.exception.code, 2)

    def test_bare_command_is_status_and_nonroot_is_clear(self):
        with patch.object(ssh, "Platform", return_value=self.platform), patch.object(ssh.os, "geteuid", return_value=0), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(ssh.main([]), 0)
        self.assertNoChanges()
        output = io.StringIO()
        with patch.object(ssh.os, "geteuid", return_value=1000), contextlib.redirect_stderr(output):
            self.assertEqual(ssh.main(["--on"]), 1)
        self.assertIn("ERROR: Root privileges", output.getvalue())

    def test_off_purge_error_never_reopens_direct_access(self):
        self.platform.change(True)
        with patch.object(self.platform.transports, "terminate", side_effect=ssh.Error("unknown monitor")):
            with self.assertRaisesRegex(ssh.Error, "New direct SSH connections remain blocked.*could not all be terminated"):
                self.platform.turn_off()
        self.assertFalse(self.platform.inspect()["enabled"])
        self.assertTrue(self.system.loops)

    def test_worker_sigterm_before_purge_uses_existing_rollback(self):
        self.platform.change(True)
        original = self.platform.hup
        interrupted = False

        def hup():
            nonlocal interrupted
            if not interrupted:
                interrupted = True
                ssh.interrupt_worker(signal.SIGTERM, None)
            original()

        with patch.object(self.platform, "hup", side_effect=hup), \
             patch.object(self.platform.transports, "terminate") as terminate:
            with self.assertRaisesRegex(ssh.Error, "previous state restored.*worker was interrupted"):
                self.platform.turn_off()
        terminate.assert_not_called()
        self.assertTrue(self.platform.inspect()["enabled"])

    def test_worker_sigterm_during_purge_leaves_off(self):
        self.platform.change(True)
        with patch.object(self.platform.transports, "terminate",
                          side_effect=lambda _: ssh.interrupt_worker(signal.SIGTERM, None)):
            with self.assertRaisesRegex(ssh.Error, "New direct SSH connections remain blocked.*worker was interrupted"):
                self.platform.turn_off()
        self.assertFalse(self.platform.inspect()["enabled"])

    def test_already_off_still_attempts_purge(self):
        with patch.object(self.platform.transports, "terminate", return_value=0) as terminate:
            state, changed = self.platform.turn_off()
        terminate.assert_called_once_with(123)
        self.assertFalse(changed or state["enabled"])

    def test_off_worker_holds_lock_through_purge(self):
        guard = ("Transient=yes\nUser=root\nGroup=root\nControlGroup=/system.slice/" + ssh.OFF_SERVICE +
                 "\nStandardInput=null\nStandardOutput=journal\nStandardError=journal\nExecStart={ argv[]=/usr/bin/python3 -I " +
                 ssh.RUNTIME + " --internal-off ; }")
        (self.root / "proc/self").mkdir()
        (self.root / "proc/self/cgroup").write_text("0::/system.slice/" + ssh.OFF_SERVICE + "\n")
        original = self.platform.run
        self.platform.run = lambda args, *rest: guard if args[:3] == ["systemctl", "show", ssh.OFF_SERVICE] else original(args, *rest)

        def purge(pid):
            with self.assertRaisesRegex(ssh.Error, "Another SSH control"):
                with self.platform.lock():
                    self.platform.change(True)
            return 0

        with patch.object(self.platform.transports, "terminate", side_effect=purge), contextlib.redirect_stdout(io.StringIO()):
            ssh.off_worker(self.platform)
        (self.root / "proc/self/cgroup").write_text("0::/user.slice/session-1.scope\n")
        with self.assertRaisesRegex(ssh.Error, "fixed root systemd worker"):
            ssh.off_worker(self.platform)

    def test_request_off_waits_without_caller_lock_and_uses_fixed_independent_worker(self):
        runtime = self.root / ssh.RUNTIME.lstrip("/")
        runtime.parent.mkdir(parents=True)
        runtime.write_text("fixed test runtime")
        runtime.chmod(0o755)

        def run(args, **kwargs):
            with self.platform.lock():
                pass  # Caller must not hold this lock while the worker runs.
            self.assertEqual(args[-4:], ["/usr/bin/python3", "-I", ssh.RUNTIME, "--internal-off"])
            for flag in ("--wait", "--unit=" + ssh.OFF_SERVICE, "--property=StandardInput=null",
                         "--property=StandardOutput=journal", "--property=User=root"):
                self.assertIn(flag, args)
            self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
            self.assertGreater(kwargs["timeout"], 15)
            return subprocess.CompletedProcess(args, 0, "", "")

        with patch.object(ssh.subprocess, "run", side_effect=run):
            self.assertFalse(ssh.request_off(self.platform)["enabled"])

    def test_caller_interrupt_does_not_stop_worker_or_reenable(self):
        with patch.object(self.platform, "read", return_value="validated runtime"), \
             patch.object(ssh.subprocess, "run", side_effect=KeyboardInterrupt()):
            with self.assertRaisesRegex(ssh.Error, "may still be running independently"):
                ssh.request_off(self.platform)
        self.assertFalse(self.platform.inspect()["enabled"])
        self.assertFalse(any("stop" in args for args, _ in self.system.calls))


class TransportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.proc = Path(self.temporary.name)
        (self.proc / "net").mkdir()
        self.rows = {"458927": ("01004E0A:0016", "37004E0A:D8DA", "01"),
                     "251254": ("0100007F:08AE", "0100007F:9D9E", "01"),
                     "777": ("01004E0A:C001", "02004E0A:0016", "01")}
        self.write_sockets()
        self.make_process(5591, 1, 0, 100, "/usr/sbin/sshd", ())
        self.make_process(148095, 5591, 0, 1890470, ssh.SESSION_EXE, ("458927",))
        self.make_process(148103, 148095, 1000, 1890504, ssh.SESSION_EXE, ("458927",))
        self.make_process(87248, 5591, 0, 1372987, ssh.SESSION_EXE, ("251254",))
        self.signals, self.closed = [], []
        self.transport = ssh.DirectTransports(self.proc, opener=lambda pid, flags: pid,
            signaler=self.send, closer=self.closed.append, sleeper=lambda _: None)

    def make_process(self, pid, ppid, uid, start, exe, inodes):
        path = self.proc / str(pid)
        (path / "fd").mkdir(parents=True, exist_ok=True)
        fields = ["S", str(ppid), *(["0"] * 17), str(start)]
        (path / "stat").write_text(str(pid) + " (sshd-session) " + " ".join(fields))
        (path / "status").write_text("Uid:\t" + "\t".join([str(uid)] * 4) + "\n")
        (path / "cmdline").write_bytes(b"sshd-session: kali [postauth]\0")
        (path / "exe").symlink_to(exe)
        for index, inode in enumerate(inodes):
            (path / "fd" / str(index + 7)).symlink_to("socket:[" + inode + "]")

    def write_sockets(self):
        head = "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
        data = "".join(f"0: {local} {remote} {state} 0:0 0:0 0 0 0 {inode}\n"
                       for inode, (local, remote, state) in self.rows.items())
        (self.proc / "net/tcp").write_text(head + data)
        (self.proc / "net/tcp6").write_text(head)

    def send(self, handle, sig, info, flags):
        self.signals.append((handle, sig))
        self.rows.pop("458927", None)
        self.write_sockets()

    def test_only_exact_direct_root_monitor_is_signaled_and_verified(self):
        self.assertEqual(self.transport.terminate(5591), 1)
        self.assertEqual(self.signals, [(148095, signal.SIGTERM)])
        self.assertEqual(self.closed, [148095])
        self.assertIn("251254", self.rows)
        self.assertIn("777", self.rows)  # outgoing remote port 22 is untouched

    def test_wrong_monitor_identity_or_protected_socket_is_never_signaled(self):
        path = self.proc / "148095"
        for mismatch in ("exe", "uid", "ppid", "title", "protected"):
            with self.subTest(mismatch=mismatch):
                backups = {name: (path / name).read_bytes() for name in ("stat", "status", "cmdline")}
                if mismatch == "exe":
                    (path / "exe").unlink()
                    (path / "exe").symlink_to("/usr/bin/unrelated")
                elif mismatch == "uid":
                    (path / "status").write_text("Uid:\t1000\t1000\t1000\t1000\n")
                elif mismatch == "ppid":
                    (path / "stat").write_text(backups["stat"].decode().replace("S 5591", "S 1"))
                elif mismatch == "title":
                    (path / "cmdline").write_bytes(b"unrelated\0")
                else:
                    (path / "fd/8").symlink_to("socket:[251254]")
                with self.assertRaises(ssh.Error):
                    self.transport.terminate(5591)
                self.assertEqual(self.signals, [])
                for name, value in backups.items():
                    (path / name).write_bytes(value)
                if mismatch == "exe":
                    (path / "exe").unlink()
                    (path / "exe").symlink_to(ssh.SESSION_EXE)
                if mismatch == "protected":
                    (path / "fd/8").unlink()

    def test_pid_reuse_after_pidfd_open_is_rejected(self):
        def open_pid(pid, flags):
            path = self.proc / str(pid) / "stat"
            path.write_text(path.read_text().replace("1890470", "1890999"))
            return pid
        self.transport.open = open_pid
        with self.assertRaisesRegex(ssh.Error, "changed while obtaining pidfd"):
            self.transport.terminate(5591)
        self.assertEqual(self.signals, [])
        self.assertEqual(self.closed, [148095])

    def test_pidfd_esrch_requires_socket_disappearance(self):
        def gone(*args):
            self.rows.pop("458927")
            self.write_sockets()
            raise ProcessLookupError()
        self.transport.signal = gone
        self.assertEqual(self.transport.terminate(5591), 1)

    def test_remaining_transport_is_a_failure_without_escalating_to_global_kill(self):
        self.transport.signal = lambda handle, sig, *_: self.signals.append((handle, sig))
        with self.assertRaisesRegex(ssh.Error, "transport.*remain"):
            self.transport.terminate(5591)
        self.assertEqual(self.signals, [(148095, signal.SIGTERM)])

    def test_signal_failure_closes_pidfds(self):
        self.transport.signal = lambda *_: (_ for _ in ()).throw(PermissionError("denied"))
        with self.assertRaises(PermissionError):
            self.transport.terminate(5591)
        self.assertEqual(self.closed, [148095])

    def test_missing_socket_owner_fails_without_signaling(self):
        (self.proc / "148095/fd/7").unlink()
        with self.assertRaisesRegex(ssh.Error, "verified monitor"):
            self.transport.terminate(5591)
        self.assertEqual(self.signals, [])

    def test_listener_and_time_wait_are_not_counted_as_connections(self):
        self.rows = {"5": ("00000000:0016", "00000000:0000", "0A"),
                     "0": ("01004E0A:0016", "37004E0A:D8DA", "06")}
        self.write_sockets()
        self.assertEqual(self.transport.sockets()[0], {})


if __name__ == "__main__":
    unittest.main()
