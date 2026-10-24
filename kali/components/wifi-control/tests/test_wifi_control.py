import copy
from contextlib import nullcontext
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("auto_wifi", ROOT / "python/auto_wifi.py")
wifi = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(wifi)
OLD = "11111111-1111-4111-8111-111111111111"
NEW = "22222222-2222-4222-8222-222222222222"


class MemoryPolicy:
    def __init__(self):
        self.approved = {OLD}
    def locked(self):
        return nullcontext(self)
    def enabled(self, identifier):
        return identifier in self.approved
    def set(self, identifier, enabled):
        (self.approved.add if enabled else self.approved.discard)(identifier)


class Hardware:
    def __init__(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "sys"
        (self.root / "class/net").mkdir(parents=True)
        (self.root / "bus/usb").mkdir(parents=True)
        self.states = {}
        self.add("ctrl0", phy=0, index=3, usb=False, mode="AP", managed=False)
        self.add("wlan0", phy=2, index=5, usb=True)

    def close(self):
        self.temp.cleanup()

    def add(self, name, *, phy, index, usb=True, mode="managed", managed=True, shared=None):
        if shared:
            existing = wifi.inventory(self.root)[shared]
            device = Path(existing.device_path)
            phy_path = Path(existing.phy_path)
        elif usb:
            parent = self.root / f"devices/usb1/1-{index}"
            device = parent / f"1-{index}:1.0"
            device.mkdir(parents=True)
            (parent / "idVendor").write_text("148f\n")
            (parent / "idProduct").write_text("3572\n")
            (parent / "subsystem").symlink_to(self.root / "bus/usb")
            phy_path = device / f"ieee80211/phy{phy}"
        else:
            device = self.root / f"devices/platform/internal-{index}"
            device.mkdir(parents=True)
            phy_path = device / f"ieee80211/phy{phy}"
        phy_path.mkdir(parents=True, exist_ok=True)
        net = self.root / "class/net" / name
        net.mkdir()
        (net / "device").symlink_to(device)
        (net / "phy80211").symlink_to(phy_path)
        (net / "ifindex").write_text(str(index))
        self.states[name] = dict(mode=mode, up=True, managed=managed, autoconnect=True,
                                 nm_state=30 if managed else 10, connection=None)
        return wifi.inventory(self.root)[name]


class FakeRunner:
    def __init__(self, hardware):
        self.hardware = hardware
        self.calls = []
        self.mutations = []
        self.saved = {"Saved Net": OLD}
        self.prompt_count = 0
        self.mode_support = {"managed", "monitor"}
        self.fail_once = None
        self.connect_error = None
        self.after_connect = None

    def __call__(self, args, *, interactive=False):
        self.calls.append((args, interactive))
        devices = wifi.inventory(self.hardware.root)
        if args[0] == "iw" and args[-1] == "info":
            if args[1] == "phy":
                return "Wiphy " + args[2] + "\n\tSupported interface modes:\n" + "".join(
                    "\t\t* " + mode + "\n" for mode in sorted(self.mode_support)) + "\tBand 1:\n"
            name = args[2]
            adapter, state = devices[name], self.hardware.states[name]
            return (f"Interface {name}\n\tifindex {adapter.index}\n\ttype {state['mode']}\n"
                    f"\twiphy {adapter.phy[3:]}\n")
        if args[0] == "nmcli" and args[-3:-1] == ["device", "show"]:
            name = args[-1]
            state = self.hardware.states[name]
            return "\n".join([
                f"GENERAL.DEVICE:{name}", "GENERAL.TYPE:wifi",
                f"GENERAL.STATE:{state['nm_state']} (state)",
                "GENERAL.NM-MANAGED:" + ("yes" if state["managed"] else "no"),
                "GENERAL.AUTOCONNECT:" + ("yes" if state["autoconnect"] else "no"),
                "GENERAL.CON-UUID:" + (state["connection"] or ""),
            ]) + "\n"
        if args[:4] == ["ip", "-json", "address", "show"]:
            name = args[-1]
            return json.dumps([{"ifname": name, "ifindex": devices[name].index,
                                "operstate": self.hardware.states[name].get("operstate", "UNKNOWN"),
                                "flags": ["UP"] if self.hardware.states[name]["up"] else []}])
        if "802-11-wireless.ssid" in args:
            return next(name for name, identifier in self.saved.items() if identifier == args[-1]) + "\n"
        if "wifi" in args and "list" in args:
            return "00:11:22:33:44:55\n"
        self.mutations.append(args)
        if self.fail_once and self.fail_once(args):
            self.fail_once = None
            raise wifi.Error("injected native failure")
        if args[0] == "nmcli" and "device" in args:
            offset = args.index("device")
            action = args[offset + 1]
            if action == "set":
                name, field, value = args[offset + 2:offset + 5]
                assert name != "ctrl0"
                state = self.hardware.states[name]
                state[field] = value == "yes"
                if field == "managed":
                    state["connection"] = None
                    state["nm_state"] = 30 if state["managed"] else 10
                return ""
            if action == "disconnect":
                name = args[-1]
                assert name != "ctrl0"
                self.hardware.states[name].update(connection=None, autoconnect=False, nm_state=30)
                return ""
            if action == "wifi":
                assert args[offset + 2] == "connect"
                ssid = args[offset + 3]
                name = args[-1]
                assert name != "ctrl0"
                state = self.hardware.states[name]
                state.update(connection=None, nm_state=30)
                if ssid not in self.saved:
                    if not interactive:
                        raise wifi.Error("No saved secret and no interactive terminal.")
                    self.prompt_count += 1
                    self.saved[ssid] = NEW
                if self.connect_error:
                    failure = self.connect_error
                    self.connect_error = None
                    raise failure
                # Native NM 1.56.1 explicit connect preserves device autoconnect.
                state.update(connection=self.saved[ssid], nm_state=100, up=True)
                if self.after_connect:
                    self.after_connect()
                return ""
        if args[0] == "nmcli" and "connection" in args and "up" in args:
            name, identifier = args[-1], args[args.index("uuid") + 1]
            assert name != "ctrl0"
            self.hardware.states[name].update(connection=identifier, nm_state=100, up=True)
            return ""
        if args[:4] == ["ip", "link", "set", "dev"]:
            name = args[4]
            assert name != "ctrl0"
            state = self.hardware.states[name]
            state["up"] = args[5] == "up"
            if not state["up"]:
                state["connection"] = None
                state["nm_state"] = 30 if state["managed"] else 10
            return ""
        if args[0] == "iw" and args[3:5] == ["set", "type"]:
            name = args[2]
            assert name != "ctrl0"
            state = self.hardware.states[name]
            assert not state["up"]
            state["mode"] = args[5]
            return ""
        if args[:4] == ["nmcli", "connection", "modify", "uuid"]:
            assert args[5:] == ["connection.autoconnect", "no"]
            self.mutations.append(args)
            return ""
        raise AssertionError(args)


class Base(unittest.TestCase):
    def setUp(self):
        self.hardware = Hardware()
        self.runner = FakeRunner(self.hardware)
        self.platform = wifi.Platform(root=self.hardware.root, lock=Path(self.hardware.temp.name) / "wifi.lock",
                                      runner=self.runner, sleeper=lambda delay: None, policy=MemoryPolicy())
        self.adapter = wifi.inventory(self.hardware.root)["wlan0"]

    def tearDown(self):
        self.hardware.close()

    def connected(self, identifier=OLD):
        self.hardware.states["wlan0"].update(connection=identifier, nm_state=100)
        return self.platform.read_state(self.adapter)

    def assert_control_untouched(self):
        self.assertTrue(self.hardware.states["ctrl0"]["up"])
        self.assertEqual(self.hardware.states["ctrl0"]["mode"], "AP")
        for arguments in self.runner.mutations:
            self.assertNotIn("ctrl0", arguments)
            self.assertNotIn("radio", arguments)
            self.assertNotIn("networking", arguments)
            self.assertNotIn("delete", arguments)
            self.assertNotIn("show-password", arguments)
            self.assertNotIn("--show-secrets", arguments)
            self.assertNotIn("password", arguments)


class DiscoveryTests(Base):
    def test_usb_external_selected_and_control_excluded(self):
        selected = wifi.select_adapter(wifi.inventory(self.hardware.root))
        self.assertEqual(selected.name, "wlan0")
        self.assertEqual(selected.usb_id, "148f:3572")

    def test_control_cannot_be_explicitly_selected(self):
        with self.assertRaisesRegex(wifi.Error, "protected"):
            wifi.select_adapter(wifi.inventory(self.hardware.root), "ctrl0")
        self.assertFalse(self.runner.mutations)

    def test_internal_named_wlan_is_never_external(self):
        self.hardware.add("wlan1", phy=3, index=6, usb=False)
        candidates = wifi.external_adapters(wifi.inventory(self.hardware.root))
        self.assertEqual(set(candidates), {"wlan0"})

    def test_usb_control_radio_alias_is_protected(self):
        self.hardware.add("alias0", phy=0, index=7, shared="ctrl0")
        candidates = wifi.external_adapters(wifi.inventory(self.hardware.root))
        self.assertNotIn("alias0", candidates)

    def test_protect_entire_phy_even_if_control_is_usb(self):
        self.hardware.add("usbcontrol", phy=2, index=7, shared="wlan0")
        devices = wifi.inventory(self.hardware.root)
        devices["ctrl0"] = devices["usbcontrol"]._replace(name="ctrl0")
        with self.assertRaises(wifi.Error):
            wifi.select_adapter(devices, "wlan0")

    def test_multiple_adapters_require_interface(self):
        self.hardware.add("wlxabcdef", phy=4, index=8)
        devices = wifi.inventory(self.hardware.root)
        with self.assertRaisesRegex(wifi.Error, "Multiple"):
            wifi.select_adapter(devices)
        self.assertEqual(wifi.select_adapter(devices, "wlxabcdef").name, "wlxabcdef")

    def test_no_external_interface_is_clear_error(self):
        devices = wifi.inventory(self.hardware.root)
        del devices["wlan0"]
        with self.assertRaisesRegex(wifi.Error, "No external"):
            wifi.select_adapter(devices)

    def test_missing_control_identity_fails_closed(self):
        devices = wifi.inventory(self.hardware.root)
        del devices["ctrl0"]
        with self.assertRaisesRegex(wifi.Error, "ctrl0"):
            wifi.select_adapter(devices)

    def test_replaced_interface_identity_is_not_modified(self):
        (self.hardware.root / "class/net/wlan0/ifindex").write_text("99")
        with self.assertRaisesRegex(wifi.Error, "changed"):
            self.platform.off(self.adapter)
        self.assertFalse(self.runner.mutations)

    def test_shared_external_phy_cannot_be_changed(self):
        self.hardware.add("monitor0", phy=2, index=8, shared="wlan0", mode="monitor", managed=False)
        with self.assertRaisesRegex(wifi.Error, "shares"):
            self.platform.change_mode(self.adapter, "monitor")
        self.assertFalse(self.runner.mutations)
        self.assertEqual(self.platform.read_state(self.adapter).mode, "managed")

    def test_iw_identity_mismatch_is_rejected(self):
        with self.assertRaisesRegex(wifi.Error, "identity"):
            wifi.parse_iw("Interface wlan0\n\tifindex 100\n\twiphy 2\n\ttype managed\n", self.adapter)

    def test_invalid_usb_ancestry_is_rejected(self):
        device = Path(self.adapter.device_path)
        (device.parent / "idProduct").write_text("broken")
        with self.assertRaisesRegex(wifi.Error, "USB"):
            wifi.inventory(self.hardware.root)


class ConnectionTests(Base):
    def test_manual_reconnect_after_off_retains_disabled_device_autoconnect(self):
        self.connected()
        self.platform.off(self.adapter)
        self.runner.mutations.clear()
        state = self.platform.connect(self.adapter, "Saved Net", False)
        self.assertEqual(state.connection, OLD)
        self.assertEqual(state.ssid, "Saved Net")
        self.assertEqual(state.nm_state, 100)
        self.assertFalse(state.autoconnect)
        self.assertEqual(self.runner.prompt_count, 0)
        self.assertEqual(self.runner.saved, {"Saved Net": OLD})
        self.assertFalse(any("autoconnect" in args for args in self.runner.mutations))
        self.assert_control_untouched()

    def test_new_ssid_uses_native_hidden_agent_not_password_arguments(self):
        state = self.platform.connect(self.adapter, "New Net", True)
        self.assertEqual(state.connection, NEW)
        self.assertEqual(self.runner.prompt_count, 1)
        calls = [(args, interactive) for args, interactive in self.runner.calls if "connect" in args]
        self.assertEqual(calls[-1], (["nmcli", "--colors", "no", "--wait", "90", "--ask",
                                     "device", "wifi", "connect", "New Net", "ifname", "wlan0"], True))
        self.assert_control_untouched()

    def test_saved_secret_reused_without_new_profile(self):
        state = self.platform.connect(self.adapter, "Saved Net", True)
        self.assertEqual(state.connection, OLD)
        self.assertEqual(self.runner.prompt_count, 0)
        self.assertEqual(self.runner.saved, {"Saved Net": OLD})
        self.assert_control_untouched()

    def test_manual_connect_without_optin_disables_only_profile_bit(self):
        self.platform.policy().approved.clear()
        state = self.platform.connect(self.adapter, "Saved Net", True)
        self.assertEqual(state.connection, OLD)
        self.assertEqual(self.runner.saved, {"Saved Net": OLD})
        self.assertEqual(self.runner.mutations[-1], ["nmcli", "connection", "modify", "uuid", OLD,
                                                    "connection.autoconnect", "no"])
        self.assertEqual(self.runner.prompt_count, 0)

    def test_existing_connection_switches_to_requested_ssid(self):
        self.connected()
        state = self.platform.connect(self.adapter, "New Net", True)
        self.assertEqual(state.connection, NEW)
        self.assertIn("Saved Net", self.runner.saved)
        self.assert_control_untouched()

    def test_ssid_shell_metacharacters_stay_one_argument(self):
        ssid = "test;$(x) \"quoted\""
        self.platform.connect(self.adapter, ssid, True)
        command = next(args for args, _ in self.runner.calls if "connect" in args)
        self.assertIn(ssid, command)
        self.assertNotIn("sh", command)

    def test_noninteractive_saved_credentials_work_without_ask(self):
        self.assertEqual(self.platform.connect(self.adapter, "Saved Net", False).connection, OLD)
        command = next(args for args, _ in self.runner.calls if "connect" in args)
        self.assertNotIn("--ask", command)

    def test_noninteractive_missing_secret_fails_and_restores_old_connection(self):
        old = self.connected()
        with self.assertRaisesRegex(wifi.Error, "Previous adapter state restored"):
            self.platform.connect(self.adapter, "New Net", False)
        self.assertEqual(self.platform.read_state(self.adapter), old)
        self.assertEqual(self.runner.prompt_count, 0)

    def test_failed_switch_restores_previous_uuid_without_prompt(self):
        old = self.connected()
        self.runner.connect_error = wifi.Error("activation failed")
        with self.assertRaisesRegex(wifi.Error, "Previous adapter state restored"):
            self.platform.connect(self.adapter, "New Net", True)
        self.assertEqual(self.platform.read_state(self.adapter), old)
        restores = [args for args, _ in self.runner.calls if "connection" in args and "up" in args]
        self.assertIn(["nmcli", "--wait", "90", "connection", "up", "uuid", OLD, "ifname", "wlan0"], restores)
        self.assert_control_untouched()

    def test_interrupted_switch_restores_previous_connection(self):
        old = self.connected()
        self.runner.connect_error = KeyboardInterrupt()
        with self.assertRaisesRegex(wifi.Error, "interrupted.*restored"):
            self.platform.connect(self.adapter, "New Net", True)
        self.assertEqual(self.platform.read_state(self.adapter), old)

    def test_hotplug_during_failure_never_changes_replacement(self):
        old = self.connected()
        def unplug():
            (self.hardware.root / "class/net/wlan0/ifindex").write_text("100")
            raise wifi.Error("removed")
        self.runner.after_connect = unplug
        with self.assertRaisesRegex(wifi.Error, "could not be fully restored"):
            self.platform.connect(self.adapter, "New Net", True)
        self.assertEqual(len(self.runner.mutations), 1)

    def test_connect_rejects_monitor_before_mutations(self):
        self.hardware.states["wlan0"].update(mode="monitor", managed=False, nm_state=10)
        with self.assertRaisesRegex(wifi.Error, "--managed"):
            self.platform.connect(self.adapter, "Saved Net", True)
        self.assertFalse(self.runner.mutations)

    def test_busy_networkmanager_rejected_before_changes(self):
        self.hardware.states["wlan0"]["nm_state"] = 50
        with self.assertRaisesRegex(wifi.Error, "busy"):
            self.platform.connect(self.adapter, "Saved Net", True)
        self.assertFalse(self.runner.mutations)


class ProfileRunner(FakeRunner):
    def __init__(self, hardware):
        super().__init__(hardware)
        self.profiles = {OLD: self.make_profile()}
        self.after_modify = None
        self.before_read = None
        self.modify_noop = False
        self.protected_active = ""
        self.storage = {}
        self.unsaved = "b false"
        self.profile_flags = "u 0"

    @staticmethod
    def make_profile(ssid="Saved Net", **overrides):
        profile = {"connection.type": "802-11-wireless", "802-11-wireless.ssid": ssid,
                   "connection.interface-name": "wlan0", "802-11-wireless.mode": "infrastructure",
                   "802-11-wireless.mac-address": "", "connection.controller": "",
                   "match.interface-name": "", "match.path": "", "match.driver": "",
                   "match.kernel-command-line": "", "connection.autoconnect": "yes"}
        profile.update(overrides)
        return profile

    def __call__(self, args, *, interactive=False):
        if args[:6] == ["nmcli", "--terse", "--escape", "no", "--fields", "UUID,DBUS-PATH,FILENAME"]:
            self.calls.append((args, interactive))
            return "".join(f"{identifier}:/org/freedesktop/NetworkManager/Settings/{index}:"
                           f"{self.storage.get(identifier, '/etc/NetworkManager/system-connections/' + identifier + '.nmconnection')}\n"
                           for index, identifier in enumerate(self.profiles, 1))
        if args[:3] == ["busctl", "--system", "get-property"]:
            self.calls.append((args, interactive))
            assert args[3] == "org.freedesktop.NetworkManager"
            assert args[5] == "org.freedesktop.NetworkManager.Settings.Connection"
            return (self.unsaved if args[-1] == "Unsaved" else self.profile_flags) + "\n"
        prefix = ["nmcli", "--terse", "--escape", "no", "--get-values"]
        if args[:5] == prefix:
            field = args[5]
            if args[6:] == ["connection", "show"] and field == "UUID":
                self.calls.append((args, interactive))
                return "".join(value + "\n" for value in self.profiles)
            if args[6:9] == ["connection", "show", "uuid"]:
                self.calls.append((args, interactive))
                identifier = args[9]
                if self.before_read:
                    self.before_read(identifier, field)
                if identifier not in self.profiles:
                    raise wifi.Error("profile no longer exists")
                return (identifier if field == "connection.uuid" else self.profiles[identifier][field]) + "\n"
            if args[6:8] == ["device", "show"] and field == "GENERAL.CON-UUID":
                self.calls.append((args, interactive))
                return self.protected_active + "\n"
        if args[:4] == ["nmcli", "connection", "modify", "uuid"]:
            self.calls.append((args, interactive))
            self.mutations.append(args)
            assert args[5] == "connection.autoconnect" and len(args) == 7
            if self.fail_once and self.fail_once(args):
                self.fail_once = None
                raise wifi.Error("injected native failure")
            if not self.modify_noop:
                self.profiles[args[4]][args[5]] = args[6]
            if self.after_modify:
                callback, self.after_modify = self.after_modify, None
                callback()
            return ""
        return super().__call__(args, interactive=interactive)


class ProfileAutoconnectTests(Base):
    def setUp(self):
        super().setUp()
        self.runner = ProfileRunner(self.hardware)
        self.platform.run = self.runner

    def assert_only_bit_changed(self, before, enabled):
        expected = copy.deepcopy(before)
        expected[OLD]["connection.autoconnect"] = "yes" if enabled else "no"
        self.assertEqual(self.runner.profiles, expected)
        self.assertTrue(all(args[:4] == ["nmcli", "connection", "modify", "uuid"]
                            for args in self.runner.mutations))
        self.assert_control_untouched()

    def test_on_and_off_only_change_selected_profile_bit_and_preserve_runtime(self):
        self.connected()
        self.hardware.states["wlan0"]["autoconnect"] = False
        runtime = copy.deepcopy(self.hardware.states)
        before = copy.deepcopy(self.runner.profiles)
        self.runner.profiles[NEW] = self.runner.make_profile("Other SSID")
        before[NEW] = copy.deepcopy(self.runner.profiles[NEW])
        for enabled in (False, True):
            result = self.platform.profile_autoconnect(self.adapter, "Saved Net", enabled)
            self.assertEqual(result.autoconnect, enabled)
            self.assert_only_bit_changed(before, enabled)
            self.assertEqual(self.hardware.states, runtime)
        self.assertEqual(self.runner.prompt_count, 0)

    def test_disconnected_profile_change_never_activates_or_changes_device_flag(self):
        runtime = copy.deepcopy(self.hardware.states)
        self.platform.profile_autoconnect(self.adapter, "Saved Net", False)
        self.assertEqual(self.hardware.states, runtime)
        self.assertEqual(self.runner.mutations, [["nmcli", "connection", "modify", "uuid", OLD,
                                                 "connection.autoconnect", "no"]])

    def test_idempotent_request_has_no_write(self):
        self.platform.profile_autoconnect(self.adapter, "Saved Net", True)
        self.assertEqual(self.runner.mutations, [])

    def test_enable_claims_existing_bit_without_creating_profile(self):
        self.platform.policy().approved.clear()
        before = copy.deepcopy(self.runner.profiles)
        self.platform.profile_autoconnect(self.adapter, "Saved Net", True)
        self.assertTrue(self.platform.policy().enabled(OLD))
        self.assertEqual(self.runner.profiles, before)
        self.assertEqual(self.runner.mutations, [])

    def test_failure_restores_optin_approval(self):
        self.platform.policy().approved.clear()
        self.runner.profiles[OLD]["connection.autoconnect"] = "no"
        self.runner.modify_noop = True
        with self.assertRaises(wifi.Error):
            self.platform.profile_autoconnect(self.adapter, "Saved Net", True)
        self.assertFalse(self.platform.policy().enabled(OLD))

    def test_ssid_punctuation_spaces_and_double_dash_are_exact(self):
        for ssid in ("x:y\\z $(cmd) \"q\"", "  SSID  ", "--", "--example", "äöü"):
            with self.subTest(ssid=ssid):
                self.runner.profiles[OLD]["802-11-wireless.ssid"] = ssid
                self.platform.profile_autoconnect(self.adapter, ssid, False)
                self.assertEqual(self.runner.profiles[OLD]["802-11-wireless.ssid"], ssid)
                self.runner.profiles[OLD]["connection.autoconnect"] = "yes"
        self.assertTrue(all(args[4] == OLD for args in self.runner.mutations))

    def test_missing_profile_never_creates_or_connects(self):
        with self.assertRaisesRegex(wifi.Error, "No eligible saved"):
            self.platform.profile_autoconnect(self.adapter, "Unknown SSID", True)
        self.assertEqual(self.runner.mutations, [])

    def test_ambiguous_profiles_fail_even_when_one_is_active(self):
        self.connected()
        self.runner.profiles[NEW] = self.runner.make_profile()
        with self.assertRaisesRegex(wifi.Error, "Multiple saved"):
            self.platform.profile_autoconnect(self.adapter, "Saved Net", False)
        self.assertEqual(self.runner.mutations, [])

    def test_foreign_ap_adhoc_controller_and_advanced_match_profiles_are_excluded(self):
        changes = ({"connection.interface-name": "ctrl0"}, {"connection.interface-name": "wlan1"},
                   {"802-11-wireless.mode": "ap"}, {"802-11-wireless.mode": "adhoc"},
                   {"connection.controller": "br0"}, {"match.path": "pci-*"},
                   {"match.interface-name": "ctrl*"}, {"match.driver": "brcmfmac"},
                   {"match.kernel-command-line": "test"})
        for fields in changes:
            with self.subTest(fields=fields):
                self.runner.profiles[OLD] = self.runner.make_profile(**fields)
                with self.assertRaisesRegex(wifi.Error, "No eligible saved"):
                    self.platform.profile_autoconnect(self.adapter, "Saved Net", False)
                self.assertEqual(self.runner.mutations, [])

    def test_unverifiable_mac_binding_rejected_even_beside_unbound_profile(self):
        self.runner.profiles[OLD]["802-11-wireless.mac-address"] = "00:11:22:33:44:55"
        self.runner.profiles[NEW] = self.runner.make_profile()
        with self.assertRaisesRegex(wifi.Error, "MAC binding"):
            self.platform.profile_autoconnect(self.adapter, "Saved Net", False)
        self.assertEqual(self.runner.mutations, [])

    def test_unbound_client_profile_allowed_but_active_control_profile_is_not(self):
        self.runner.profiles[OLD]["connection.interface-name"] = ""
        self.runner.protected_active = OLD
        with self.assertRaisesRegex(wifi.Error, "protected control radio"):
            self.platform.profile_autoconnect(self.adapter, "Saved Net", False)
        self.assertEqual(self.runner.mutations, [])
        self.runner.protected_active = ""
        self.assertFalse(self.platform.profile_autoconnect(self.adapter, "Saved Net", False).autoconnect)

    def test_non_wifi_profiles_skipped(self):
        self.runner.profiles[NEW] = {"connection.type": "802-3-ethernet"}
        self.assertFalse(self.platform.profile_autoconnect(self.adapter, "Saved Net", False).autoconnect)
        self.assertEqual(self.runner.profiles[NEW], {"connection.type": "802-3-ethernet"})

    def test_second_interface_selects_only_its_bound_profile(self):
        adapter = self.hardware.add("wlan1", phy=3, index=6)
        self.runner.profiles[NEW] = self.runner.make_profile(**{"connection.interface-name": "wlan1"})
        result = self.platform.profile_autoconnect(adapter, "Saved Net", False)
        self.assertEqual(result.uuid, NEW)
        self.assertEqual(self.runner.profiles[OLD]["connection.autoconnect"], "yes")

    def test_profile_changes_during_preflight_are_not_written(self):
        original = self.platform.select_profile
        calls = 0
        def select(*args):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.runner.profiles[OLD]["connection.autoconnect"] = "no"
            return original(*args)
        self.platform.select_profile = select
        with self.assertRaisesRegex(wifi.Error, "changed before"):
            self.platform.profile_autoconnect(self.adapter, "Saved Net", False)
        self.assertEqual(self.runner.mutations, [])

    def test_error_before_write_requires_no_rollback_write(self):
        self.runner.fail_once = lambda args: True
        with self.assertRaisesRegex(wifi.Error, "Previous profile autoconnect restored"):
            self.platform.profile_autoconnect(self.adapter, "Saved Net", False)
        self.assertEqual(len(self.runner.mutations), 1)
        self.assertEqual(self.runner.profiles[OLD]["connection.autoconnect"], "yes")

    def test_partial_native_failure_and_interrupt_restore_only_profile_bit(self):
        for failure in (wifi.Error("partial native failure"), KeyboardInterrupt()):
            with self.subTest(failure=type(failure).__name__):
                self.runner.mutations.clear()
                before = copy.deepcopy(self.runner.profiles)
                runtime = copy.deepcopy(self.hardware.states)
                def fail():
                    raise failure
                self.runner.after_modify = fail
                with self.assertRaisesRegex(wifi.Error, "Previous profile autoconnect restored"):
                    self.platform.profile_autoconnect(self.adapter, "Saved Net", False)
                self.assertEqual(self.runner.profiles, before)
                self.assertEqual(self.hardware.states, runtime)
                self.assertEqual([args[-1] for args in self.runner.mutations], ["no", "yes"])

    def test_success_exit_without_persistence_is_reported(self):
        self.runner.modify_noop = True
        with self.assertRaisesRegex(wifi.Error, "verification failed.*restored"):
            self.platform.profile_autoconnect(self.adapter, "Saved Net", False)
        self.assertEqual(len(self.runner.mutations), 1)

    def test_readback_failure_rolls_back_without_device_changes(self):
        def after():
            def once(identifier, field):
                self.runner.before_read = None
                raise wifi.Error("readback failed")
            self.runner.before_read = once
        self.runner.after_modify = after
        with self.assertRaisesRegex(wifi.Error, "readback failed.*restored"):
            self.platform.profile_autoconnect(self.adapter, "Saved Net", False)
        self.assertEqual([args[-1] for args in self.runner.mutations], ["no", "yes"])

    def test_foreign_metadata_change_is_not_overwritten_by_rollback(self):
        def after():
            self.runner.profiles[OLD]["802-11-wireless.ssid"] = "Changed independently"
        self.runner.after_modify = after
        with self.assertRaisesRegex(wifi.Error, "could not be fully restored.*changed independently"):
            self.platform.profile_autoconnect(self.adapter, "Saved Net", False)
        self.assertEqual(len(self.runner.mutations), 1)
        self.assertEqual(self.runner.profiles[OLD]["802-11-wireless.ssid"], "Changed independently")

    def test_deleted_profile_is_not_recreated_during_rollback(self):
        self.runner.after_modify = lambda: self.runner.profiles.pop(OLD)
        with self.assertRaisesRegex(wifi.Error, "could not be fully restored"):
            self.platform.profile_autoconnect(self.adapter, "Saved Net", False)
        self.assertNotIn(OLD, self.runner.profiles)
        self.assertEqual(len(self.runner.mutations), 1)

    def test_failure_of_rollback_is_reported_without_other_changes(self):
        def after():
            self.runner.fail_once = lambda args: args[-1] == "yes"
            raise wifi.Error("partial failure")
        self.runner.after_modify = after
        with self.assertRaisesRegex(wifi.Error, "could not be fully restored"):
            self.platform.profile_autoconnect(self.adapter, "Saved Net", False)
        self.assertTrue(all(args[:4] == ["nmcli", "connection", "modify", "uuid"]
                            for args in self.runner.mutations))

    def test_cli_profile_actions_require_ssid_and_cannot_mix_actions(self):
        for args in (["--autoconnect-on"], ["--autoconnect-off"],
                     ["Saved Net", "--autoconnect-on", "--autoconnect-off"],
                     ["Saved Net", "--autoconnect-on", "--off"],
                     ["Saved Net", "--autoconnect-off", "--monitor"],
                     ["Saved Net", "--autoconnect-on", "--managed"],
                     ["Saved Net", "--autoconnect-off", "--status"],
                     ["Saved Net", "--autoconnect"], ["Saved Net", "--on"]):
            with self.subTest(args=args), patch.object(wifi, "Platform") as platform, \
                    patch("sys.stderr", new=io.StringIO()), self.assertRaises(SystemExit) as result:
                wifi.main(args)
            self.assertEqual(result.exception.code, 2)
            platform.assert_not_called()

    def test_cli_profile_action_requires_root(self):
        with patch.object(wifi.os, "geteuid", return_value=1000), patch.object(wifi, "Platform") as platform, \
                patch("sys.stderr", new=io.StringIO()):
            self.assertEqual(wifi.main(["Saved Net", "--autoconnect-off"]), 1)
        platform.assert_not_called()

    def test_cli_profile_action_does_not_invoke_connect(self):
        for flag in ("--autoconnect-off", "--autoconnect-on"):
            with patch.object(wifi.os, "geteuid", return_value=0), \
                    patch.object(wifi, "Platform", return_value=self.platform), \
                    patch.object(self.platform, "locked", return_value=nullcontext()), \
                    patch("sys.stdout", new=io.StringIO()) as output:
                self.assertEqual(wifi.main(["Saved Net", flag]), 0)
            self.assertIn("Saved profile", output.getvalue())
            self.assertNotIn("Connected to", output.getvalue())
        self.assertTrue(all(args[:4] == ["nmcli", "connection", "modify", "uuid"]
                            for args in self.runner.mutations))

    def test_runtime_or_missing_storage_rejected_even_when_bit_already_matches(self):
        for filename in ("", "--", "/run/NetworkManager/system-connections/temporary.nmconnection",
                         "/usr/lib/NetworkManager/system-connections/vendor.nmconnection"):
            for enabled in (True, False):
                with self.subTest(filename=filename, enabled=enabled):
                    self.runner.storage[OLD] = filename
                    with self.assertRaisesRegex(wifi.Error, "not stored in persistent"):
                        self.platform.profile_autoconnect(self.adapter, "Saved Net", enabled)
                    self.assertEqual(self.runner.mutations, [])

    def test_unsaved_generated_or_volatile_profile_never_saved_implicitly(self):
        for unsaved, flags in (("b true", "u 0"), ("b false", "u 1"), ("b false", "u 2"),
                               ("b false", "u 4"), ("b false", "u 8")):
            for enabled in (True, False):
                with self.subTest(unsaved=unsaved, flags=flags, enabled=enabled):
                    self.runner.unsaved, self.runner.profile_flags = unsaved, flags
                    with self.assertRaisesRegex(wifi.Error, "temporary, generated or has unsaved"):
                        self.platform.profile_autoconnect(self.adapter, "Saved Net", enabled)
                    self.assertEqual(self.runner.mutations, [])

    def test_storage_change_during_update_is_not_overwritten(self):
        self.runner.after_modify = lambda: self.runner.storage.update({OLD: "/run/NetworkManager/system-connections/temporary.nmconnection"})
        with self.assertRaisesRegex(wifi.Error, "could not be fully restored"):
            self.platform.profile_autoconnect(self.adapter, "Saved Net", False)
        self.assertEqual(len(self.runner.mutations), 1)

    def test_completion_contains_only_correct_autoconnect_options(self):
        options = (ROOT / "components/wifi-control/files/completion").read_text().splitlines()
        self.assertIn("--autoconnect-on", options)
        self.assertIn("--autoconnect-off", options)
        self.assertNotIn("--autoconnect", options)
        self.assertNotIn("--on", options)

    def test_runtime_direct_help_smoke_uses_lf_shebang(self):
        source = ROOT / "python/auto_wifi.py"
        self.assertNotIn(b"\r", source.read_bytes())
        # Match the manifest's executable installation mode without changing the checkout.
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "wifi"
            executable.write_bytes(source.read_bytes())
            executable.chmod(0o755)
            result = subprocess.run([str(executable), "--help"], text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--autoconnect-on", result.stdout)
        self.assertIn("--autoconnect-off", result.stdout)


class ModeTests(Base):
    def test_monitor_transition_preserves_profiles_and_control(self):
        self.connected()
        state = self.platform.change_mode(self.adapter, "monitor")
        self.assertEqual(state.mode, "monitor")
        self.assertFalse(state.managed)
        self.assertIsNone(state.connection)
        self.assertTrue(state.up)
        self.assertEqual(self.runner.saved, {"Saved Net": OLD})
        self.assert_control_untouched()

    def test_return_managed_stays_disconnected(self):
        self.platform.change_mode(self.adapter, "monitor")
        self.runner.mutations.clear()
        state = self.platform.change_mode(self.adapter, "managed")
        self.assertEqual(state.mode, "managed")
        self.assertTrue(state.managed)
        self.assertFalse(state.autoconnect)
        self.assertIsNone(state.connection)
        self.assertFalse(any("connect" in args or "connection" in args for args in self.runner.mutations))
        self.assert_control_untouched()

    def test_already_managed_preserves_active_connection(self):
        old = self.connected()
        self.assertEqual(self.platform.change_mode(self.adapter, "managed"), old)
        self.assertFalse(self.runner.mutations)

    def test_already_monitor_is_idempotent(self):
        self.platform.change_mode(self.adapter, "monitor")
        self.runner.mutations.clear()
        self.platform.change_mode(self.adapter, "monitor")
        self.assertFalse(self.runner.mutations)

    def test_unsupported_monitor_does_not_disconnect(self):
        old = self.connected()
        self.runner.mode_support = {"managed"}
        with self.assertRaisesRegex(wifi.Error, "does not advertise"):
            self.platform.change_mode(self.adapter, "monitor")
        self.assertEqual(self.platform.read_state(self.adapter), old)
        self.assertFalse(self.runner.mutations)

    def test_mode_switch_failure_restores_old_connection_and_flags(self):
        old = self.connected()
        self.runner.fail_once = lambda args: args[:5] == ["iw", "dev", "wlan0", "set", "type"]
        with self.assertRaisesRegex(wifi.Error, "Previous adapter state restored"):
            self.platform.change_mode(self.adapter, "monitor")
        self.assertEqual(self.platform.read_state(self.adapter), old)
        self.assert_control_untouched()

    def test_failure_after_mode_change_restores_mode_and_connection(self):
        old = self.connected()
        self.runner.fail_once = lambda args: args == ["ip", "link", "set", "dev", "wlan0", "up"]
        with self.assertRaisesRegex(wifi.Error, "Previous adapter state restored"):
            self.platform.change_mode(self.adapter, "monitor")
        self.assertEqual(self.platform.read_state(self.adapter), old)

    def test_failed_managed_return_restores_monitor(self):
        old = self.platform.change_mode(self.adapter, "monitor")
        self.runner.fail_once = lambda args: args == ["nmcli", "device", "set", "wlan0", "managed", "yes"]
        with self.assertRaisesRegex(wifi.Error, "Previous adapter state restored"):
            self.platform.change_mode(self.adapter, "managed")
        self.assertEqual(self.platform.read_state(self.adapter), old)

    def test_unmanaged_client_requires_explicit_managed_action(self):
        self.hardware.states["wlan0"].update(managed=False, nm_state=10)
        with self.assertRaisesRegex(wifi.Error, "unmanaged"):
            self.platform.change_mode(self.adapter, "monitor")
        self.assertFalse(self.runner.mutations)
        state = self.platform.change_mode(self.adapter, "managed")
        self.assertTrue(state.managed)
        self.assertFalse(state.autoconnect)

    def test_off_disconnects_only_external_and_keeps_saved_keys(self):
        self.connected()
        state = self.platform.off(self.adapter)
        self.assertIsNone(state.connection)
        self.assertFalse(state.autoconnect)
        self.assertEqual(self.runner.saved, {"Saved Net": OLD})
        self.assert_control_untouched()

    def test_off_when_disconnected_disables_device_autoconnect_without_failure(self):
        state = self.platform.off(self.adapter)
        self.assertIsNone(state.connection)
        self.assertFalse(state.autoconnect)
        self.assertFalse(any("disconnect" in args for args in self.runner.mutations))

    def test_off_is_idempotent(self):
        self.platform.off(self.adapter)
        self.runner.mutations.clear()
        self.platform.off(self.adapter)
        self.assertFalse(self.runner.mutations)

    def test_off_monitor_stops_only_link_and_monitor_can_restart(self):
        self.platform.change_mode(self.adapter, "monitor")
        self.runner.mutations.clear()
        off = self.platform.off(self.adapter)
        self.assertFalse(off.up)
        self.assertEqual(off.mode, "monitor")
        self.assertEqual(self.runner.mutations, [["ip", "link", "set", "dev", "wlan0", "down"]])
        resumed = self.platform.change_mode(self.adapter, "monitor")
        self.assertTrue(resumed.up)
        self.assert_control_untouched()


class SafetyAndCLITests(Base):
    def test_lock_serializes_mutations(self):
        with self.platform.locked():
            with self.assertRaisesRegex(wifi.Error, "Another"):
                with self.platform.locked():
                    pass

    def test_symlink_lock_rejected(self):
        target = Path(self.hardware.temp.name) / "target"
        target.write_text("unchanged")
        self.platform.lock_path.symlink_to(target)
        with self.assertRaises(OSError):
            with self.platform.locked():
                pass
        self.assertEqual(target.read_text(), "unchanged")

    def test_help_unprivileged_without_host_access(self):
        with patch.object(wifi.os, "geteuid", return_value=1000), patch.object(wifi, "Platform") as platform:
            with self.assertRaises(SystemExit) as result, patch("sys.stdout", new=io.StringIO()):
                wifi.main(["--help"])
        self.assertEqual(result.exception.code, 0)
        platform.assert_not_called()

    def test_mutation_requires_root(self):
        with patch.object(wifi.os, "geteuid", return_value=1000), patch.object(wifi, "Platform") as platform, \
                patch("sys.stderr", new=io.StringIO()):
            self.assertEqual(wifi.main(["--off"]), 1)
        platform.assert_not_called()

    def test_invalid_action_combination_rejected(self):
        with self.assertRaises(SystemExit), patch("sys.stderr", new=io.StringIO()):
            wifi.main(["Saved Net", "--off"])
        with self.assertRaises(SystemExit), patch("sys.stderr", new=io.StringIO()):
            wifi.main(["--monitor", "--managed"])

    def test_no_runtime_sysfs_override(self):
        with self.assertRaises(SystemExit), patch("sys.stderr", new=io.StringIO()):
            wifi.main(["--sysfs-root", "/tmp/fake"])

    def test_status_is_read_only_and_lists_multiple_adapters(self):
        self.hardware.add("wlan1", phy=3, index=6)
        with patch.object(wifi, "Platform", return_value=self.platform), patch("sys.stdout", new=io.StringIO()) as output:
            self.assertEqual(wifi.main([]), 0)
        self.assertIn("wlan0", output.getvalue())
        self.assertIn("wlan1", output.getvalue())
        self.assertFalse(self.runner.mutations)

    def test_ssid_validation_bytes_controls_and_ambiguous_mac(self):
        for ssid in ("", "ä" * 17, "line\nSSID", "00:11:22:33:44:55"):
            with self.subTest(ssid=ssid), self.assertRaises(wifi.Error):
                wifi.validate_ssid(ssid)
        for ssid in ("ä" * 16, "Guest Wi-Fi", "colon:name", "--literal"):
            wifi.validate_ssid(ssid)

    def test_native_runner_secret_prompt_inherits_tty_without_capture(self):
        result = subprocess.CompletedProcess([], 0, None, None)
        with patch.dict(os.environ, {"PATH": "/untrusted", "LC_ALL": "de_DE.UTF-8"}), \
                patch.object(wifi.subprocess, "run", return_value=result) as native:
            wifi.run_command(["nmcli", "--ask"], interactive=True)
        arguments = native.call_args.kwargs
        self.assertFalse(arguments["capture_output"])
        self.assertIsNone(arguments["stdin"])
        self.assertEqual(arguments["env"]["PATH"], "/usr/sbin:/usr/bin:/sbin:/bin")
        self.assertEqual(arguments["env"]["LC_ALL"], "C")
        self.assertNotIn("shell", arguments)

    def test_noninteractive_native_command_has_no_stdin_secret_channel(self):
        result = subprocess.CompletedProcess([], 0, "", "")
        with patch.object(wifi.subprocess, "run", return_value=result) as native:
            wifi.run_command(["nmcli", "device", "show", "wlan0"])
        self.assertEqual(native.call_args.kwargs["stdin"], subprocess.DEVNULL)

    def test_native_error_does_not_echo_arbitrary_secret_output(self):
        result = subprocess.CompletedProcess([], 4, "secret-value", "secret-value")
        with patch.object(wifi.subprocess, "run", return_value=result):
            with self.assertRaises(wifi.Error) as result:
                wifi.run_command(["nmcli", "--ask"], interactive=True)
        self.assertNotIn("secret-value", str(result.exception))

    def test_status_reports_ssid_and_actual_addresses(self):
        self.connected()
        runner = self.runner
        def with_addresses(args, **kwargs):
            result = runner(args, **kwargs)
            if args[:4] == ["ip", "-json", "address", "show"]:
                links = json.loads(result)
                links[0]["addr_info"] = [{"local": "192.0.2.5", "prefixlen": 24},
                                        {"local": "2001:db8::5", "prefixlen": 64}]
                result = json.dumps(links)
            return result
        self.platform.run = with_addresses
        state = self.platform.read_state(self.adapter)
        with patch("sys.stdout", new=io.StringIO()) as output:
            wifi.show(state)
        self.assertIn('"Saved Net"', output.getvalue())
        self.assertIn("192.0.2.5/24", output.getvalue())
        self.assertIn("2001:db8::5/64", output.getvalue())
        self.assertFalse(any("--show-secrets" in args for args, _ in self.runner.calls))

    def test_status_separates_administrative_and_operational_link_state(self):
        for admin, operational, label in ((True, "DOWN", "down"), (True, "UP", "up"),
                                           (False, "DOWN", "down"), (True, "UNKNOWN", "unknown"),
                                           (True, None, "unknown"), (True, ["UP"], "unknown")):
            with self.subTest(admin=admin, operational=operational):
                self.hardware.states["wlan0"].update(up=admin, operstate=operational)
                state = self.platform.read_state(self.adapter)
                with patch("sys.stdout", new=io.StringIO()) as output:
                    wifi.show(state)
                self.assertIn(f"admin {'up' if admin else 'down'}, operational {label}", output.getvalue())
                self.assertNotIn("link up", output.getvalue())
                self.assertEqual(state.up, admin)  # Rollback still retains the administrative state.
        self.assertFalse(self.runner.mutations)

    def test_malformed_nm_response_rejected(self):
        with self.assertRaises(wifi.Error):
            wifi.parse_nm("GENERAL.DEVICE:ctrl0\n", self.adapter)


if __name__ == "__main__":
    unittest.main()
