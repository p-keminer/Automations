"""Fixture-only regressions for host Wi-Fi; no native networking commands run."""

from dataclasses import dataclass, replace
import importlib.util
import io
import json
import fcntl
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[4]
SPEC = importlib.util.spec_from_file_location("host_wifi_test_backend", ROOT / "portable/python/host_wifi.py")
host = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = host
SPEC.loader.exec_module(host)
wifi = host._wifi
OLD = "11111111-1111-4111-8111-111111111111"
OTHER = "22222222-2222-4222-8222-222222222222"
NEW = "33333333-3333-4333-8333-333333333333"
AP = "44444444-4444-4444-8444-444444444444"


@dataclass(frozen=True)
class HostProfile:
    platform: str = "kali-host"
    configured: bool = True
    protected_interfaces: tuple = ()
    ssh_service: str = "ssh"
    identity: str = "a" * 64


class TTY(io.StringIO):
    def isatty(self):
        return True


class Hardware:
    def __init__(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "sys"
        (Path(self.temp.name) / 'run').mkdir(mode=0o755)
        (self.root / "class/net").mkdir(parents=True)
        (self.root / "bus/pci").mkdir(parents=True)
        (self.root / "bus/usb").mkdir(parents=True)
        self.states = {}

    def close(self):
        self.temp.cleanup()

    def add(self, name, bus="pci", phy=0, index=3, shared=None):
        if shared is not None:
            old = host.inventory(self.root)[shared]
            device, phy_path = Path(old.device_path), Path(old.phy_path)
        elif bus == "pci":
            device = self.root / f"devices/pci0000:00/0000:02:{index:02x}.0"
            device.mkdir(parents=True)
            (device / "subsystem").symlink_to(self.root / "bus/pci")
            (device / "vendor").write_text("0x8086\n")
            (device / "device").write_text("0x2723\n")
            phy_path = device / f"ieee80211/phy{phy}"
        elif bus == "usb":
            parent = self.root / f"devices/usb1/1-{index}"
            device = parent / f"1-{index}:1.0"
            device.mkdir(parents=True)
            (parent / "idVendor").write_text("148f\n")
            (parent / "idProduct").write_text("3572\n")
            (parent / "subsystem").symlink_to(self.root / "bus/usb")
            phy_path = device / f"ieee80211/phy{phy}"
        else:
            device = self.root / f"devices/platform/radio{index}"
            device.mkdir(parents=True)
            phy_path = device / f"ieee80211/phy{phy}"
        phy_path.mkdir(parents=True, exist_ok=True)
        net = self.root / "class/net" / name
        net.mkdir()
        (net / "device").symlink_to(device)
        (net / "phy80211").symlink_to(phy_path)
        (net / "ifindex").write_text(str(index))
        (net / "address").write_text(f"02:00:00:00:00:{index:02x}\n")
        (net / "addr_assign_type").write_text("0\n")
        self.states[name] = dict(mode="managed", up=True, managed=True,
                                 autoconnect=True, nm_state=30, connection=None)

    def remove(self, name):
        net = self.root / "class/net" / name
        for item in net.iterdir():
            item.unlink()
        net.rmdir()
        del self.states[name]


class Runner:
    def __init__(self, hardware):
        self.hardware = hardware
        self.calls, self.mutations = [], []
        self.profiles = {}
        self.fail_connect = False
        self.fail_modify_after_write = False
        self.after_scan = None
        self.profile("Saved Net", OLD, autoconnect=True)
        self.profile("Other Net", OTHER, autoconnect=True, interface="other0")

    def profile(self, ssid, identifier, *, autoconnect=True, interface="", mac=""):
        self.profiles[identifier] = dict(ssid=ssid, autoconnect=autoconnect, interface=interface,
                                         mode="infrastructure", mac=mac, controller="",
                                         match=("", "", "", ""))

    def __call__(self, args, *, interactive=False):
        self.calls.append((list(args), interactive))
        devices = host.inventory(self.hardware.root)
        if args[:2] == ["iw", "phy"]:
            return "Wiphy " + args[2] + "\n\tSupported interface modes:\n\t\t* managed\n\t\t* monitor\n\tBand 1:\n"
        if args[0] == "iw" and args[-1] == "info":
            adapter = devices[args[2]]
            state = self.hardware.states[adapter.name]
            return (f"Interface {adapter.name}\n\tifindex {adapter.index}\n"
                    f"\twiphy {adapter.phy[3:]}\n\ttype {state['mode']}\n")
        if args[:4] == ["ip", "-json", "address", "show"]:
            name = args[-1]
            return json.dumps([{"ifname": name, "ifindex": devices[name].index,
                                "operstate": "UP", "flags": ["UP"] if self.hardware.states[name]["up"] else [],
                                "addr_info": []}])
        if args[0] == "busctl":
            return "b false\n" if args[-1] == "Unsaved" else "u 0\n"
        if args[0] == "nmcli" and "--fields" in args:
            field = args[args.index("--fields") + 1]
            if field == "UUID,DBUS-PATH,FILENAME":
                return "".join(f"{identifier}:/org/freedesktop/NetworkManager/Settings/{i}:"
                               f"/{'etc' if self.profiles[identifier].get('persistent', True) else 'run'}"
                               f"/NetworkManager/system-connections/lab-{i}.nmconnection\n"
                               for i, identifier in enumerate(self.profiles, 1))
            name = args[-1]
            state = self.hardware.states[name]
            return "\n".join([f"GENERAL.DEVICE:{name}", "GENERAL.TYPE:wifi",
                              f"GENERAL.STATE:{state['nm_state']} (state)",
                              "GENERAL.NM-MANAGED:" + ("yes" if state["managed"] else "no"),
                              "GENERAL.AUTOCONNECT:" + ("yes" if state["autoconnect"] else "no"),
                              "GENERAL.CON-UUID:" + (state["connection"] or "")]) + "\n"
        if args[0] == "nmcli" and "--get-values" in args:
            field = args[args.index("--get-values") + 1]
            if field == "BSSID":
                self.mutations.append(list(args))
                if self.after_scan:
                    callback, self.after_scan = self.after_scan, None
                    callback()
                return "02:00:00:00:00:10\n"
            if field == "GENERAL.CON-UUID":
                return (self.hardware.states[args[-1]]["connection"] or "") + "\n"
            if field == "UUID":
                return "".join(identifier + "\n" for identifier in self.profiles)
            profile = self.profiles[args[-1]]
            values = {"connection.uuid": args[-1], "connection.type": "802-11-wireless",
                      "802-11-wireless.ssid": profile["ssid"],
                      "connection.interface-name": profile["interface"],
                      "802-11-wireless.mode": profile["mode"],
                      "802-11-wireless.mac-address": profile["mac"],
                      "connection.controller": profile["controller"],
                      "connection.autoconnect": "yes" if profile["autoconnect"] else "no"}
            values.update({"match." + key: value for key, value in zip(
                ("interface-name", "path", "driver", "kernel-command-line"), profile["match"])})
            return values[field] + "\n"
        self.mutations.append(list(args))
        if args[:4] == ["nmcli", "connection", "modify", "uuid"]:
            assert args[5] == "connection.autoconnect"
            self.profiles[args[4]]["autoconnect"] = args[6] == "yes"
            if self.fail_modify_after_write:
                self.fail_modify_after_write = False
                raise host.Error("injected failure after profile write")
            return ""
        if args[0] == "nmcli" and "connection" in args and "up" in args:
            identifier = args[args.index("uuid") + 1]
            state = self.hardware.states[args[-1]]
            state.update(connection=identifier, nm_state=100, up=True, autoconnect=True)
            if self.fail_connect:
                self.fail_connect = False
                raise host.Error("injected connection failure")
            return ""
        if args[0] == "nmcli" and "device" in args:
            offset = args.index("device")
            action = args[offset + 1]
            if action == "set":
                name, field, value = args[offset + 2:offset + 5]
                state = self.hardware.states[name]
                state[field] = value == "yes"
                if field == "managed":
                    state.update(connection=None, nm_state=30 if state["managed"] else 10)
                return ""
            if action == "disconnect":
                self.hardware.states[args[-1]].update(connection=None, autoconnect=False, nm_state=30)
                return ""
            if action == "wifi" and args[offset + 2] == "connect":
                ssid, name = args[offset + 3], args[-1]
                if not interactive:
                    raise host.Error("No saved secret and no terminal")
                self.profile(ssid, NEW, interface=name)
                self.hardware.states[name].update(connection=NEW, nm_state=100,
                                                   up=True, autoconnect=True)
                return ""
        if args[:4] == ["ip", "link", "set", "dev"]:
            state = self.hardware.states[args[4]]
            state["up"] = args[5] == "up"
            if not state["up"]:
                state.update(connection=None, nm_state=30 if state["managed"] else 10)
            return ""
        if args[0] == "iw" and args[3:5] == ["set", "type"]:
            state = self.hardware.states[args[2]]
            assert not state["up"]
            state["mode"] = args[5]
            return ""
        raise AssertionError(args)


class HostWifiTests(unittest.TestCase):
    def setUp(self):
        self.hardware = Hardware()
        self.addCleanup(self.hardware.close)
        self.hardware.add("wlp2s0")
        self.runner = Runner(self.hardware)
        self.loaded_profile = HostProfile()
        self.platform = self.make_platform()
        self.adapter = host.inventory(self.hardware.root)["wlp2s0"]

    def make_platform(self, *, profile=None, profile_loader=None):
        return host.HostPlatform(root=self.hardware.root,
                                 owner_uid=os.geteuid(),
                                 lock=Path(self.hardware.temp.name) / "wifi.lock",
                                 runner=self.runner, sleeper=lambda _: None,
                                 profile=self.loaded_profile if profile is None else profile,
                                 profile_loader=(lambda: self.loaded_profile) if profile_loader is None else profile_loader)

    def invoke(self, argv, *, tty=False, uid=0):
        output, errors = (TTY() if tty else io.StringIO()), io.StringIO()
        result = host.main(argv, profile_loader=lambda: self.loaded_profile,
                           platform_factory=lambda **kwargs: self.make_platform(**kwargs),
                           stdin=TTY("1\n") if tty else io.StringIO(), stdout=output,
                           stderr=errors, geteuid=lambda: uid)
        return result, output.getvalue(), errors.getvalue()

    def assert_no_profile_changes(self):
        self.assertFalse(any(args[:3] == ["nmcli", "connection", "modify"]
                             for args in self.runner.mutations))

    def test_pci_and_usb_inventory_without_ctrl0(self):
        self.hardware.add("wlxlab", bus="usb", phy=1, index=4)
        devices = host.inventory(self.hardware.root)
        self.assertEqual(set(devices), {"wlp2s0", "wlxlab"})
        self.assertEqual((devices["wlp2s0"].bus, devices["wlp2s0"].hardware_id), ("pci", "8086:2723"))
        self.assertEqual((devices["wlxlab"].bus, devices["wlxlab"].hardware_id), ("usb", "148f:3572"))

    def test_unidentified_platform_radio_is_not_claimed_as_pci(self):
        self.hardware.add("socwifi", bus="platform", phy=2, index=7)
        self.assertNotIn("socwifi", host.inventory(self.hardware.root))

    def test_invalid_pci_identity_refused(self):
        Path(self.adapter.device_path, "vendor").write_text("invalid\n")
        with self.assertRaisesRegex(host.Error, "PCI"):
            host.inventory(self.hardware.root)

    def test_protected_entire_pci_phy_and_usb_remains_eligible(self):
        self.hardware.add("alias0", shared="wlp2s0", index=5)
        self.hardware.add("wlxlab", bus="usb", phy=1, index=4)
        profile = replace(self.loaded_profile, protected_interfaces=("wlp2s0",))
        eligible = host.eligible_adapters(host.inventory(self.hardware.root), profile)
        self.assertEqual(set(eligible), {"wlxlab"})

    def test_protected_usb_phy_alias_not_selected(self):
        self.hardware.add("wlxlab", bus="usb", phy=1, index=4)
        self.hardware.add("alias0", shared="wlxlab", index=5)
        profile = replace(self.loaded_profile, protected_interfaces=("wlxlab",))
        with self.assertRaisesRegex(host.Error, "protected"):
            host.select_adapter(host.inventory(self.hardware.root), profile, "alias0")

    def test_noninteractive_never_autoselects_even_one_adapter(self):
        with self.assertRaisesRegex(host.Error, "--interface"):
            host.select_adapter(host.inventory(self.hardware.root), self.loaded_profile,
                                stdin=io.StringIO(), stdout=io.StringIO())

    def test_multiple_adapters_exact_selection_and_tty_choice(self):
        self.hardware.add("wlxlab", bus="usb", phy=1, index=4)
        devices = host.inventory(self.hardware.root)
        self.assertEqual(host.select_adapter(devices, self.loaded_profile, "wlxlab").name, "wlxlab")
        chosen = host.select_adapter(devices, self.loaded_profile,
                                     stdin=TTY("unknown\n2\n"), stdout=TTY())
        self.assertEqual(chosen.name, "wlxlab")

    def test_help_does_not_load_profile_or_require_root(self):
        def forbidden(*args, **kwargs):
            self.fail("help accessed privileged/profile state")
        output = io.StringIO()
        with self.assertRaises(SystemExit) as exc:
            host.main(["--help"], profile_loader=forbidden, platform_factory=forbidden,
                      geteuid=forbidden, stdout=output, stderr=io.StringIO())
        self.assertEqual(exc.exception.code, 0)
        self.assertIn("--autoconnect-on", output.getvalue())
        self.assertIn("PCI or USB", output.getvalue())

    def test_read_only_unconfigured_host_works_without_root(self):
        self.loaded_profile = replace(self.loaded_profile, configured=False)
        result, output, errors = self.invoke(["--status"], uid=1000)
        self.assertEqual((result, errors), (0, ""))
        self.assertIn("PCI 8086:2723", output)
        self.assertFalse(self.runner.mutations)

    def test_no_wifi_returns_typed_unavailable_and_nonzero(self):
        self.hardware.remove("wlp2s0")
        result, output, errors = self.invoke([], uid=1000)
        self.assertEqual(result, 3)
        self.assertIn("Not available", errors)
        self.assertNotIn("ctrl0", errors)
        self.assertFalse(self.runner.mutations)

    def test_unconfigured_or_nonroot_mutation_refused(self):
        self.loaded_profile = replace(self.loaded_profile, configured=False)
        self.assertEqual(self.invoke(["--off", "--interface", "wlp2s0"])[0], 1)
        self.loaded_profile = HostProfile()
        self.assertEqual(self.invoke(["--off", "--interface", "wlp2s0"], uid=1000)[0], 1)
        self.assertFalse(self.runner.mutations)

    def test_profile_reload_blocks_later_mutation(self):
        self.loaded_profile = replace(self.loaded_profile, identity="b" * 64)
        with self.assertRaisesRegex(host.Error, "profile changed"):
            self.platform.link(self.adapter, False)
        self.assertFalse(self.runner.mutations)

    def test_replaced_ifindex_is_never_modified(self):
        (self.hardware.root / "class/net/wlp2s0/ifindex").write_text("19\n")
        with self.assertRaisesRegex(host.Error, "changed"):
            self.platform.link(self.adapter, False)
        self.assertFalse(self.runner.mutations)

    def test_shared_unprotected_phy_prevents_disruptive_operation(self):
        self.hardware.add("alias0", shared="wlp2s0", index=5)
        with self.assertRaisesRegex(host.Error, "shares"):
            self.platform.change_mode(self.adapter, "monitor")
        self.assertFalse(self.runner.mutations)

    def test_missing_protected_interface_fails_closed(self):
        self.loaded_profile = replace(self.loaded_profile, protected_interfaces=("missing0",))
        platform = self.make_platform()
        with self.assertRaisesRegex(host.Error, "protected interface disappeared"):
            platform.off(self.adapter)
        self.assertFalse(self.runner.mutations)

    def test_saved_connect_preserves_both_profile_bits_and_device_autoconnect(self):
        self.runner.profiles[OLD]["autoconnect"] = False
        self.hardware.states["wlp2s0"]["autoconnect"] = False
        result = self.platform.connect(self.adapter, "Saved Net", False)
        self.assertEqual(result.connection, OLD)
        self.assertFalse(result.autoconnect)
        self.assertFalse(self.runner.profiles[OLD]["autoconnect"])
        self.assertTrue(self.runner.profiles[OTHER]["autoconnect"])
        self.assert_no_profile_changes()
        self.assertTrue(any("up" in args and OLD in args for args in self.runner.mutations))
        self.assertFalse(any("connect" in args for args in self.runner.mutations))

    def test_new_connection_uses_native_defaults_without_global_policy(self):
        result = self.platform.connect(self.adapter, "New Lab", True)
        self.assertEqual(result.connection, NEW)
        self.assertTrue(self.runner.profiles[NEW]["autoconnect"])
        self.assertTrue(self.runner.profiles[OLD]["autoconnect"])
        self.assertTrue(self.runner.profiles[OTHER]["autoconnect"])
        self.assert_no_profile_changes()

    def test_same_ssid_runtime_ap_does_not_prevent_fresh_client_connection(self):
        self.runner.profile("New Lab", AP, interface="ap-radio")
        self.runner.profiles[AP].update(mode="ap", persistent=False, autoconnect=False)
        original_ap = dict(self.runner.profiles[AP])
        state = self.platform.connect(self.adapter, "New Lab", True)
        self.assertEqual(state.connection, NEW)
        self.assertEqual(self.runner.profiles[AP], original_ap)
        self.assert_no_profile_changes()
        self.assertFalse(any(args[-1] == AP and "match.interface-name" in args
                             for args, _interactive in self.runner.calls))

    def test_same_ssid_runtime_ap_is_ignored_for_saved_client_and_autoconnect(self):
        self.runner.profile("Saved Net", AP, interface="ap-radio")
        self.runner.profiles[AP].update(mode="ap", persistent=False, autoconnect=False)
        original_ap = dict(self.runner.profiles[AP])
        self.assertEqual(self.platform.connect(self.adapter, "Saved Net", False).connection, OLD)
        self.platform.profile_autoconnect(self.adapter, "Saved Net", False)
        self.assertFalse(self.runner.profiles[OLD]["autoconnect"])
        self.assertEqual(self.runner.profiles[AP], original_ap)
        writes = [args for args in self.runner.mutations if args[:3] == ["nmcli", "connection", "modify"]]
        self.assertEqual([args[4] for args in writes], [OLD])

    def test_ignored_ap_does_not_relax_incompatible_or_multiple_client_profiles(self):
        self.runner.profile("Saved Net", AP)
        self.runner.profiles[AP].update(mode="ap", persistent=False)
        self.runner.profiles[OLD]["interface"] = "another-client"
        with self.assertRaisesRegex(host.Error, "incompatible"):
            self.platform.connect(self.adapter, "Saved Net", True)
        self.runner.profiles[OLD]["interface"] = ""
        self.runner.profile("Saved Net", NEW)
        with self.assertRaisesRegex(host.Error, "Multiple"):
            self.platform.connect(self.adapter, "Saved Net", True)
        self.assertFalse(self.runner.mutations)

    def test_autoconnect_flag_changes_only_one_saved_uuid_without_disconnecting(self):
        self.hardware.states["wlp2s0"].update(connection=OLD, nm_state=100)
        result = self.platform.profile_autoconnect(self.adapter, "Saved Net", False)
        self.assertFalse(result.autoconnect)
        self.assertTrue(self.runner.profiles[OTHER]["autoconnect"])
        self.assertEqual(self.hardware.states["wlp2s0"]["connection"], OLD)
        self.assertEqual(len(self.runner.mutations), 1)
        self.assertEqual(self.runner.mutations[0][4], OLD)

    def test_autoconnect_on_is_not_pi_policy_approval(self):
        self.runner.profiles[OLD]["autoconnect"] = False
        self.assertTrue(self.platform.profile_autoconnect(self.adapter, "Saved Net", True).autoconnect)
        self.assertTrue(self.runner.profiles[OTHER]["autoconnect"])
        self.assertEqual(len(self.runner.mutations), 1)

    def test_autoconnect_partial_write_rolls_back_only_same_profile_bit(self):
        self.runner.fail_modify_after_write = True
        with self.assertRaisesRegex(host.Error, "restored"):
            self.platform.profile_autoconnect(self.adapter, "Saved Net", False)
        self.assertTrue(self.runner.profiles[OLD]["autoconnect"])
        self.assertTrue(self.runner.profiles[OTHER]["autoconnect"])
        self.assertEqual([args[4] for args in self.runner.mutations], [OLD, OLD])

    def test_ambiguous_or_incompatible_profile_not_replaced_by_native_connect(self):
        self.runner.profile("Saved Net", NEW)
        with self.assertRaisesRegex(host.Error, "Multiple"):
            self.platform.connect(self.adapter, "Saved Net", False)
        del self.runner.profiles[NEW]
        self.runner.profiles[OLD]["interface"] = "other0"
        with self.assertRaisesRegex(host.Error, "incompatible"):
            self.platform.connect(self.adapter, "Saved Net", False)
        self.assertFalse(self.runner.mutations)

    def test_active_profile_on_other_adapter_remains_untouched(self):
        self.hardware.add("wlxlab", bus="usb", phy=1, index=4)
        self.hardware.states["wlxlab"].update(connection=OLD, nm_state=100)
        with self.assertRaisesRegex(host.Error, "another Wi-Fi"):
            self.platform.profile_autoconnect(self.adapter, "Saved Net", False)
        self.assertFalse(self.runner.mutations)

    def test_permanent_mac_binding_supported_but_randomized_binding_refused(self):
        address = (self.hardware.root / "class/net/wlp2s0/address").read_text().strip()
        self.runner.profiles[OLD]["mac"] = address
        self.assertEqual(self.platform.select_profile(self.adapter, "Saved Net").uuid, OLD)
        (self.hardware.root / "class/net/wlp2s0/addr_assign_type").write_text("3\n")
        with self.assertRaisesRegex(host.Error, "unverifiable"):
            self.platform.profile_autoconnect(self.adapter, "Saved Net", False)
        self.assertFalse(self.runner.mutations)

    def test_failed_connect_restores_selected_state_without_touching_profile_bits(self):
        self.hardware.states["wlp2s0"].update(connection=OTHER, nm_state=100)
        old = self.platform.read_state(self.adapter)
        self.runner.fail_connect = True
        with self.assertRaisesRegex(host.Error, "restored"):
            self.platform.connect(self.adapter, "Saved Net", False)
        self.assertEqual(self.platform.read_state(self.adapter), old)
        self.assertTrue(all(p["autoconnect"] for p in self.runner.profiles.values()))
        self.assert_no_profile_changes()

    def test_mode_roundtrip_does_not_normalize_saved_profiles(self):
        self.runner.profiles[OLD]["autoconnect"] = False
        self.assertEqual(self.platform.change_mode(self.adapter, "monitor").mode, "monitor")
        self.assertEqual(self.platform.change_mode(self.adapter, "managed").mode, "managed")
        self.assertFalse(self.runner.profiles[OLD]["autoconnect"])
        self.assertTrue(self.runner.profiles[OTHER]["autoconnect"])
        self.assert_no_profile_changes()

    def test_cli_requires_explicit_selection_and_keeps_ssid_flag_semantics(self):
        result, _, errors = self.invoke(["Saved Net"])
        self.assertEqual(result, 1)
        self.assertIn("--interface", errors)
        with self.assertRaises(SystemExit) as exc:
            self.invoke(["Saved Net", "--status"])
        self.assertEqual(exc.exception.code, 2)
        self.assertFalse(self.runner.mutations)


    def test_pci_ancestor_does_not_misidentify_an_sdio_radio(self):
        device = self.hardware.root / "devices/pci0000:00/0000:04:00.0"
        device.mkdir(parents=True)
        (device / "subsystem").symlink_to(self.hardware.root / "bus/pci")
        (device / "vendor").write_text("0x1234\n")
        (device / "device").write_text("0x5678\n")
        sdio_bus = self.hardware.root / "bus/sdio"
        sdio_bus.mkdir()
        radio = device / "mmc_host/sdio0"
        radio.mkdir(parents=True)
        (radio / "subsystem").symlink_to(sdio_bus)
        phy = radio / "ieee80211/phy8"
        phy.mkdir(parents=True)
        net = self.hardware.root / "class/net/sdiolab"
        net.mkdir()
        (net / "device").symlink_to(radio)
        (net / "phy80211").symlink_to(phy)
        (net / "ifindex").write_text("28\n")
        self.assertNotIn("sdiolab", host.inventory(self.hardware.root))

    def test_physical_links_leaving_sysfs_are_refused(self):
        outside = Path(self.hardware.temp.name) / "outside/phy9"
        outside.mkdir(parents=True)
        link = self.hardware.root / "class/net/wlp2s0/phy80211"
        link.unlink()
        link.symlink_to(outside)
        with self.assertRaisesRegex(host.Error, "leave sysfs"):
            host.inventory(self.hardware.root)
        self.assertFalse(self.runner.mutations)

    def test_protected_identity_change_blocks_next_mutation(self):
        self.hardware.add("wlxlab", bus="usb", phy=1, index=4)
        self.loaded_profile = replace(self.loaded_profile, protected_interfaces=("wlxlab",))
        platform = self.make_platform()
        platform.read_state(self.adapter)
        (self.hardware.root / "class/net/wlxlab/ifindex").write_text("24\n")
        with self.assertRaisesRegex(host.Error, "Protected wireless hardware identity"):
            platform.link(self.adapter, False)
        self.assertFalse(self.runner.mutations)

    def test_profile_change_during_scan_prevents_connection_and_rollback_writes(self):
        def update_profile():
            self.loaded_profile = replace(self.loaded_profile, identity="b" * 64)
        self.runner.after_scan = update_profile
        with self.assertRaisesRegex(host.Error, "could not be fully restored"):
            self.platform.connect(self.adapter, "Saved Net", False)
        self.assertEqual(len(self.runner.mutations), 1)
        self.assertIn("list", self.runner.mutations[0])
        self.assert_no_profile_changes()

    def test_explicit_cli_selection_changes_only_selected_device(self):
        self.hardware.add("wlxlab", bus="usb", phy=1, index=4)
        result, output, errors = self.invoke(["--off", "--interface", "wlp2s0"])
        self.assertEqual((result, errors), (0, ""))
        self.assertFalse(self.hardware.states["wlp2s0"]["autoconnect"])
        self.assertTrue(self.hardware.states["wlxlab"]["autoconnect"])
        self.assertTrue(all(p["autoconnect"] for p in self.runner.profiles.values()))
        self.assert_no_profile_changes()

    def test_host_network_lock_blocks_wifi_before_any_device_change(self):
        path = Path(self.hardware.temp.name) / 'run/automations-host-share.lock'
        descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result, _, errors = self.invoke(['--off', '--interface', 'wlp2s0'])
            self.assertEqual(result, 1)
            self.assertIn('Another host network operation', errors)
            self.assertFalse(self.runner.mutations)
        finally:
            os.close(descriptor)

    def test_symlink_network_coordination_lock_is_not_followed(self):
        path = Path(self.hardware.temp.name) / 'run/automations-host-share.lock'
        target = Path(self.hardware.temp.name) / 'untouched'
        target.write_text('preserve')
        path.symlink_to(target)
        result, _, _ = self.invoke(['--off', '--interface', 'wlp2s0'])
        self.assertEqual(result, 1)
        self.assertEqual(target.read_text(), 'preserve')
        self.assertFalse(self.runner.mutations)

    def test_pi4_profile_cannot_authorize_host_backend(self):
        with self.assertRaisesRegex(host.Error, "Kali-host"):
            self.make_platform(profile=replace(self.loaded_profile, platform="pi4"))
        self.assertFalse(self.runner.mutations)


if __name__ == "__main__":
    unittest.main()
