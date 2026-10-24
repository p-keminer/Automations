"""Hardware-free tests using Linux-style sysfs directories and symlinks."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parents[4]
SCRIPT = REPOSITORY / "common/python" / "awus036acm.py"
SPEC = importlib.util.spec_from_file_location("awus036acm", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
awus = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(awus)


class Sysfs:
    def __init__(self, root: Path):
        self.root = root
        self.bus = root / "bus" / "usb" / "devices"
        self.net = root / "class" / "net"
        self.bus.mkdir(parents=True)
        self.net.mkdir(parents=True)

    def usb(self, name="1-1.2", usb_id="0e8d:7612", driver="mt76x2u", interface="wlan1", nested=False):
        physical = self.root / "devices" / "platform" / "usb-host" / name
        physical.mkdir(parents=True)
        vendor, product = usb_id.split(":")
        (physical / "idVendor").write_text(vendor + "\n", encoding="ascii")
        (physical / "idProduct").write_text(product + "\n", encoding="ascii")
        (self.bus / name).symlink_to(physical, target_is_directory=True)
        usb_interface = physical / (name + ":1.0")
        usb_interface.mkdir()
        (self.bus / usb_interface.name).symlink_to(usb_interface, target_is_directory=True)
        if driver is not None:
            driver_path = self.root / "bus" / "usb" / "drivers" / driver
            driver_path.mkdir(parents=True, exist_ok=True)
            (usb_interface / "driver").symlink_to(driver_path, target_is_directory=True)
        if interface is not None:
            net_parent = usb_interface / "phy" if nested else usb_interface
            self.wifi(interface, net_parent, usb_interface)
        return physical, usb_interface

    def wifi(self, name, parent, device):
        net_device = parent / "net" / name
        (net_device / "wireless").mkdir(parents=True)
        (net_device / "device").symlink_to(device, target_is_directory=True)
        (self.net / name).symlink_to(net_device, target_is_directory=True)
        return net_device

    def control(self):
        control_device = self.root / "devices" / "platform" / "mmc" / "mmc1:0001:1"
        control_device.mkdir(parents=True)
        return self.wifi("ctrl0", control_device, control_device)


class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.sysfs = Sysfs(self.root)

    def inspect(self):
        return awus.inspect_adapter(self.root)

    def test_no_adapter_does_not_fall_back_to_control_wifi(self):
        self.sysfs.control()
        result = self.inspect()
        self.assertEqual(result["status"], "missing")
        self.assertEqual(result["adapters"], [])

    def test_other_alfa_or_wifi_adapter_does_not_match(self):
        self.sysfs.usb(usb_id="0bda:8812", driver="rtl8812au")
        self.assertEqual(self.inspect()["status"], "missing")

    def test_native_binding_and_real_symlinks_are_recognized(self):
        self.sysfs.control()
        self.sysfs.usb()
        result = self.inspect()
        self.assertEqual(result["status"], "ready")
        self.assertEqual(len(result["adapters"]), 1)
        adapter = result["adapters"][0]
        self.assertEqual(adapter["interfaces"], ["wlan1"])
        self.assertEqual(adapter["drivers"], ["mt76x2u"])
        self.assertEqual(adapter["issues"], [])

    def test_moved_port_and_predictable_interface_name(self):
        self.sysfs.usb(name="2-3.4", interface="wlx001122334455")
        result = self.inspect()
        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["adapters"][0]["usb_device"], "2-3.4")
        self.assertEqual(result["adapters"][0]["interfaces"], ["wlx001122334455"])

    def test_nested_net_device_is_found_through_class_link(self):
        self.sysfs.usb(interface="work0", nested=True)
        result = self.inspect()
        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["adapters"][0]["interfaces"], ["work0"])

    def test_unbound_adapter_is_present_but_not_ready(self):
        self.sysfs.usb(driver=None, interface=None)
        result = self.inspect()
        self.assertEqual(result["status"], "not_ready")
        self.assertEqual(result["adapters"][0]["issues"], ["unbound", "no_wireless_interface"])

    def test_driver_without_wifi_interface_is_not_ready(self):
        self.sysfs.usb(interface=None)
        result = self.inspect()
        self.assertEqual(result["status"], "not_ready")
        self.assertEqual(result["adapters"][0]["issues"], ["no_wireless_interface"])

    def test_wrong_driver_is_not_reported_as_ready(self):
        self.sysfs.usb(driver="unrelated_driver")
        result = self.inspect()
        self.assertEqual(result["status"], "not_ready")
        self.assertIn("unexpected_driver", result["adapters"][0]["issues"])

    def test_multiple_adapters_are_reported_without_selection(self):
        self.sysfs.usb(name="1-1", interface="wlan1")
        self.sysfs.usb(name="2-2", interface="wlan2")
        result = self.inspect()
        self.assertEqual(result["status"], "multiple")
        self.assertEqual(len(result["adapters"]), 2)
        self.assertTrue(all(item["status"] == "ready" for item in result["adapters"]))
        self.assertNotIn("selected_adapter", result)

    def test_reserved_control_name_is_rejected_even_with_matching_usb_id(self):
        self.sysfs.usb(interface="ctrl0")
        result = self.inspect()
        self.assertEqual(result["status"], "not_ready")
        self.assertIn("reserved_control_interface", result["adapters"][0]["issues"])

    def test_unrelated_interface_alias_cannot_supply_a_driver(self):
        physical, usb_interface = self.sysfs.usb(driver=None, interface=None)
        unrelated, unrelated_interface = self.sysfs.usb(name="2-2", usb_id="0000:0001", interface="other0")
        alias = self.sysfs.bus / (physical.name + ":1.1")
        alias.symlink_to(unrelated_interface, target_is_directory=True)
        result = self.inspect()
        self.assertEqual(result["status"], "not_ready")
        self.assertEqual(result["adapters"][0]["interfaces"], [])
        self.assertEqual(result["adapters"][0]["drivers"], [])

    def test_unreadable_or_incomplete_sysfs_is_distinct_from_missing_adapter(self):
        result = awus.inspect_adapter(self.root / "missing")
        self.assertEqual(result["status"], "unavailable")
        self.assertTrue(result["errors"])

    def test_malformed_device_is_reported_as_incomplete_discovery(self):
        physical, _ = self.sysfs.usb()
        (physical / "idProduct").unlink()
        self.assertEqual(self.inspect()["status"], "unavailable")

    def test_broken_driver_link_is_not_reported_as_ready(self):
        _, usb_interface = self.sysfs.usb()
        driver = usb_interface / "driver"
        driver.unlink()
        driver.symlink_to(self.root / "absent-driver", target_is_directory=True)
        result = self.inspect()
        self.assertEqual(result["status"], "not_ready")
        self.assertIn("read_error", result["adapters"][0]["issues"])

    def run_cli(self, *options):
        return subprocess.run([sys.executable, str(SCRIPT), "--sysfs-root", str(self.root), *options], capture_output=True, text=True, check=False)

    def test_json_cli_has_documented_missing_and_ready_exit_codes(self):
        result = self.run_cli("--json")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(json.loads(result.stdout)["status"], "missing")
        self.sysfs.usb()
        result = self.run_cli("--json")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["status"], "ready")
        self.assertEqual(result.stderr, "")

    def test_json_cli_distinguishes_not_ready_multiple_and_unavailable(self):
        self.sysfs.usb(name="1-1", driver=None, interface=None)
        result = self.run_cli("--json")
        self.assertEqual(result.returncode, 3)
        self.assertEqual(json.loads(result.stdout)["status"], "not_ready")
        self.sysfs.usb(name="2-2", interface="wlan2")
        result = self.run_cli("--json")
        self.assertEqual(result.returncode, 4)
        self.assertEqual(json.loads(result.stdout)["status"], "multiple")
        result = self.run_cli("--json", "--sysfs-root", str(self.root / "missing"))
        self.assertEqual(result.returncode, 5)
        self.assertEqual(json.loads(result.stdout)["status"], "unavailable")

    def test_human_output_and_invalid_argument_exit_code(self):
        self.sysfs.usb()
        result = self.run_cli()
        self.assertEqual(result.returncode, 0)
        self.assertIn("Driver: mt76x2u", result.stdout)
        self.assertIn("Wi-Fi: wlan1", result.stdout)
        self.assertEqual(self.run_cli("--not-an-option").returncode, 64)

    def test_observation_does_not_change_fixture_files(self):
        self.sysfs.usb()
        self.sysfs.control()
        def snapshot():
            return {str(path.relative_to(self.root)): ("link", str(path.readlink())) if path.is_symlink() else ("file", path.read_bytes()) for path in self.root.rglob("*") if path.is_symlink() or path.is_file()}
        before = snapshot()
        self.inspect()
        self.assertEqual(before, snapshot())


if __name__ == "__main__":
    unittest.main()
