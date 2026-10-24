"""No real GPIO, fan, service or network operation is permitted by these tests."""
import contextlib
from dataclasses import replace
import importlib.util
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    spec.loader.exec_module(result)
    return result


fan = module("host_fan_under_test", ROOT / "portable/python/host_fan.py")
support = module("host_fan_profile_fixture", ROOT / "common/python/platform_support.py")
PROFILE = support.Profile("kali-host", True, (), "ssh.service", "a" * 64)


class HostFanTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.backend = fan.HostFan(PROFILE, sysroot=self.root)

    def sensor(self, value, name="fan1_input"):
        directory = self.root / "devices/platform/example/hwmon/hwmon0"
        directory.mkdir(parents=True, exist_ok=True)
        entry = directory / name
        entry.write_text(value, encoding="ascii")
        link = self.root / "class/hwmon/hwmon0"
        link.parent.mkdir(parents=True, exist_ok=True)
        if not link.exists():
            link.symlink_to(directory, target_is_directory=True)
        return entry

    def test_vm_without_sensors_is_unavailable_not_fake_off(self):
        state = self.backend.inspect()
        self.assertFalse(state["available"])
        self.assertEqual(state["control"], "unsupported")
        self.assertIsNone(state["live_mode"])
        self.assertIsNone(state["requested_mode"])
        self.assertEqual(state["sensors"], [])
        self.assertEqual(list(self.root.iterdir()), [])

    def test_hwmon_rpm_is_read_only_and_does_not_establish_control(self):
        sensor = self.sensor("1234\n")
        state = self.backend.inspect()
        self.assertEqual(state["sensors"][0]["rpm"], 1234)
        self.assertFalse(state["available"])
        self.assertIsNone(state["live_mode"])
        self.assertEqual(sensor.read_text(), "1234\n")

    def test_zero_rpm_does_not_claim_requested_off(self):
        self.sensor("0\n")
        state = self.backend.inspect()
        self.assertEqual(state["sensors"][0]["rpm"], 0)
        self.assertIsNone(state["requested_mode"])

    def test_all_hardware_actions_are_unavailable_and_do_not_write(self):
        sensor = self.sensor("0\n")
        for mode in ("on", "auto", "off"):
            with self.subTest(mode=mode), self.assertRaisesRegex(fan.NotAvailable, "nothing was changed"):
                self.backend.change(mode)
        self.assertEqual(sensor.read_text(), "0\n")

    def test_malformed_or_oversized_sensor_is_only_a_diagnostic(self):
        for raw in ("-1\n", "unknown\n", "1" * 40, "123 extra"):
            self.sensor(raw)
            state = self.backend.inspect()
            self.assertEqual(state["sensors"], [])
            self.assertEqual(len(state["sensor_errors"]), 1)

    def test_sysfs_symlink_must_not_escape_to_a_file_outside_sysroot(self):
        sensor = self.sensor("123\n")
        with tempfile.TemporaryDirectory() as outside:
            secret = Path(outside) / "private"
            secret.write_text("987\n")
            sensor.unlink()
            sensor.symlink_to(secret)
            state = self.backend.inspect()
        self.assertEqual(state["sensors"], [])
        self.assertEqual(len(state["sensor_errors"]), 1)

    def test_pi4_or_invalid_profile_is_rejected(self):
        for profile in (replace(PROFILE, platform="pi4"), replace(PROFILE, identity="untrusted")):
            with self.assertRaises(fan.Error):
                fan.HostFan(profile, sysroot=self.root)

    def test_unconfigured_common_host_profile_allows_only_honest_observation(self):
        backend = fan.HostFan(replace(PROFILE, configured=False), sysroot=self.root)
        self.assertFalse(backend.inspect()["configured"])
        with self.assertRaises(fan.NotAvailable):
            backend.change("off")

    def test_help_has_no_root_or_profile_requirement(self):
        with patch.object(fan, "load_profile", side_effect=AssertionError("must not load")), \
                contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as result:
            fan.main(["--help"])
        self.assertEqual(result.exception.code, 0)

    def test_status_and_every_action_have_nonzero_unavailable_exit(self):
        factory = lambda _profile: self.backend
        for args in ([], ["--status"], ["--auto"], ["--off"], ["--on"]):
            with self.subTest(args=args), contextlib.redirect_stdout(io.StringIO()), \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(fan.main(args, profile_loader=lambda: PROFILE, backend_factory=factory), 3)

    def test_mutually_exclusive_actions_remain_usage_errors(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as result:
            fan.main(["--auto", "--off"])
        self.assertEqual(result.exception.code, 2)

    def test_output_distinguishes_rpm_observation_and_unavailable_gpio_control(self):
        self.sensor("321\n")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            fan.print_status(self.backend.inspect())
        text = output.getvalue()
        self.assertIn("321 RPM", text)
        self.assertIn("GPIO14 output: unavailable", text)
        self.assertIn("do not establish controllability", text)
        self.assertNotIn("Live control: off", text)


if __name__ == "__main__":
    unittest.main()
