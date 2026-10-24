"""Trust boundaries and effective identity of read-only platform profiles."""

from dataclasses import FrozenInstanceError
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[4]
SPEC = importlib.util.spec_from_file_location(
    "platform_support_tests", ROOT / "common/python/platform_support.py"
)
platform = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = platform
SPEC.loader.exec_module(platform)


class PlatformSupportTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.owner_uid = os.getuid()
        self.directory = self.root / "etc/automations"
        self.directory.mkdir(parents=True)
        self.directory.parent.chmod(0o755)
        self.directory.chmod(0o755)
        self.path = self.directory / "platform.json"
        self.data = {
            "schema_version": 1, "platform": "kali-host",
            "protected_interfaces": ["enp0s3"], "ssh_service": "ssh.service",
        }

    def write(self, value=None):
        self.path.write_text(
            json.dumps(self.data if value is None else value), encoding="utf-8"
        )
        self.path.chmod(0o644)

    def load(self):
        return platform.load_profile(self.root, _owner_uid=self.owner_uid)

    def device_tree(self, model=b"Raspberry Pi 4 Model B Rev 1.4\0",
                    compatible=b"raspberrypi,4-model-b\0brcm,bcm2711\0"):
        folder = self.root / "sys/firmware/devicetree/base"
        folder.mkdir(parents=True, exist_ok=True)
        for relative in ("sys", "sys/firmware", "sys/firmware/devicetree",
                         "sys/firmware/devicetree/base"):
            (self.root / relative).chmod(0o755)
        (folder / "model").write_bytes(model)
        (folder / "compatible").write_bytes(compatible)
        (folder / "model").chmod(0o644)
        (folder / "compatible").chmod(0o644)
        return folder

    def test_missing_profile_is_unconfigured_host_and_writes_nothing(self):
        before = sorted(str(path.relative_to(self.root)) for path in self.root.rglob("*"))
        result = self.load()
        self.assertEqual(result.platform, "kali-host")
        self.assertFalse(result.configured)
        self.assertEqual(result.protected_interfaces, ())
        self.assertEqual(result.ssh_service, "ssh.service")
        self.assertRegex(result.identity, r"^[0-9a-f]{64}$")
        self.assertEqual(
            sorted(str(path.relative_to(self.root)) for path in self.root.rglob("*")),
            before,
        )

    def test_host_profile_is_frozen_and_preserves_explicit_service(self):
        self.data["ssh_service"] = "sshd.service"
        self.write()
        result = self.load()
        self.assertTrue(result.configured)
        self.assertEqual(result.protected_interfaces, ("enp0s3",))
        self.assertEqual(result.ssh_service, "sshd.service")
        with self.assertRaises(FrozenInstanceError):
            result.platform = "pi4"

    def test_identity_ignores_formatting_and_protected_interface_order(self):
        self.data["protected_interfaces"] = ["wlan0", "enp0s3"]
        self.write()
        first = self.load()
        reversed_keys = dict(reversed(list(self.data.items())))
        reversed_keys["protected_interfaces"] = ["enp0s3", "wlan0"]
        self.path.write_text(json.dumps(reversed_keys, indent=4) + "\n")
        second = self.load()
        self.assertEqual(first.identity, second.identity)
        self.assertEqual(second.protected_interfaces, ("enp0s3", "wlan0"))

    def test_identity_changes_when_effective_settings_change(self):
        self.write()
        initial = self.load().identity
        self.data["ssh_service"] = "sshd.service"
        self.write()
        self.assertNotEqual(self.load().identity, initial)
        self.data["ssh_service"] = "ssh.service"
        self.data["protected_interfaces"] = []
        self.write()
        self.assertNotEqual(self.load().identity, initial)

    def test_explicit_configuration_and_automatic_defaults_have_distinct_identity(self):
        automatic = self.load()
        self.data["protected_interfaces"] = []
        self.write()
        explicit = self.load()
        self.assertNotEqual(automatic.identity, explicit.identity)
        self.assertEqual(automatic.platform, explicit.platform)

    def test_true_pi4_model_and_compatible_select_legacy_protection(self):
        self.device_tree()
        result = self.load()
        self.assertEqual(result.platform, "pi4")
        self.assertFalse(result.configured)
        self.assertEqual(result.protected_interfaces, ("ctrl0",))

    def test_other_boards_or_model_only_do_not_select_pi4(self):
        for model, compatible in (
            (b"Raspberry Pi 3 Model B Rev 1.2\0", b"raspberrypi,3-model-b\0"),
            (b"Raspberry Pi Compute Module 4 Rev 1.1\0", b"raspberrypi,4-compute-module\0"),
            (b"Raspberry Pi 4 Model B Rev 1.4\0", b"brcm,bcm2711\0"),
            (b"Raspberry Pi 4 Model B modified\0", b"raspberrypi,4-model-b\0brcm,bcm2711\0"),
        ):
            with self.subTest(model=model):
                self.device_tree(model, compatible)
                self.assertEqual(self.load().platform, "kali-host")

    def test_legacy_configuration_marker_does_not_spoof_hardware_identity(self):
        marker = self.root / "etc/pi4"
        marker.mkdir()
        (marker / "sshd_config").write_text("Pi4-looking configuration\n")
        self.assertEqual(self.load().platform, "kali-host")

    def test_explicit_host_profile_takes_precedence_over_pi4_device_tree(self):
        self.device_tree()
        self.write()
        self.assertEqual(self.load().platform, "kali-host")

    def test_exact_schema_rejects_missing_unknown_or_nonobject_values(self):
        missing = dict(self.data)
        missing.pop("ssh_service")
        for value in (missing, {**self.data, "command": "true"}, [], None):
            with self.subTest(value=value):
                self.path.write_text(json.dumps(value))
                self.path.chmod(0o644)
                with self.assertRaises(platform.ProfileError):
                    self.load()

    def test_duplicate_json_keys_are_rejected(self):
        raw = json.dumps(self.data).replace(
            '"platform": "kali-host"',
            '"platform": "pi4", "platform": "kali-host"',
        )
        self.path.write_text(raw)
        self.path.chmod(0o644)
        with self.assertRaisesRegex(platform.ProfileError, "duplicate"):
            self.load()

    def test_invalid_schema_platform_service_and_interfaces_are_rejected(self):
        changes = (
            {"schema_version": True}, {"schema_version": 2},
            {"platform": "pi4"}, {"platform": "windows"},
            {"ssh_service": "ssh.service;id"}, {"ssh_service": "/usr/bin/ssh"},
            {"protected_interfaces": "eth0"}, {"protected_interfaces": ["eth0", "eth0"]},
            {"protected_interfaces": ["../eth0"]}, {"protected_interfaces": ["has space"]},
            {"protected_interfaces": ["x" * 16]}, {"protected_interfaces": [1]},
            {"protected_interfaces": ["eth" + str(i) for i in range(33)]},
        )
        for change in changes:
            with self.subTest(change=change):
                self.write({**self.data, **change})
                with self.assertRaises(platform.ProfileError):
                    self.load()

    def test_malformed_json_utf8_and_oversized_profile_are_rejected(self):
        for content in (b"{not json", b"\xff", b" " * (platform.MAX_PROFILE_BYTES + 1)):
            with self.subTest(size=len(content)):
                self.path.write_bytes(content)
                self.path.chmod(0o644)
                with self.assertRaises(platform.ProfileError):
                    self.load()

    def test_profile_and_parent_symlinks_are_rejected(self):
        target = self.root / "actual-profile"
        target.write_text(json.dumps(self.data))
        self.path.symlink_to(target)
        with self.assertRaisesRegex(platform.ProfileError, "symlink"):
            self.load()
        self.path.unlink()
        self.directory.rmdir()
        self.directory.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(platform.ProfileError, "symlink"):
            self.load()

    def test_unsafe_profile_or_parent_write_permissions_are_rejected(self):
        self.write()
        for target, mode in ((self.path, 0o664), (self.path, 0o666),
                             (self.directory, 0o775), (self.directory, 0o777)):
            with self.subTest(target=target, mode=mode):
                previous = stat.S_IMODE(target.stat().st_mode)
                target.chmod(mode)
                try:
                    with self.assertRaisesRegex(platform.ProfileError, "writable"):
                        self.load()
                finally:
                    target.chmod(previous)

    def test_owner_is_rechecked_on_the_opened_profile(self):
        self.write()
        actual_fstat = os.fstat

        def foreign_owner(descriptor):
            values = list(actual_fstat(descriptor))
            values[4] = self.owner_uid + 1
            return os.stat_result(values)

        with patch.object(platform.os, "fstat", side_effect=foreign_owner):
            with self.assertRaisesRegex(platform.ProfileError, "root-owned"):
                self.load()

    def test_default_owner_expectation_remains_root(self):
        self.write()
        if self.owner_uid == 0:
            self.assertEqual(platform.load_profile(self.root).platform, "kali-host")
        else:
            with self.assertRaisesRegex(platform.ProfileError, "root-owned"):
                platform.load_profile(self.root)

    def test_nonregular_profile_and_untrusted_device_tree_are_rejected(self):
        self.path.mkdir()
        with self.assertRaisesRegex(platform.ProfileError, "file type"):
            self.load()
        self.path.rmdir()
        folder = self.device_tree()
        model = folder / "model"
        model.unlink()
        model.symlink_to(folder / "compatible")
        with self.assertRaisesRegex(platform.ProfileError, "symlink"):
            self.load()


if __name__ == "__main__":
    unittest.main()
