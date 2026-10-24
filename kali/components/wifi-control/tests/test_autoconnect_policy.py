import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("wifi_policy", ROOT / "python/wifi_autoconnect.py")
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)
IDENTIFIER = "11111111-1111-4111-8111-111111111111"


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = policy.Store(self.root / "state")
        self.settings = {"connection": {"uuid": IDENTIFIER, "type": "802-11-wireless", "autoconnect": True},
                         "802-11-wireless": {"mode": "infrastructure", "ssid": b"Probe"}}

    def test_default_unapproved_disabled_and_idempotent(self):
        changed = []
        before = copy.deepcopy(self.settings)
        self.assertTrue(policy.reconcile(self.settings, self.store, changed.append))
        self.assertEqual(changed, [IDENTIFIER])
        self.assertEqual(self.settings, before)
        self.settings["connection"]["autoconnect"] = False
        self.assertFalse(policy.reconcile(self.settings, self.store, changed.append))
        self.assertEqual(changed, [IDENTIFIER])

    def test_explicit_uuid_approval_survives_new_store_and_other_profiles_do_not(self):
        with self.store.locked():
            self.store.set(IDENTIFIER, True)
        fresh = policy.Store(self.store.directory)
        self.assertFalse(policy.reconcile(self.settings, fresh, lambda _: self.fail("Approved profile modified")))
        self.settings["connection"]["uuid"] = "22222222-2222-4222-8222-222222222222"
        changed = []
        policy.reconcile(self.settings, fresh, changed.append)
        self.assertEqual(changed, [self.settings["connection"]["uuid"]])
        with fresh.locked():
            fresh.set(IDENTIFIER, False)
            self.assertFalse(fresh.enabled(IDENTIFIER))

    def test_control_ap_and_ethernet_never_changed(self):
        for connection, wifi in [({"interface-name": "ctrl0"}, {}), ({}, {"mode": "ap"}),
                                 ({"type": "802-3-ethernet"}, {}), ({"uuid": "bad"}, {})]:
            settings = copy.deepcopy(self.settings)
            settings["connection"].update(connection)
            settings["802-11-wireless"].update(wifi)
            self.assertFalse(policy.reconcile(settings, self.store, lambda _: self.fail("Foreign profile modified")))

    def keyfile(self, bit=b"autoconnect=true\n", extra=b""):
        return (b"[connection]\nid=Profile\nuuid=" + IDENTIFIER.encode() + b"\ntype=wifi\n" + bit
                + extra + b"\n[wifi]\nmode=infrastructure\nssid=Probe\n\n[wifi-security]\npsk=TEST-ONLY-PLACEHOLDER\n\n[ipv6]\nmethod=auto\n")

    def test_preboot_patch_preserves_all_other_bytes_including_synthetic_secret(self):
        for bit in (b"autoconnect=true\n", b""):
            data = self.keyfile(bit)
            result = policy.normalized_keyfile(data, set())
            expected = data.replace(bit, b"autoconnect=false\n", 1) if bit else data.replace(b"[connection]\n", b"[connection]\nautoconnect=false\n", 1)
            self.assertEqual(result, expected)
            self.assertEqual(policy.normalized_keyfile(result, set()), result)
            self.assertEqual(policy.normalized_keyfile(data, {IDENTIFIER}), data)

    def test_preboot_control_and_ap_unchanged_and_duplicates_refused(self):
        for data in (self.keyfile(extra=b"interface-name=ctrl0\n"), self.keyfile().replace(b"infrastructure", b"ap")):
            self.assertEqual(policy.normalized_keyfile(data, set()), data)
        with self.assertRaises(policy.PolicyError):
            policy.normalized_keyfile(self.keyfile(b"autoconnect=true\nautoconnect=false\n"), set())

    @unittest.skipUnless(os.name == "posix", "POSIX permissions required")
    def test_preparation_atomic_mode_preservation_and_symlink_refusal(self):
        directory = self.root / "profiles"
        directory.mkdir(mode=0o700)
        profile = directory / "test.nmconnection"
        profile.write_bytes(self.keyfile())
        profile.chmod(0o600)
        self.assertEqual(policy.prepare([directory], self.store), 1)
        self.assertEqual(profile.stat().st_mode & 0o777, 0o600)
        self.assertEqual(policy.prepare([directory], self.store), 0)
        other = directory / "link.nmconnection"
        other.symlink_to(profile)
        with self.assertRaises(policy.PolicyError):
            policy.prepare([directory], self.store)

    def test_invalid_approval_data_refused(self):
        with self.store.locked():
            self.store.path.write_text(json.dumps({"schema_version": 1, "enabled": ["not-a-uuid"]}))
            with self.assertRaises(policy.PolicyError):
                self.store.read()

    def test_native_write_error_remains_an_error(self):
        def fail(_):
            raise policy.PolicyError("Native update failed")
        with self.assertRaises(policy.PolicyError):
            policy.reconcile(self.settings, self.store, fail)


if __name__ == "__main__":
    unittest.main()
