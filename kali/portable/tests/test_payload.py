import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'tools' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
payload, installer = load('payload'), load('install')


class VMPayloadTests(unittest.TestCase):
    def fixture_root(self, tmp):
        root = Path(tmp)
        root.chmod(0o755)
        return dict(_root=root, _owner_uid=os.geteuid())

    def test_nested_public_directories_and_payload_modes_under_umask_027(self):
        with tempfile.TemporaryDirectory() as tmp:
            options = self.fixture_root(tmp)
            root = Path(tmp)
            program = root / 'usr/local/libexec/automations-host/cert'
            support = root / 'usr/local/libexec/automations-support/platform_support.py'
            original_umask = os.umask(0o027)
            try:
                installer.atomic_write(program, b'public worker\n', 0o755, **options)
                installer.atomic_write(support, b'public support\n', 0o644, **options)
            finally:
                os.umask(original_umask)
            for path in (program, support):
                parent = path.parent
                while parent != root:
                    self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o755, str(parent))
                    parent = parent.parent
            self.assertEqual(stat.S_IMODE(program.stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE(support.stat().st_mode), 0o644)
            self.assertEqual(program.read_bytes(), b'public worker\n')

    def test_preflight_is_read_only_and_refuses_private_existing_public_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            options = self.fixture_root(tmp)
            parent = Path(tmp) / 'public'
            parent.mkdir()
            parent.chmod(0o750)
            target = parent / 'nested/worker'
            with self.assertRaisesRegex(ValueError, 'not traversable.*' + str(parent)):
                installer.check_parent_directories(target, **options)
            self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o750)
            self.assertFalse((parent / 'nested').exists())
            with self.assertRaisesRegex(ValueError, 'not traversable'):
                installer.atomic_write(target, b'worker', 0o755, **options)
            self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o750)
            self.assertFalse((parent / 'nested').exists())

    def test_preflight_missing_public_parent_does_not_create_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            options = self.fixture_root(tmp)
            installer.check_parent_directories(Path(tmp) / 'absent/nested/worker', **options)
            self.assertEqual(list(Path(tmp).iterdir()), [])

    def test_existing_traverse_only_configuration_parent_is_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            options = self.fixture_root(tmp)
            parent = Path(tmp) / 'automations'
            parent.mkdir()
            parent.chmod(0o751)
            installer.atomic_write(parent / 'platform.json', b'{}\n', 0o644, **options)
            self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o751)

    def test_private_registry_does_not_require_public_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            options = self.fixture_root(tmp)
            parent = Path(tmp) / 'registry'
            parent.mkdir()
            parent.chmod(0o700)
            receipt = parent / 'nested/install.json'
            original_umask = os.umask(0o027)
            try:
                installer.atomic_write(receipt, b'{"private":true}\n', 0o600,
                                       public=False, **options)
            finally:
                os.umask(original_umask)
            self.assertEqual(stat.S_IMODE(parent.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(receipt.stat().st_mode), 0o600)
            self.assertEqual(receipt.read_bytes(), b'{"private":true}\n')

    def test_symlink_and_writable_existing_parent_are_not_changed(self):
        for kind in ('symlink', 'writable'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as tmp:
                options = self.fixture_root(tmp)
                root = Path(tmp)
                parent = root / 'unsafe'
                if kind == 'symlink':
                    (root / 'actual').mkdir()
                    parent.symlink_to(root / 'actual', target_is_directory=True)
                else:
                    parent.mkdir()
                    parent.chmod(0o775)
                before = parent.lstat()
                with self.assertRaisesRegex(ValueError, 'Unsafe destination parent:'):
                    installer.atomic_write(parent / 'worker', b'worker', 0o755, **options)
                self.assertEqual(parent.lstat().st_mode, before.st_mode)
                self.assertFalse((parent / 'worker').exists())

    def test_only_expected_install_roots(self):
        for name in ('usr/bin/auto', 'usr/local/libexec/automations-host/tor',
                     'etc/systemd/system/automations-tor.service'):
            self.assertEqual(str(installer.destination(name)), '/' + name)
        for name in ('/etc/shadow', '../etc/shadow', 'etc/shadow', 'usr/bin/sh',
                     'etc/systemd/system/NetworkManager.service.d/a.conf',
                     'etc/systemd/system/automations-x.service.d/a.conf'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                installer.destination(name)

    def test_vm_selection_excludes_pi4_boot_and_network_policy(self):
        value = payload.payload()
        sources = {item['source'] for item in value['files']}
        self.assertFalse(sources & payload.EXCLUDED)
        destinations = {item['destination'] for item in value['files']}
        for name in ('ap', 'cert', 'fan', 'share', 'ssh', 'tor', 'wifi'):
            self.assertIn('usr/local/libexec/automations-host/' + name, destinations)
        self.assertFalse(any('NetworkManager.service.d/' in name or 'wifi-policy' in name
                             or 'share-watch' in name or 'fan-off' in name for name in destinations))

    def test_archive_reproducible_and_installer_hash_bound(self):
        with tempfile.TemporaryDirectory() as tmp:
            one, two = Path(tmp) / 'one.tar', Path(tmp) / 'two.tar'
            value = payload.archive(one)
            payload.archive(two)
            self.assertEqual(one.read_bytes(), two.read_bytes())
            manifest, files = installer.read_bundle(one)
            self.assertEqual(manifest, value)
            self.assertEqual(len(files), len(manifest['files']))

    def test_unsafe_archive_members_rejected_before_extraction(self):
        for name, kind in (('../escape', tarfile.REGTYPE), ('/escape', tarfile.REGTYPE),
                           ('link', tarfile.SYMTYPE)):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / 'unsafe.tar'
                with tarfile.open(path, 'w') as archive:
                    item = tarfile.TarInfo(name)
                    item.type, item.size = kind, 0
                    archive.addfile(item, io.BytesIO())
                with self.assertRaises(ValueError):
                    installer.read_bundle(path)


if __name__ == '__main__':
    unittest.main()
