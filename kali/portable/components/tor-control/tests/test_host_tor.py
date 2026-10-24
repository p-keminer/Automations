import hashlib
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[4]
spec = importlib.util.spec_from_file_location('host_tor_adapter', ROOT / 'portable/python/host_tor.py')
tor = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = tor
spec.loader.exec_module(tor)


class HostTorAdapterTests(unittest.TestCase):
    def test_explicit_host_only_selection(self):
        args, rest = tor.selection_args(['--on', '--lan', '--to', 'eth0', '--rotate-every', '2m'])
        self.assertEqual((args.to, args.mode), ('eth0', 'lan'))
        self.assertEqual(rest, ['--on', '--rotate-every', '2m'])

    def test_no_selection_for_existing_share_or_recovery(self):
        for argv in (['--on'], ['--status'], ['--recovery-worker'], ['--rotation-worker', '120']):
            args, rest = tor.selection_args(argv)
            self.assertEqual((args.to, args.mode), (None, None))
            self.assertEqual(rest, argv)

    def test_partial_or_misplaced_selection_rejected(self):
        for argv in (['--on', '--to', 'eth0'], ['--on', '--lan'],
                     ['--status', '--lan', '--to', 'eth0'],
                     ['--recovery-worker', '--lan', '--to', 'eth0']):
            with self.subTest(argv=argv), self.assertRaises(SystemExit):
                tor.selection_args(argv)

    def test_vm_definitions_bound_to_payloads(self):
        files = ROOT / 'portable/components/tor-control/files'
        paths = {tor.TORRC: files / 'torrc',
                 Path('/etc/systemd/system/automations-tor.service'): files / 'automations-tor.service',
                 Path('/etc/systemd/system/automations-tor-recovery.service'): files / 'automations-tor-recovery.service'}
        self.assertEqual(set(tor.DEFINITION_HASHES), set(paths))
        for path, source in paths.items():
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(), tor.DEFINITION_HASHES[path])
        self.assertNotIn(b'10.78.0.1', (files / 'torrc').read_bytes())

    def test_configure_keeps_common_protocol_code_and_exact_vm_runtime(self):
        module = mock.Mock()
        module.DEFINITION_HASHES = {Path('/usr/local/share/automations/tor/torrc'): 'pi4', Path('/common'): 'unchanged'}
        self.assertIs(tor.configure(module), module)
        self.assertEqual(module.RUNTIME, '/usr/local/libexec/automations-host/tor')
        self.assertEqual(module.SUPPORT, tor.SUPPORT)
        self.assertNotIn(Path('/usr/local/share/automations/tor/torrc'), module.DEFINITION_HASHES)
        self.assertEqual(module.DEFINITION_HASHES[Path('/common')], 'unchanged')

    def test_trusted_loader_rejects_replaceable_code(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'payload'
            path.write_text('executed = True')
            with self.assertRaises(tor.Error):
                tor.trusted_read(path)


if __name__ == '__main__':
    unittest.main()
