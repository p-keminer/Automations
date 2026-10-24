"""Source peers remain unique across code groups; installation uses fixed paths."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
spec = importlib.util.spec_from_file_location('source_layout_selection', ROOT / 'common/python/adapter_selection.py')
selection = importlib.util.module_from_spec(spec)
spec.loader.exec_module(selection)


class SourceLayoutTests(unittest.TestCase):
    def test_peers_resolve_to_one_canonical_source(self):
        for filename, group in [('auto_wifi.py', 'common'), ('auto_share.py', 'pi4'), ('host_ap.py', 'portable')]:
            with self.subTest(filename=filename):
                self.assertEqual(selection.source_peer(filename), ROOT / group / 'python' / filename)

    def test_duplicate_peers_are_refused_instead_of_silently_shadowed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for group in ('common', 'portable'):
                folder = root / group / 'python'
                folder.mkdir(parents=True)
                (folder / 'peer.py').write_text('fixture\n')
            with patch.object(selection, '__file__', str(root / 'common/python/adapter_selection.py')):
                with self.assertRaisesRegex(ValueError, 'Duplicate source peer'):
                    selection.source_peer('peer.py')

    def test_source_name_cannot_escape_the_code_groups(self):
        for value in ('../peer.py', '/tmp/peer.py', 'nested/peer.py', 'peer.sh'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                selection.source_peer(value)

    def test_installed_helper_does_not_search_the_checkout(self):
        with patch.object(selection, '__file__', '/usr/local/libexec/automations-support/adapter_selection.py'):
            self.assertEqual(selection.source_peer('host_ap.py'),
                             Path('/usr/local/libexec/automations-support/host_ap.py'))


if __name__ == '__main__':
    unittest.main()
