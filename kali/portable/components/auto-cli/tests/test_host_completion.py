"""Host completion fixtures: no command payload or networking tool is executed."""

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[4]
SPEC = importlib.util.spec_from_file_location('host_completion_reader', ROOT / 'common/python/auto_completion.py')
completion = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(completion)
DISPATCH_SPEC = importlib.util.spec_from_file_location('host_completion_dispatch', ROOT / 'common/python/auto.py')
dispatch = importlib.util.module_from_spec(DISPATCH_SPEC)
DISPATCH_SPEC.loader.exec_module(dispatch)


class HostCompletionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.owner_uid = os.getuid()
        self.commands = self.root / 'commands'
        self.backends = self.root / completion.HOST_DIRECTORY
        self.data = self.root / 'data'
        self.support = self.root / 'support'
        self.templates = self.root / 'templates'
        self.profile = self.root / completion.PROFILE_PATH
        self.helper = self.root / completion.PROFILE_HELPER
        self.sysroot = self.root / 'sys'
        self.sysnet = self.sysroot / 'class/net'
        self.marker = self.root / 'must-not-be-created'
        self.profile_value = {
            'schema_version': 1, 'platform': 'kali-host',
            'protected_interfaces': ['wlp2s0'], 'ssh_service': 'ssh.service',
        }
        for directory in (self.commands, self.backends, self.data, self.support, self.templates,
                          self.profile.parent, self.helper.parent, self.sysnet):
            directory.mkdir(parents=True, exist_ok=True)
        for bus in ('pci', 'usb', 'sdio'):
            (self.sysroot / 'bus' / bus).mkdir(parents=True)
        for directory in self.root.rglob('*'):
            if directory.is_dir():
                directory.chmod(0o755)
        self.helper.write_bytes((ROOT / 'common/python/platform_support.py').read_bytes())
        self.helper.chmod(0o644)
        self.write_profile()
        for name in ('wifi', 'ssh', 'share', 'fan'):
            self.command(name)
        for name in ('wifi', 'ssh', 'share'):
            self.command(name, host=True)
        for command, component in (('wifi', 'wifi-control'), ('ssh', 'ssh-control'),
                                   ('share', 'share-control')):
            manifest = json.loads((ROOT / 'common/components' / component / 'component.json').read_text())
            source = next(item['source'] for item in manifest['files'] if item['destination'] == 'usr/local/share/automations/completions/' + command)
            (self.data / command).write_bytes((ROOT / source).read_bytes())
        (self.support / 'hotspot.py').write_text('raise RuntimeError("must not import")\n')
        (self.data / 'share-ap').write_text('--interface\n--off\n--status\n--help\n')
        self.radio('wlp2s0', phy=0, index=2)
        self.radio('wlp3s0', phy=1, index=3)
        self.radio('wlx1', bus='usb', phy=2, index=4)
        self.physical('eth0', 5)
        (self.sysnet / 'lo').mkdir()
        (self.sysnet / 'veth0').mkdir()

    def write_profile(self):
        self.profile.write_text(json.dumps(self.profile_value))
        self.profile.chmod(0o644)

    def command(self, name, *, host=False, mode=0o755):
        path = (self.backends if host else self.commands) / name
        path.write_text('#!/usr/bin/python3\nfrom pathlib import Path\nPath(' + repr(str(self.marker)) + ').touch()\n')
        path.chmod(mode)
        return path

    def physical(self, name, index):
        device = self.sysroot / f'devices/pci0000:00/0000:02:{index:02x}.0'
        device.mkdir(parents=True)
        (device / 'subsystem').symlink_to(self.sysroot / 'bus/pci')
        (device / 'vendor').write_text('0x8086\n')
        (device / 'device').write_text('0x2723\n')
        entry = self.sysnet / name
        entry.mkdir()
        (entry / 'device').symlink_to(device)
        (entry / 'ifindex').write_text(str(index))
        return entry, device

    def radio(self, name, *, bus='pci', phy, index, shared=None):
        if shared is not None:
            original = self.sysnet / shared
            device = (original / 'device').resolve()
            phy_path = (original / 'phy80211').resolve()
            entry = self.sysnet / name
            entry.mkdir()
            (entry / 'device').symlink_to(device)
            (entry / 'ifindex').write_text(str(index))
        elif bus == 'pci':
            entry, device = self.physical(name, index)
            phy_path = device / f'ieee80211/phy{phy}'
        else:
            parent = self.sysroot / f'devices/{bus}{index}/radio{index}'
            device = parent / f'{index}:1.0'
            device.mkdir(parents=True)
            if bus == 'usb':
                (parent / 'idVendor').write_text('148f\n')
                (parent / 'idProduct').write_text('3572\n')
                (parent / 'subsystem').symlink_to(self.sysroot / 'bus/usb')
            else:
                (device / 'subsystem').symlink_to(self.sysroot / 'bus/sdio')
            entry = self.sysnet / name
            entry.mkdir()
            (entry / 'device').symlink_to(device)
            (entry / 'ifindex').write_text(str(index))
            phy_path = device / f'ieee80211/phy{phy}'
        phy_path.mkdir(parents=True, exist_ok=True)
        (entry / 'phy80211').symlink_to(phy_path)
        return entry, device

    def suggest(self, *words):
        result = completion.candidates(
            list(words), len(words) - 1, commands=self.commands, data=self.data,
            sysnet=self.sysnet, support=self.support, templates=self.templates,
            _profile_root=self.root, _owner_uid=self.owner_uid,
        )
        self.assertFalse(self.marker.exists(), 'Completion executed a command payload.')
        return result

    def test_host_discovery_matches_dispatcher_help_intersection(self):
        self.command('orphan', host=True)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = dispatch.main(['--help'], directory=self.commands,
                                 _profile_root=self.root, _owner_uid=self.owner_uid)
        self.assertEqual(code, 0)
        expected = {line.strip() for line in output.getvalue().splitlines() if line.startswith('  ')}
        self.assertEqual(set(self.suggest('auto', '')), {'--help', *expected})
        self.assertEqual(self.suggest('auto', 'f'), [])
        self.assertEqual(self.suggest('auto', 'fan', '--'), [])
        self.assertEqual(self.suggest('auto', 'orphan', '--'), [])

    def test_vm_ap_completion_requires_owned_helper_and_vm_metadata(self):
        self.assertEqual(self.suggest('auto', 'share', 'ap', '--'), [])
        (self.support / 'host_ap.py').write_text('raise RuntimeError("must not execute")\n')
        (self.support / 'host_ap.py').chmod(0o644)
        (self.data / 'share-ap-vm').write_bytes((ROOT / 'portable/components/hotspot-control/files/completion').read_bytes())
        (self.data / 'share-ap-vm').chmod(0o644)
        self.assertEqual(self.suggest('auto', 'share', 'a'), ['ap'])
        self.assertEqual(set(self.suggest('auto', 'share', 'ap', '--')),
                         {'--on', '--off', '--status', '--interface', '--password-file', '--help', '--template'})
        self.assertEqual(self.suggest('auto', 'share', 'ap', '--interface', ''), ['wlp3s0', 'wlx1'])
        self.assertEqual(self.suggest('auto', 'share', 'ap', '--password-file', ''), [])
        (self.templates/'welcome').mkdir()
        (self.templates/'welcome/index.html').write_text('<h1>local</h1>')
        self.assertEqual(self.suggest('auto', 'share', 'ap', '--template', 'wel'), ['welcome'])
        self.assertEqual(self.suggest('auto', 'share', 'ap', '--template=wel'), ['--template=welcome'])
        (self.support / 'host_ap.py').chmod(0o666)
        self.assertEqual(self.suggest('auto', 'share', 'ap', '--'), [])

    def test_vm_tor_selection_completion_and_no_internal_worker_flags(self):
        self.command('tor')
        self.command('tor', host=True)
        (self.data / 'tor-vm').write_bytes((ROOT / 'portable/components/tor-control/files/completion').read_bytes())
        (self.data / 'tor-vm').chmod(0o644)
        flags = self.suggest('auto', 'tor', '--')
        self.assertIn('--to', flags)
        self.assertIn('--lan', flags)
        self.assertNotIn('--recovery-worker', flags)
        self.assertNotIn('--rotation-worker', flags)
        self.assertEqual(self.suggest('auto', 'tor', '--lan', '--to', ''), ['eth0'])
        self.assertEqual(self.suggest('auto', 'tor', '--wifi', '--to', ''), ['wlp3s0', 'wlx1'])
        self.assertIn('2m', self.suggest('auto', 'tor', '--rotate-every', ''))

    def test_wifi_and_ssh_keep_existing_option_metadata_and_help(self):
        for name in ('wifi', 'ssh'):
            with self.subTest(name=name):
                expected = set((self.data / name).read_text().splitlines())
                self.assertEqual(set(self.suggest('auto', name, '--')), expected)
                self.assertEqual(self.suggest('auto', name, '--he'), ['--help'])

    def test_nonexecutable_or_symlink_backend_is_unavailable(self):
        backend = self.backends / 'wifi'
        backend.chmod(0o644)
        self.assertNotIn('wifi', self.suggest('auto', ''))
        self.assertEqual(self.suggest('auto', 'wifi', '--'), [])
        backend.unlink()
        backend.symlink_to(self.commands / 'wifi')
        self.assertNotIn('wifi', self.suggest('auto', ''))
        self.assertEqual(self.suggest('auto', 'wifi', '--'), [])

    def test_unsafe_backend_or_parent_fails_closed(self):
        for path in (self.backends / 'wifi', self.backends):
            with self.subTest(path=path):
                mode = path.stat().st_mode & 0o777
                path.chmod(0o777)
                self.assertEqual(self.suggest('auto', ''), [])
                self.assertEqual(self.suggest('auto', 'wifi', '--'), [])
                path.chmod(mode)

    def test_invalid_profile_never_offers_legacy_fallback(self):
        for value in ('{invalid', json.dumps({**self.profile_value, 'extra': True}),
                      json.dumps({**self.profile_value, 'platform': 'pi4'}),
                      '{"schema_version":1,"schema_version":1}',
                      json.dumps({**self.profile_value, 'protected_interfaces': ['bad/name']})):
            with self.subTest(value=value):
                self.profile.write_text(value)
                self.assertEqual(self.suggest('auto', ''), [])
                self.assertEqual(self.suggest('auto', 'wifi', '--'), [])

    def test_unsafe_or_dangling_profile_is_not_legacy_mode(self):
        self.profile.chmod(0o666)
        self.assertEqual(self.suggest('auto', ''), [])
        self.profile.unlink()
        self.profile.symlink_to(self.root / 'missing-profile')
        self.assertEqual(self.suggest('auto', ''), [])
        self.assertEqual(self.suggest('auto', 'wifi', '--'), [])

    def test_missing_or_unsafe_helper_is_rejected_before_evaluation(self):
        self.helper.write_bytes((self.commands / 'wifi').read_bytes())
        self.helper.chmod(0o666)
        self.assertEqual(self.suggest('auto', ''), [])
        self.helper.unlink()
        self.assertEqual(self.suggest('auto', ''), [])
        self.assertEqual(self.suggest('auto', 'wifi', '--'), [])

    def test_missing_profile_preserves_legacy_discovery_without_loading_helper(self):
        self.profile.unlink()
        self.helper.write_text('raise RuntimeError("must not load")\n')
        self.helper.chmod(0o666)
        self.assertEqual(set(self.suggest('auto', '')), {'--help', 'fan', 'share', 'ssh', 'wifi'})
        self.assertEqual(self.suggest('auto', 'share', 'a'), ['ap'])

    def test_host_wifi_offers_identified_pci_and_usb_and_protects_radio_siblings(self):
        self.radio('protected-sib', phy=0, index=8, shared='wlp2s0')
        self.assertEqual(set(self.suggest('auto', 'wifi', '--interface', '')), {'wlp3s0', 'wlx1'})
        self.assertEqual(self.suggest('auto', 'wifi', '--interface=wlp'), ['--interface=wlp3s0'])

    def test_unprotected_ctrl0_is_an_ordinary_host_interface(self):
        self.radio('ctrl0', bus='usb', phy=4, index=9)
        self.assertIn('ctrl0', self.suggest('auto', 'wifi', '--interface', ''))

    def test_unsupported_or_unidentified_wireless_bus_is_not_offered(self):
        self.radio('sdio0', bus='sdio', phy=5, index=10)
        self.assertEqual(set(self.suggest('auto', 'wifi', '--interface', '')), {'wlp3s0', 'wlx1'})
        (self.sysnet / 'wlp3s0/device').resolve().joinpath('vendor').write_text('invalid\n')
        self.assertEqual(self.suggest('auto', 'wifi', '--interface', ''), [])

    def test_invalid_usb_identity_or_wireless_ifindex_fails_closed(self):
        device = (self.sysnet / 'wlx1/device').resolve()
        (device.parent / 'idProduct').write_text('not-hex\n')
        self.assertEqual(self.suggest('auto', 'wifi', '--interface', ''), [])
        (device.parent / 'idProduct').write_text('3572\n')
        (self.sysnet / 'wlx1/ifindex').write_text('0\n')
        self.assertEqual(self.suggest('auto', 'wifi', '--interface', ''), [])

    def test_host_share_keeps_legacy_alias_hidden_but_completes_its_values(self):
        with (self.data / 'share').open('a') as stream:
            stream.write('--interface\n')
        self.assertEqual(set(self.suggest('auto', 'share', '')), {'--wifi', '--lan', '--off', '--status', '--help', '--to', '--from'})
        self.assertEqual(self.suggest('auto', 'share', 'a'), [])
        self.assertEqual(self.suggest('auto', 'share', 'ap', ''), [])
        self.assertEqual(set(self.suggest('auto', 'share', '--interface', '')), {'eth0','wlp3s0','wlx1'})
        self.assertEqual(set(self.suggest('auto', 'share', '--interface=')), {'--interface=eth0','--interface=wlp3s0','--interface=wlx1'})

    def test_host_share_sources_are_physical_and_do_not_inherit_uplink_medium(self):
        expected = {'host', 'eth0', 'wlp3s0', 'wlx1'}
        for medium in ('--wifi', '--lan'):
            with self.subTest(medium=medium):
                self.assertEqual(set(self.suggest('auto', 'share', medium, '--from', '')), expected)
        self.assertEqual(self.suggest('auto', 'share', '--wifi', '--from', 'eth0,wl'), ['eth0,wlp3s0', 'eth0,wlx1'])
        self.assertEqual(self.suggest('auto', 'share', '--lan', '--from=eth0,eth'), [])
        self.assertEqual(self.suggest('auto', 'share', '--lan', '--from=host,'), [])
        self.assertEqual(self.suggest('auto', 'share', '--lan', '--from=eth0,h'), [])
        self.assertEqual(set(self.suggest('auto', 'share', '--wifi', '--to', '')), {'wlp3s0', 'wlx1'})
        self.assertEqual(self.suggest('auto', 'share', '--lan', '--to', ''), ['eth0'])

    def test_host_share_protects_named_ethernet_and_hardware_siblings(self):
        self.profile_value['protected_interfaces'].append('eth0')
        self.write_profile()
        entry = self.sysnet / 'eth-sibling'
        entry.mkdir()
        (entry / 'device').symlink_to((self.sysnet / 'eth0/device').resolve())
        self.radio('protected-sib', phy=0, index=8, shared='wlp2s0')
        self.assertEqual(set(self.suggest('auto', 'share', '--from', '')), {'host','wlp3s0', 'wlx1'})

    def bridge(self):
        bridge = self.root / 'reader.py'
        bridge.write_text(
            'import importlib.util, os, sys\nfrom pathlib import Path\n'
            's = importlib.util.spec_from_file_location("completion", ' + repr(str(ROOT / 'common/python/auto_completion.py')) + ')\n'
            'm = importlib.util.module_from_spec(s)\ns.loader.exec_module(m)\n'
            'for value in m.candidates(sys.argv[2:], int(sys.argv[1]), '
            'commands=Path(' + repr(str(self.commands)) + '), data=Path(' + repr(str(self.data)) + '), '
            'sysnet=Path(' + repr(str(self.sysnet)) + '), support=Path(' + repr(str(self.support)) + '), '
            '_profile_root=Path(' + repr(str(self.root)) + '), _owner_uid=os.getuid()):\n    print(value)\n'
        )
        return bridge

    def test_bash_wrapper_passes_the_same_host_candidates(self):
        wrapper = self.root / 'completion.sh'
        wrapper.write_text((ROOT / 'common/shell/bash/auto-completion.sh').read_text().replace(
            '/usr/local/libexec/automations-support/completion.py', str(self.bridge())))
        script = ('source ' + shlex.quote(str(wrapper)) + '\n'
                  'COMP_WORDS=(auto wifi --interface w)\nCOMP_CWORD=3\n_auto_complete\n'
                  'printf "%s\\n" "${COMPREPLY[@]}"\n')
        result = subprocess.run(['bash', '--noprofile', '--norc'], input=script,
                                capture_output=True, text=True, cwd=self.root,
                                env={'PATH': '/usr/bin:/bin', 'HOME': str(self.root), 'BASH_ENV': '/dev/null'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(set(result.stdout.splitlines()), {'wlp3s0', 'wlx1'})
        self.assertFalse(self.marker.exists())

    def test_zsh_wrapper_passes_the_same_host_candidates_without_file_fallback(self):
        if shutil.which('zsh') is None:
            self.skipTest('Zsh is not installed.')
        wrapper = self.root / '_auto'
        wrapper.write_text((ROOT / 'common/shell/zsh/_auto').read_text().replace(
            '/usr/local/libexec/automations-support/completion.py', str(self.bridge())))
        script = ('compadd() { [[ "$1" == -Q && "$2" == -- ]] || return 91; shift 2; printf "%s\\n" "$@"; }\n'
                  '_auto() { source ' + shlex.quote(str(wrapper)) + '; }\n'
                  'words=(auto wifi --interface w); CURRENT=4; _auto\n'
                  'words=(auto fan --); CURRENT=3; _auto\n')
        result = subprocess.run(['zsh', '-df'], input=script, capture_output=True,
                                text=True, cwd=self.root,
                                env={'PATH': '/usr/bin:/bin', 'HOME': str(self.root)})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(set(result.stdout.splitlines()), {'wlp3s0', 'wlx1'})
        self.assertFalse(self.marker.exists())


if __name__ == '__main__':
    unittest.main()
