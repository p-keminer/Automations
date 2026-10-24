"""Host AP transaction, secret handling, hardware and ownership boundaries."""

from collections import namedtuple
import contextlib
from dataclasses import dataclass
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
SPEC = importlib.util.spec_from_file_location('host_ap_module', ROOT / 'portable/python/host_ap.py')
ap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ap)
Adapter = namedtuple('Adapter', 'name index phy phy_path device_path usb_id bus hardware_id')


@dataclass(frozen=True)
class Profile:
    platform: str = 'kali-host'
    configured: bool = True
    protected_interfaces: tuple = ()
    ssh_service: str = 'ssh.service'
    identity: str = 'a' * 64


class Radio:
    def __init__(self, fixture):
        self.fixture = fixture
        self.root = fixture.root / 'sys'
        self.host_profile = Profile()
        self.owner_uid = os.getuid()
        self.adapters = {}
        for name, index in [('wlan0', 3), ('wlan1', 4)]:
            phy = 'phy' + str(index)
            device = fixture.root / ('sys/devices/usb1/1-' + str(index))
            (device / 'ieee80211' / phy).mkdir(parents=True)
            self.adapters[name] = Adapter(name, index, phy, str(device / 'ieee80211' / phy), str(device),
                                          '0bda:b832', 'usb', '0bda:b832')
            fixture.file('/proc/sys/net/ipv4/conf/' + name + '/forwarding', '0\n')

    def devices(self):
        return self.adapters

    def guard(self, item, *, exclusive=False):
        ap.require(self.adapters.get(item.name) == item and item.name not in self.host_profile.protected_interfaces,
                   'Fixture radio identity changed.')

    def read_state(self, item):
        return SimpleNamespace(mode=self.fixture.mode, managed=self.fixture.managed,
                               connection=self.fixture.active or None, nm_state=100 if self.fixture.active else 30,
                               addresses=tuple(self.fixture.addresses), autoconnect=self.fixture.autoconnect)


class Fixture:
    def __init__(self, root):
        self.root, self.calls = root, []
        self.mode, self.managed, self.autoconnect = 'managed', True, True
        self.active, self.addresses, self.profiles = '', [], {}
        self.routes, self.service = [], None
        self.fail_up = None
        self.after_down = None
        (root / 'run/NetworkManager/system-connections').mkdir(parents=True)
        self.file('/proc/sys/kernel/random/boot_id', '00000000-0000-4000-8000-000000000001\n')
        for filename in (ap.NMCLI, ap.IP, ap.IW, ap.SYSTEMCTL, ap.SYSTEMD_RUN, ap.DNSMASQ):
            self.file(filename, 'fixture executable', 0o755)
        self.radio = Radio(self)

    def file(self, filename, contents, mode=0o644):
        target = self.root / filename.lstrip('/')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents)
        target.chmod(mode)
        return target

    @staticmethod
    def parse_key(text):
        groups, group = {}, None
        for line in text.splitlines():
            if line.startswith('['):
                group = line[1:-1]
            elif '=' in line:
                key, value = line.split('=', 1)
                value = value.replace('\\s', ' ').replace('\\\\', '\\')
                if group == 'wifi' and key == 'ssid':
                    value = bytes(int(byte) for byte in value.rstrip(';').split(';')).decode('utf-8')
                groups[group + '.' + key] = value
        fields = {}
        for key, value in groups.items():
            if key.startswith('wifi-security.'):
                key = key.replace('wifi-security.', '802-11-wireless-security.', 1)
            elif key.startswith('wifi.'):
                key = key.replace('wifi.', '802-11-wireless.', 1)
            if key in ('connection.autoconnect', '802-11-wireless.hidden', 'ipv4.never-default'):
                value = {'true': 'yes', 'false': 'no'}[value]
            if key == 'ipv4.address1':
                key = 'ipv4.addresses'
            fields[key] = value
        return fields

    def __call__(self, args, *, timeout=15):
        self.calls.append((args, timeout))
        if args[0] == ap.NMCLI:
            if args[1:4] == ['--escape', 'no', '-g']:
                field, query = args[4], args[5:]
                if query[:2] == ['connection', 'show'] and field == 'UUID' and len(query) == 2:
                    return '\n'.join(self.profiles) + ('\n' if self.profiles else '')
                if query[:2] == ['connection', 'show']:
                    return self.profiles[query[-1]]['fields'][field] + '\n'
                if query[:2] == ['device', 'show']:
                    return (self.active if field == 'GENERAL.CON-UUID' else '100 (connected)' if self.active else '30 (disconnected)') + '\n'
                raise AssertionError(args)
            if args[1:4] == ['connection', 'load', args[-1]]:
                path = self.root / args[-1].lstrip('/')
                fields = self.parse_key(path.read_text())
                self.profiles[fields['connection.uuid']] = dict(fields=fields, path=path)
                return ''
            if args[1:3] == ['device', 'set']:
                self.autoconnect = args[-1] == 'yes'
                return ''
            if args[1:3] == ['--wait', str(ap.ACTIVATION_SECONDS)] and args[3:5] == ['connection', 'up']:
                if self.active:
                    raise AssertionError('A connection must be explicitly deactivated before another activation.')
                if self.fail_up:
                    error, self.fail_up = self.fail_up, None
                    raise error
                self.active = args[6]
                self.mode, self.addresses = 'AP', [ap.ADDRESS]
                return ''
            if args[1:3] == ['--wait', '30'] and args[3:5] == ['connection', 'down']:
                self.active, self.mode, self.addresses = '', 'managed', []
                if self.after_down is not None:
                    self.after_down()
                return ''
            if args[1:3] == ['connection', 'delete']:
                item = self.profiles.pop(args[-1])
                item['path'].unlink()
                return ''
            raise AssertionError(args)
        if args[0] == ap.IP:
            if args[1:] == ['-j', '-4', 'route', 'show', 'table', 'all']:
                return json.dumps(self.routes)
            if args[1:6] == ['-j', '-4', 'address', 'show', 'dev']:
                item = self.radio.adapters[args[-1]]
                return json.dumps([dict(ifindex=item.index, addr_info=[dict(local='10.79.0.1', prefixlen=24, scope='global')]
                                       if self.active else [])])
            raise AssertionError(args)
        if args[0] == ap.IW:
            if args[1] == 'phy':
                return 'Supported interface modes:\n\t * managed\n\t * AP\n'
            item = self.radio.adapters[args[2]]
            return 'Interface ' + item.name + '\n\tifindex ' + str(item.index) + '\n\twiphy ' + item.phy[3:] + '\n\ttype ' + self.mode + '\n'
        if args[0] == ap.DNSMASQ:
            return ''
        if args[0] == ap.SYSTEMD_RUN:
            unit = next(word[7:] for word in args if word.startswith('--unit='))
            description = next(word[14:] for word in args if word.startswith('--description='))
            self.service = dict(unit=unit, description=description, state='active', pid='4321', transient='yes')
            command = args[args.index('--') + 1:]
            self.file('/proc/4321/cmdline', '\0'.join(command) + '\0')
            return ''
        if args[0] == ap.SYSTEMCTL:
            if args[1] == 'stop':
                self.service['state'] = 'inactive'
                return ''
            if args[1] == 'start':
                self.service['state'] = 'active'
                return ''
            if not self.service or self.service['unit'] != args[2]:
                return 'LoadState=not-found\nActiveState=inactive\nMainPID=0\n'
            executable = self.service.get('exec_start', '{ path=' + ap.DNSMASQ + ' ; argv[]=' +
                ' '.join([ap.DNSMASQ, '--keep-in-foreground', '--conf-file=' + ap.RUNTIME + '/dnsmasq.conf']) +
                ' ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=4321 ; code=(null) ; status=0/0 }')
            return ('LoadState=loaded\nTransient=' + self.service['transient'] + '\nActiveState=' + self.service['state']
                    + '\nMainPID=' + self.service['pid'] + '\nDescription=' + self.service['description']
                    + '\nFragmentPath=/run/systemd/transient/' + self.service['unit']
                    + '\nDropInPaths=\nType=exec\nUser=\nGroup=\nKillMode=control-group\nExecStart=' + executable + '\n')
        raise AssertionError(args)


class HostAPTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.fixture = Fixture(self.root)
        self.service = ap.HostAP(Profile(), root=self.root, runner=self.fixture, owner_uid=os.getuid(), radio=self.fixture.radio)
        self.privileges = patch.object(ap.os, 'geteuid', return_value=0)
        self.privileges.start()

    def tearDown(self):
        self.privileges.stop()
        self.temp.cleanup()

    def start(self, **kwargs):
        return self.service.on('wlan0', 'Test AP', 'private-passphrase', **kwargs)

    def test_full_lifecycle_preserves_device_policy_and_removes_only_owned_profiles(self):
        unrelated = self.fixture.file('/run/NetworkManager/system-connections/existing.nmconnection', 'unrelated', 0o600)
        self.fixture.profiles['unrelated'] = dict(fields={}, path=unrelated)
        result = self.start()
        self.assertTrue(result['active'])
        self.assertFalse(self.fixture.autoconnect)
        self.assertEqual(result['ssid'], 'Test AP')
        state = self.service.load()
        self.assertEqual(self.service.trusted(self.service.key_path(state), private=True).stat().st_mode & 0o777, 0o600)
        self.assertFalse(self.service.off()['active'])
        self.assertTrue(self.fixture.autoconnect)
        self.assertEqual(set(self.fixture.profiles), {'unrelated'})
        self.assertEqual(unrelated.read_text(), 'unrelated')
        self.assertFalse((self.root / ap.RUNTIME.lstrip('/')).exists())

    def test_no_credentials_in_receipt_command_arguments_or_output(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            ap.print_status(self.start())
        state = self.service.load()
        self.assertNotIn('private-passphrase', json.dumps(state))
        self.assertNotIn('private-passphrase', json.dumps(self.fixture.calls))
        self.assertNotIn('private-passphrase', out.getvalue())

    def test_bound_activation_timeout_supports_slow_ax(self):
        self.start()
        activations = [(args, timeout) for args, timeout in self.fixture.calls if args[:3] == [ap.NMCLI, '--wait', '150']]
        self.assertEqual(len(activations), 1)
        self.assertGreaterEqual(activations[0][1], 150)

    def test_wpa2_manual_address_never_uses_nm_shared_mode(self):
        self.start()
        state = self.service.load()
        fields = self.fixture.profiles[state['connection']]['fields']
        self.assertEqual(fields['ipv4.method'], 'manual')
        self.assertEqual(fields['ipv6.method'], 'disabled')
        self.assertEqual(fields['802-11-wireless-security.key-mgmt'], 'wpa-psk')
        self.assertEqual(fields['802-11-wireless-security.proto'], 'rsn;')
        self.assertEqual(fields['802-11-wireless.ap-isolation'], '1')
        self.assertFalse(any(args[0].endswith('nft') for args, _ in self.fixture.calls))

    def test_utf8_and_decimal_looking_ssid_roundtrip_as_exact_bytes(self):
        for name in ('65;66;', ' AP ünicode\\;'):
            with self.subTest(name=name):
                self.assertEqual(self.service.on('wlan0', name, 'private-passphrase')['ssid'], name)
                self.service.off()

    def test_dhcp_is_confined_to_selected_ap_and_does_not_resolve_dns(self):
        self.start()
        state = self.service.load()
        text = (self.root / ap.RUNTIME.lstrip('/') / 'dnsmasq.conf').read_text()
        self.assertIn('port=0\n', text)
        self.assertIn('interface=wlan0\nbind-interfaces\nexcept-interface=lo', text)
        self.assertIn('dhcp-option=option:dns-server,10.79.0.1', text)
        calls = [args for args, _ in self.fixture.calls if args[0] == ap.SYSTEMD_RUN]
        self.assertEqual(len(calls), 1)
        self.assertIn('--property=UMask=0077', calls[0])
        self.assertIn('--property=KillMode=control-group', calls[0])
        self.assertTrue(self.service.verify_service(state))

    def test_no_dhcp_option_has_no_service(self):
        self.assertFalse(self.start(dhcp=False)['dhcp'])
        self.assertIsNone(self.fixture.service)
        self.assertFalse(self.service.off()['active'])

    def test_genuine_dnsmasq_0644_lease_database_is_cleaned_inside_private_runtime(self):
        self.start()
        self.fixture.file(ap.RUNTIME + '/leases', '', 0o644)
        self.assertFalse(self.service.off()['active'])
        self.assertFalse(self.service.path(ap.RUNTIME).exists())

    def test_lease_exception_does_not_weaken_other_runtime_permissions(self):
        self.start()
        self.service.path(ap.RUNTIME + '/dnsmasq.conf').chmod(0o644)
        before = len(self.fixture.calls)
        with self.assertRaisesRegex(ap.Error, 'private file permissions'):
            self.service.off()
        self.assertFalse(any(args[0] == ap.SYSTEMCTL and args[1] == 'stop' for args, _ in self.fixture.calls[before:]))

    def test_group_writable_lease_database_is_not_removed(self):
        self.start()
        path = self.fixture.file(ap.RUNTIME + '/leases', '', 0o664)
        with self.assertRaisesRegex(ap.Error, 'writable by another user'):
            self.service.off()
        self.assertTrue(path.exists())
        self.assertEqual(self.fixture.service['state'], 'active')

    def test_symlink_lease_database_is_not_removed(self):
        self.start()
        target = self.fixture.file('/run/other-leases', '', 0o644)
        self.service.path(ap.RUNTIME + '/leases').symlink_to(target)
        with self.assertRaisesRegex(ap.Error, 'lease database'):
            self.service.off()
        self.assertTrue(target.exists())
        self.assertEqual(self.fixture.service['state'], 'active')

    def test_hardlink_lease_database_is_not_removed(self):
        self.start()
        target = self.fixture.file('/run/other-leases', '', 0o644)
        os.link(target, self.service.path(ap.RUNTIME + '/leases'))
        with self.assertRaisesRegex(ap.Error, 'Unsafe AP path type'):
            self.service.off()
        self.assertEqual(target.stat().st_nlink, 2)

    def test_oversized_lease_database_is_not_removed(self):
        self.start()
        target = self.fixture.file(ap.RUNTIME + '/leases', 'x' * 65537, 0o644)
        with self.assertRaisesRegex(ap.Error, 'lease database'):
            self.service.off()
        self.assertTrue(target.exists())

    def test_visibility_reactivates_and_verifies_owned_radio(self):
        self.start()
        before = len(self.fixture.calls)
        self.assertTrue(self.service.visibility(True)['hidden'])
        operations = self.fixture.calls[before:]
        stop = next(index for index, (args, _) in enumerate(operations) if args[:2] == [ap.SYSTEMCTL, 'stop'])
        down = next(index for index, (args, _) in enumerate(operations) if args[:5] == [ap.NMCLI, '--wait', '30', 'connection', 'down'])
        load = next(index for index, (args, _) in enumerate(operations) if args[:3] == [ap.NMCLI, 'connection', 'load'])
        up = next(index for index, (args, _) in enumerate(operations) if args[:5] == [ap.NMCLI, '--wait', '150', 'connection', 'up'])
        restart = next(index for index, (args, _) in enumerate(operations) if args[:2] == [ap.SYSTEMCTL, 'start'])
        self.assertLess(stop, down)
        self.assertLess(down, load)
        self.assertLess(load, up)
        self.assertLess(up, restart)
        self.assertFalse(self.service.visibility(False)['hidden'])
        self.assertEqual(len([args for args, _ in self.fixture.calls if args[:3] == [ap.NMCLI, '--wait', '150']]), 3)
        self.service.off()

    def test_active_nm_connection_cannot_be_reactivated_by_fixture(self):
        self.start()
        state = self.service.load()
        with self.assertRaisesRegex(AssertionError, 'explicitly deactivated'):
            self.fixture([ap.NMCLI, '--wait', '150', 'connection', 'up', 'uuid', state['connection'], 'ifname', 'wlan0'])

    def test_visibility_refuses_up_until_radio_is_quiescent(self):
        self.start()
        self.fixture.after_down = lambda: setattr(self.fixture, 'mode', 'AP')
        before = len(self.fixture.calls)
        with self.assertRaisesRegex(ap.Error, 'visibility activation failed'):
            self.service.visibility(True)
        self.assertFalse(any(args[:5] == [ap.NMCLI, '--wait', '150', 'connection', 'up']
                             for args, _ in self.fixture.calls[before:]))
        self.assertEqual(self.fixture.service['state'], 'inactive')
        self.assertEqual(self.service.load()['phase'], 'changing')

    def test_visibility_quiescence_rejects_replacement_hardware(self):
        self.start()
        original = self.fixture.radio.adapters['wlan0']
        self.fixture.after_down = lambda: self.fixture.radio.adapters.update(wlan0=original._replace(index=99))
        before = len(self.fixture.calls)
        with self.assertRaisesRegex(ap.Error, 'visibility activation failed'):
            self.service.visibility(True)
        self.assertFalse(any(args[:5] == [ap.NMCLI, '--wait', '150', 'connection', 'up']
                             for args, _ in self.fixture.calls[before:]))
        self.assertEqual(self.fixture.service['state'], 'inactive')

    def test_stopped_foreign_service_command_is_not_restarted(self):
        self.start()
        state = self.service.load()
        self.fixture.service.update(state='inactive', exec_start='{ path=/bin/sleep ; argv[]=/bin/sleep infinity }')
        before = len(self.fixture.calls)
        with self.assertRaisesRegex(ap.Error, 'service identity'):
            self.service.start_dhcp(state)
        self.assertFalse(any(args[:2] == [ap.SYSTEMCTL, 'start'] for args, _ in self.fixture.calls[before:]))

    def test_visibility_without_dhcp_still_deactivates_before_up(self):
        self.start(dhcp=False)
        self.assertTrue(self.service.visibility(True)['hidden'])
        self.assertIsNone(self.fixture.service)
        self.assertFalse(any(args[0] == ap.SYSTEMCTL and args[1] in ('start', 'stop') for args, _ in self.fixture.calls))
        self.service.off()

    def test_changed_dhcp_configuration_is_not_executed(self):
        self.start()
        state = self.service.load()
        self.fixture.service['state'] = 'inactive'
        path = self.service.path(ap.RUNTIME + '/dnsmasq.conf')
        path.write_text(path.read_text() + 'dhcp-script=/foreign/script\n')
        before = len(self.fixture.calls)
        with self.assertRaisesRegex(ap.Error, 'configuration changed'):
            self.service.start_dhcp(state)
        self.assertFalse(any(args[:2] == [ap.SYSTEMCTL, 'start'] for args, _ in self.fixture.calls[before:]))

    def test_visibility_idempotent_does_not_restart(self):
        self.start()
        before = len(self.fixture.calls)
        self.assertFalse(self.service.visibility(False)['hidden'])
        self.assertFalse(any(args[:3] == [ap.NMCLI, '--wait', '150'] for args, _ in self.fixture.calls[before:]))

    def test_existing_connection_is_not_disconnected(self):
        self.fixture.active = 'foreign'
        with self.assertRaisesRegex(ap.Error, 'idle managed'):
            self.start()
        self.assertEqual(self.fixture.active, 'foreign')
        self.assertFalse(any(args[1:3] == ['connection', 'delete'] for args, _ in self.fixture.calls))

    def test_explicit_interface_required(self):
        with self.assertRaisesRegex(ap.Error, 'explicitly'):
            self.service.on(None, 'Test', 'private-passphrase')

    def test_route_overlap_refuses_before_profile_creation(self):
        self.fixture.routes = [dict(dst='10.79.0.0/24', dev='other0')]
        with self.assertRaisesRegex(ap.Error, 'conflicts'):
            self.start()
        self.assertFalse(self.fixture.profiles)

    def test_existing_forwarding_refuses_without_change(self):
        path = self.fixture.file('/proc/sys/net/ipv4/conf/wlan0/forwarding', '1\n')
        with self.assertRaisesRegex(ap.Error, 'already forwards'):
            self.start()
        self.assertEqual(path.read_text(), '1\n')
        self.assertFalse(self.fixture.profiles)

    def test_changed_radio_not_disconnected_on_cleanup(self):
        self.start()
        adapter = self.fixture.radio.adapters['wlan0']
        self.fixture.radio.adapters['wlan0'] = adapter._replace(index=99)
        before = len(self.fixture.calls)
        with self.assertRaisesRegex(ap.Error, 'disappeared or changed'):
            self.service.off()
        self.assertFalse(any(args[1] in ('stop', 'connection') for args, _ in self.fixture.calls[before:]))

    def test_changed_profile_not_deleted(self):
        self.start()
        state = self.service.load()
        path = self.service.path(self.service.key_path(state))
        path.write_text(path.read_text() + '# outside edit\n')
        with self.assertRaisesRegex(ap.Error, 'profile changed'):
            self.service.off()
        self.assertTrue(path.exists())
        self.assertEqual(self.fixture.service['state'], 'active')

    def test_foreign_connection_not_disconnected(self):
        self.start()
        self.fixture.active = 'foreign'
        with self.assertRaisesRegex(ap.Error, 'Another connection'):
            self.service.off()
        self.assertEqual(self.fixture.active, 'foreign')
        self.assertEqual(self.fixture.service['state'], 'active')

    def test_foreign_service_not_stopped(self):
        self.start()
        self.fixture.service['description'] = 'foreign service'
        before = len(self.fixture.calls)
        with self.assertRaisesRegex(ap.Error, 'service identity'):
            self.service.off()
        self.assertFalse(any(args[0] == ap.SYSTEMCTL and args[1] == 'stop' for args, _ in self.fixture.calls[before:]))

    def test_foreign_process_not_stopped(self):
        self.start()
        self.fixture.file('/proc/4321/cmdline', '/bin/sleep\0infinity\0')
        before = len(self.fixture.calls)
        with self.assertRaisesRegex(ap.Error, 'process command'):
            self.service.off()
        self.assertFalse(any(args[0] == ap.SYSTEMCTL and args[1] == 'stop' for args, _ in self.fixture.calls[before:]))

    def test_signal_interrupt_rolls_back_owned_objects(self):
        self.fixture.fail_up = KeyboardInterrupt()
        with self.assertRaises(KeyboardInterrupt):
            self.start()
        self.assertFalse(self.fixture.profiles)
        self.assertTrue(self.fixture.autoconnect)
        self.assertIsNone(self.service.load())

    def test_activation_error_rolls_back_owned_objects(self):
        self.fixture.fail_up = ap.Error('injected activation failure')
        with self.assertRaisesRegex(ap.Error, 'owned runtime changes were removed'):
            self.start()
        self.assertFalse(self.fixture.profiles)
        self.assertTrue(self.fixture.autoconnect)
        self.assertIsNone(self.service.load())

    def test_share_and_tor_receipts_block_mutation(self):
        for filename in ('/run/automations-host-share/state.json', '/run/automations-host-tor/state.json',
                         '/run/automations-anonymity/state.json'):
            with self.subTest(filename=filename):
                path = self.fixture.file(filename, '{"phase":"active"}', 0o600)
                with self.assertRaisesRegex(ap.Error, 'Stop host sharing and Tor'):
                    self.start()
                path.unlink()

    def test_active_tor_blocks_off_and_visibility_but_status_works(self):
        self.start()
        self.fixture.file('/run/automations-host-tor/state.json', '{"phase":"active"}', 0o600)
        self.assertTrue(self.service.status()['active'])
        for action in (self.service.off, lambda: self.service.visibility(True)):
            with self.assertRaisesRegex(ap.Error, 'Stop host sharing and Tor'):
                action()

    def test_unsafe_guard_receipt_fails_closed(self):
        path = self.fixture.file('/run/automations-host-tor/state.json', '{"phase":"active"}', 0o644)
        with self.assertRaisesRegex(ap.Error, 'private file permissions'):
            self.start()
        self.assertTrue(path.exists())

    def test_private_password_file_and_no_symlink(self):
        self.fixture.file('/run/ap-secret', 'private-passphrase\n', 0o600)
        self.assertEqual(ap.read_password_file(self.service, '/run/ap-secret'), 'private-passphrase')
        (self.root / 'run/ap-secret-link').symlink_to(self.root / 'run/ap-secret')
        with self.assertRaises(ap.Error):
            ap.read_password_file(self.service, '/run/ap-secret-link')

    def test_password_file_must_not_be_world_readable(self):
        self.fixture.file('/run/ap-secret', 'private-passphrase', 0o644)
        with self.assertRaisesRegex(ap.Error, 'private file permissions'):
            ap.read_password_file(self.service, '/run/ap-secret')

    def test_no_shell_psk_or_open_network_in_cli(self):
        for psk in ('', 'short', 'a' * 64, 'pässword123', 'foo\nbar123'):
            with self.subTest(value=repr(psk)), self.assertRaises(ap.Error):
                ap.validate_psk(psk)
        with contextlib.redirect_stderr(io.StringIO()) as out, self.assertRaises(SystemExit):
            ap.share_main(['SSID', '--interface', 'wlan0', '--password', 'private-passphrase'], backend=self.service)
        self.assertNotIn('private-passphrase', out.getvalue())

    def test_wifi_mutation_hook_allows_independent_physical_radio_only(self):
        self.start()
        with self.assertRaisesRegex(ap.Error, 'belongs to the owned host AP'):
            ap.require_wifi_change_allowed(self.fixture.radio, self.fixture.radio.adapters['wlan0'])
        ap.require_wifi_change_allowed(self.fixture.radio, self.fixture.radio.adapters['wlan1'])

    def test_unconfigured_profile_cannot_mutate(self):
        service = ap.HostAP(Profile(configured=False), root=self.root, runner=self.fixture, owner_uid=os.getuid(), radio=self.fixture.radio)
        with self.assertRaisesRegex(ap.Error, 'explicit Kali-host'):
            service.on('wlan0', 'Test', 'private-passphrase')

    def test_receipt_rejects_duplicate_and_changed_profile_identity(self):
        self.start()
        state = self.service.load()
        path = self.service.path(ap.RUNTIME + '/state.json')
        state['profile_identity'] = 'b' * 64
        path.write_text(json.dumps(state))
        with self.assertRaisesRegex(ap.Error, 'receipt identity'):
            self.service.load()
        path.write_text('{"format":"first","format":"second"}')
        with self.assertRaisesRegex(ap.Error, 'Duplicate AP state field'):
            self.service.load()

    def test_broken_runtime_symlink_is_not_reported_as_clean_off(self):
        target = self.root / ap.RUNTIME.lstrip('/')
        target.symlink_to(self.root / 'missing-directory')
        with self.assertRaises((ap.Error, OSError)):
            self.service.status()

    def test_lock_serializes_with_share_and_wifi(self):
        self.start()
        import fcntl
        descriptor = os.open(self.service.path('/run/automations-wifi.lock'), os.O_RDWR)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(ap.Error, 'Another host AP, Share or Wi-Fi'):
                self.service.off()
        finally:
            os.close(descriptor)


if __name__ == '__main__':
    unittest.main()
