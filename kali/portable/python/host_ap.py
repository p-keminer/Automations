#!/usr/bin/python3
"""Temporary Kali-host access point with optional password and SSID visibility."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import getpass
import hashlib
from importlib.machinery import SourceFileLoader
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import time
import uuid

NMCLI = '/usr/bin/nmcli'
IP = '/usr/sbin/ip'
IW = '/usr/sbin/iw'
SYSTEMCTL = '/usr/bin/systemctl'
SYSTEMD_RUN = '/usr/bin/systemd-run'
DNSMASQ = '/usr/sbin/dnsmasq'
PYTHON = '/usr/bin/python3'
PORTAL = '/usr/local/libexec/automations-support/portal_templates.py'
TEMPLATES = '/usr/local/share/automations/hotspot/templates'
WEB = '/run/automations-host-ap-www'
RUNTIME = '/run/automations-host-ap'
LOCK = '/run/automations-host-ap.lock'
COORDINATION_LOCKS = ('/run/automations-host-share.lock', LOCK, '/run/automations-wifi.lock')
NM_DIR = '/run/NetworkManager/system-connections'
ADDRESS, NETWORK = '10.79.0.1/24', '10.79.0.0/24'
ACTIVATION_SECONDS = 150
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,14}')
DIGEST = re.compile(r'[0-9a-f]{64}')
ENV = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}


class Error(RuntimeError):
    pass


class Parser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        kwargs['allow_abbrev'] = False
        super().__init__(*args, **kwargs)

    def error(self, message):
        # Do not echo unknown tokens: somebody may have mistakenly put a PSK in argv.
        self.print_usage(sys.stderr)
        self.exit(64, self.prog + ': invalid arguments; use --help.\n')


def require(value, message):
    if not value:
        raise Error(message)


def peer(filename, installed, name):
    path = Path(__file__).with_name(filename)
    if Path(__file__).parent.name == 'python' and not path.is_file():
        path = Path(__file__).resolve().parents[2] / 'common/python' / filename
    if Path(__file__).parent.name != 'python':
        path = Path(installed)
        for entry in (path, *path.parents):
            info = entry.lstat()
            require(not stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                    'Installed AP support is not root-protected.')
    spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, str(path)))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def wifi_module():
    return peer('host_wifi.py', '/usr/local/libexec/automations-host/wifi', '_host_ap_wifi')


def load_profile():
    return peer('platform_support.py', '/usr/local/libexec/automations-support/platform_support.py',
                '_host_ap_profile').load_profile()


def portal_module():
    return peer('portal_templates.py', PORTAL, '_host_ap_portal')


def run(args, *, timeout=15):
    try:
        result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                timeout=timeout, check=False, env=ENV)
    except (OSError, subprocess.TimeoutExpired):
        raise Error('A required AP system command is unavailable or timed out.') from None
    # Never disclose daemon output, private keyfiles or credentials.
    require(result.returncode == 0, Path(args[0]).name + ' failed (exit ' + str(result.returncode) + ').')
    require(len(result.stdout) <= 1024 * 1024, 'AP command output exceeds its size limit.')
    return result.stdout


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate AP state field.')
        result[key] = value
    return result


def validate_ssid(ssid):
    require(isinstance(ssid, str) and 1 <= len(ssid.encode('utf-8')) <= 32
            and all(ord(char) >= 32 and ord(char) != 127 for char in ssid),
            'SSID must contain 1 to 32 UTF-8 bytes without control characters.')
    return ssid


def validate_psk(psk):
    require(isinstance(psk, str) and (psk == '' or (8 <= len(psk) <= 63
            and all(32 <= ord(char) <= 126 for char in psk))),
            'Use a WPA2 passphrase of 8 to 63 printable ASCII characters, or leave it empty for an open AP.')
    return psk


def key_escape(value):
    # NM keyfile strings follow GKeyFile escaping, including leading spaces.
    return value.replace('\\', '\\\\').replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t').replace(' ', '\\s')


def keyfile(state, psk):
    adapter, identifier = state['adapter'], state['connection']
    security = ('[wifi-security]\nkey-mgmt=wpa-psk\nproto=rsn;\npairwise=ccmp;\ngroup=ccmp;\npsk='
                + key_escape(psk) + '\n') if psk else ''
    # PSK is never part of saved JSON or process arguments.
    return ('[connection]\nid=automations-host-ap-' + identifier + '\nuuid=' + identifier
            + '\ntype=wifi\ninterface-name=' + adapter['name'] + '\nautoconnect=false\nauth-retries=0\n'
            '[wifi]\nmode=ap\nband=bg\nchannel=6\nssid=' + ';'.join(str(byte) for byte in state['ssid'].encode('utf-8')) + ';'
            + '\nhidden=' + ('true' if state['hidden'] else 'false')
            + '\ncloned-mac-address=permanent\nap-isolation=1\n'
            + security + '[ipv4]\nmethod=manual\naddress1=' + ADDRESS
            + '\nnever-default=true\n[ipv6]\nmethod=disabled\n')


def dhcp_config(state):
    text = ('port=53\nlisten-address=10.79.0.1\nno-resolv\nno-poll\nno-hosts\nuser=root\ngroup=root\ninterface=' + state['adapter']['name']
            + '\nbind-interfaces\nexcept-interface=lo\ndhcp-authoritative\n'
            'dhcp-range=10.79.0.20,10.79.0.200,255.255.255.0,1h\n'
            'dhcp-option=option:router,10.79.0.1\ndhcp-option=option:dns-server,10.79.0.1\n'
            'dhcp-leasefile=' + RUNTIME + '/leases\n')
    for host in portal_module().CAPTIVE_HOSTS:
        text += 'address=/' + host + '/10.79.0.1\nlocal=/' + host + '/\n'
    return text


class HostAP:
    """Only owned runtime profiles/services are changed; existing connections are never displaced."""
    def __init__(self, profile, *, root=Path('/'), runner=run, owner_uid=0,
                 radio=None, clock=time.monotonic, sleep=time.sleep):
        require(profile.platform == 'kali-host' and type(profile.configured) is bool
                and isinstance(profile.protected_interfaces, tuple) and DIGEST.fullmatch(profile.identity),
                'An explicit Kali-host profile is required.')
        self.profile, self.root, self.runner, self.uid = profile, Path(root), runner, owner_uid
        self.radio = radio
        self.clock, self.sleep = clock, sleep

    def path(self, absolute):
        require(absolute.startswith('/') and '..' not in Path(absolute).parts, 'Unsafe AP path.')
        return self.root / absolute.lstrip('/')

    def trusted(self, absolute, *, directory=False, private=False):
        path = self.path(absolute)
        resolved = path.resolve(strict=True)
        require(resolved.is_relative_to(self.root.resolve()), 'AP path escapes its system root.')
        for item in {path, *path.parents, resolved, *resolved.parents}:
            if not item.is_relative_to(self.root):
                continue
            info = item.lstat()
            require(info.st_uid == self.uid and (stat.S_ISLNK(info.st_mode) or not info.st_mode & 0o022),
                    'An AP path is writable by another user.')
        info = path.lstat() if private else resolved.stat()
        require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
                and (directory or info.st_nlink == 1), 'Unsafe AP path type.')
        if private:
            require(not stat.S_ISLNK(info.st_mode) and stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600),
                    'Unsafe AP private file permissions.')
        return path

    def command(self, args, *, timeout=15):
        require(args[0] in (NMCLI, IP, IW, SYSTEMCTL, SYSTEMD_RUN, DNSMASQ, PYTHON), 'Unsupported AP executable.')
        target = self.trusted(args[0])
        require(target.stat().st_mode & 0o111, 'AP system tool is not executable.')
        result = self.runner(list(args), timeout=timeout)
        require(isinstance(result, str) and len(result) <= 1024 * 1024, 'Invalid AP system response.')
        return result

    def boot(self):
        return str(uuid.UUID(self.path('/proc/sys/kernel/random/boot_id').read_text().strip()))

    def mutation(self):
        require(os.geteuid() == 0, 'Use sudo to change the host access point.')
        require(self.profile.configured, 'Install an explicit Kali-host profile before changing an AP.')

    @contextmanager
    def lock(self):
        self.trusted('/run', directory=True)
        descriptors = []
        try:
            for filename in COORDINATION_LOCKS:
                descriptor = os.open(self.path(filename), os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
                descriptors.append(descriptor)
                info = os.fstat(descriptor)
                require(stat.S_ISREG(info.st_mode) and info.st_uid == self.uid and info.st_nlink == 1
                        and stat.S_IMODE(info.st_mode) == 0o600, 'Unsafe AP coordination lock.')
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise Error('Another host AP, Share or Wi-Fi operation is running.') from None
            yield
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)

    def private_write(self, absolute, text, *, replace=False):
        path = self.path(absolute)
        self.trusted('/' + str(path.parent.relative_to(self.root)), directory=True)
        if path.exists() or path.is_symlink():
            self.trusted(absolute, private=True)
            require(replace, 'Owned AP file already exists.')
        temporary = path.parent / ('.ap-' + secrets.token_hex(16))
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
                stream.write(text)
                stream.flush()
                os.fsync(stream.fileno())
            if replace:
                os.replace(temporary, path)
            else:
                # link provides no-clobber publication even after the existence check.
                os.link(temporary, path, follow_symlinks=False)
                temporary.unlink()
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)

    def save(self, state):
        self.validate_state(state)
        self.private_write(RUNTIME + '/state.json', json.dumps(state, sort_keys=True) + '\n', replace=True)

    def validate_state(self, state):
        fields = {'format', 'run_id', 'connection', 'profile_identity',
                  'boot_id', 'phase', 'adapter', 'ssid', 'hidden', 'original_autoconnect', 'key_sha256', 'dhcp'}
        portal_fields = {'template', 'template_sha256', 'portal_files'}
        require(type(state) is dict and set(state) in (fields, fields | portal_fields,
                fields | {'security'}, fields | portal_fields | {'security'}),
                'Invalid host AP receipt fields.')
        require(state.get('security', 'WPA2-PSK') in ('open', 'WPA2-PSK'), 'Invalid host AP security mode.')
        if 'template' in state:
            require(isinstance(state['template'], str) and portal_module().NAME.fullmatch(state['template'])
                    and isinstance(state['template_sha256'], str) and DIGEST.fullmatch(state['template_sha256']),
                    'Invalid host AP portal identity.')
            portal_module().validate_manifest(state['portal_files'])
        require(state['format'] == 'AUTOMATIONS_HOST_AP.v1'
                and state['profile_identity'] == self.profile.identity and state['boot_id'] == self.boot()
                and state['phase'] in ('preparing', 'active', 'changing', 'cleanup')
                and all(str(uuid.UUID(state[field])) == state[field] for field in ('run_id', 'connection'))
                and type(state['hidden']) is bool and type(state['original_autoconnect']) is bool
                and type(state['dhcp']) is bool and DIGEST.fullmatch(state['key_sha256']),
                'Invalid host AP receipt identity.')
        validate_ssid(state['ssid'])
        item = state['adapter']
        require(type(item) is dict and set(item) == {'name', 'index', 'phy', 'phy_path', 'device_path', 'usb_id', 'bus', 'hardware_id'}
                and NAME.fullmatch(item['name']) and item['name'] not in self.profile.protected_interfaces
                and type(item['index']) is int and item['index'] > 0 and re.fullmatch(r'phy[0-9]+', item['phy'])
                and item['bus'] in ('usb', 'pci') and re.fullmatch(r'[0-9a-f]{4}:[0-9a-f]{4}', item['hardware_id'])
                and item['usb_id'] == (item['hardware_id'] if item['bus'] == 'usb' else None)
                and all(isinstance(item[key], str) and item[key].startswith(str(self.path('/sys/devices')) + '/')
                        and '..' not in Path(item[key]).parts for key in ('phy_path', 'device_path')),
                'Invalid AP physical hardware receipt.')

    def load(self):
        if not self.path(RUNTIME).exists() and not self.path(RUNTIME).is_symlink():
            return None
        self.trusted(RUNTIME, directory=True, private=True)
        path = self.path(RUNTIME + '/state.json')
        if not path.exists() and not path.is_symlink():
            require(not list(path.parent.iterdir()), 'Unrecognized unfinished AP runtime.')
            return None
        self.trusted(RUNTIME + '/state.json', private=True)
        require(path.stat().st_size <= 65536, 'Host AP receipt is too large.')
        state = json.loads(path.read_text(), object_pairs_hook=unique)
        self.validate_state(state)
        return state

    def platform(self):
        if self.radio is None:
            self.radio = wifi_module().HostPlatform(profile=self.profile)
        return self.radio

    def adapter(self, name=None, state=None):
        platform = self.platform()
        devices = platform.devices()
        if state is not None:
            expected = state['adapter']
            adapter = devices.get(expected['name'])
            require(adapter is not None and adapter._asdict() == expected,
                    'The AP physical radio disappeared or changed; no replacement hardware is modified.')
        else:
            require(name and NAME.fullmatch(name), 'Choose the AP radio explicitly with --interface IFACE.')
            adapter = devices.get(name)
            require(adapter is not None, 'The selected AP interface is unavailable.')
        platform.guard(adapter, exclusive=True)
        return adapter

    def nm_value(self, field, *args):
        return self.command([NMCLI, '--escape', 'no', '-g', field, *args]).rstrip('\n')

    def key_path(self, state):
        return NM_DIR + '/automations-host-ap-' + state['connection'] + '.nmconnection'

    def unit(self, state):
        return 'automations-host-ap-' + state['run_id'] + '.service'

    def dns_args(self):
        return [DNSMASQ, '--keep-in-foreground', '--conf-file=' + RUNTIME + '/dnsmasq.conf']

    def verify_key(self, state):
        path = self.trusted(self.key_path(state), private=True)
        require(path.stat().st_size <= 8192 and hashlib.sha256(path.read_bytes()).hexdigest() == state['key_sha256'],
                'Owned AP profile changed; refusing to overwrite or delete it.')

    def runtime_member(self, name):
        require(name in ('state.json', 'dnsmasq.conf', 'leases'), 'Unknown AP runtime member.')
        if name != 'leases':
            return self.trusted(RUNTIME + '/' + name, private=True)
        # dnsmasq explicitly publishes its lease database as 0644 even with a
        # 0077 service umask. It contains no PSK and remains inside our private
        # root-owned 0700 directory. No other runtime or keyfile gets this exception.
        self.trusted(RUNTIME, directory=True, private=True)
        path = self.trusted(RUNTIME + '/leases')
        info = path.lstat()
        require(not stat.S_ISLNK(info.st_mode) and stat.S_ISREG(info.st_mode)
                and info.st_uid == self.uid and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) in (0o600, 0o644) and info.st_size <= 65536,
                'Unsafe AP DHCP lease database.')
        return path

    def verify_profile(self, state, *, active=False):
        self.verify_key(state)
        identifier = state['connection']
        expected = {'connection.id': 'automations-host-ap-' + identifier,
                    'connection.uuid': identifier, 'connection.interface-name': state['adapter']['name'],
                    'connection.autoconnect': 'no', '802-11-wireless.mode': 'ap',
                    '802-11-wireless.ssid': state['ssid'], '802-11-wireless.hidden': 'yes' if state['hidden'] else 'no',
                    '802-11-wireless.band': 'bg', '802-11-wireless.channel': '6',
                    '802-11-wireless-security.key-mgmt': '' if state.get('security') == 'open' else 'wpa-psk', 'ipv4.method': 'manual',
                    'ipv4.addresses': ADDRESS, 'ipv4.never-default': 'yes', 'ipv6.method': 'disabled'}
        for field, value in expected.items():
            require(self.nm_value(field, 'connection', 'show', 'uuid', identifier) == value,
                    'Owned AP connection settings changed.')
        if active:
            name = state['adapter']['name']
            require(self.nm_value('GENERAL.CON-UUID', 'device', 'show', name) == identifier
                    and self.nm_value('GENERAL.STATE', 'device', 'show', name).split(' ', 1)[0] == '100',
                    'The owned AP connection is not active.')
            rows = json.loads(self.command([IP, '-j', '-4', 'address', 'show', 'dev', name]))
            require(len(rows) == 1 and rows[0].get('ifindex') == state['adapter']['index']
                    and [item.get('local', '') + '/' + str(item.get('prefixlen')) for item in rows[0].get('addr_info', [])
                         if item.get('scope') == 'global'] == [ADDRESS], 'Owned AP address verification failed.')
            details = self.command([IW, 'dev', name, 'info'])
            require(re.search(r'^\s*type AP\s*$', details, re.M)
                    and re.search(r'^\s*wiphy ' + state['adapter']['phy'][3:] + r'\s*$', details, re.M),
                    'The selected radio is not operating as the expected AP.')

    def service_info(self, state):
        text = self.command([SYSTEMCTL, 'show', self.unit(state),
                            '--property=ActiveState,MainPID,Transient,Description,LoadState,FragmentPath,DropInPaths,Type,User,Group,KillMode,ExecStart'])
        return dict(line.split('=', 1) for line in text.splitlines() if '=' in line)

    def verify_service(self, state, *, required=True):
        values = self.service_info(state)
        if values.get('LoadState') == 'not-found':
            require(not required, 'Owned AP DHCP service is not running.')
            return False
        expected_start = (r'\{ path=' + re.escape(DNSMASQ) + r' ; argv\[\]=' + re.escape(' '.join(self.dns_args()))
                          + r' ; ignore_errors=no ; start_time=[^;{}\r\n]+ ; stop_time=[^;{}\r\n]+'
                          + r' ; pid=[0-9]+ ; code=[^;{}\r\n]+ ; status=[^;{}\r\n]+ \}')
        require(values.get('Transient') == 'yes' and values.get('Type') == 'exec'
                and values.get('Description') == 'Automations host AP DHCP ' + state['run_id']
                and values.get('FragmentPath') == '/run/systemd/transient/' + self.unit(state)
                and values.get('DropInPaths') == '' and values.get('User') in ('', 'root')
                and values.get('Group') in ('', 'root') and values.get('KillMode') == 'control-group'
                and re.fullmatch(expected_start, values.get('ExecStart', '')),
                'AP DHCP service identity changed.')
        if values.get('ActiveState') in ('inactive', 'failed'):
            require(not required, 'Owned AP DHCP service is not running.')
            return False
        require(values.get('ActiveState') == 'active' and re.fullmatch(r'[1-9][0-9]*', values.get('MainPID', '')),
                'AP DHCP service identity changed.')
        pid = values['MainPID']
        process = self.path('/proc/' + pid)
        require(process.stat().st_uid == self.uid, 'AP DHCP process owner changed.')
        require((process / 'cmdline').read_bytes().rstrip(b'\0').split(b'\0') == [word.encode() for word in self.dns_args()],
                'AP DHCP process command changed.')
        return True

    def start_dhcp(self, state):
        self.runtime_member('dnsmasq.conf')
        require(self.path(RUNTIME + '/dnsmasq.conf').read_text() == dhcp_config(state),
                'Owned AP DHCP configuration changed; refusing to start it.')
        self.command([DNSMASQ, '--test', '--conf-file=' + RUNTIME + '/dnsmasq.conf'])
        values = self.service_info(state)
        if values.get('LoadState') == 'not-found':
            self.command([SYSTEMD_RUN, '--quiet', '--collect', '--unit=' + self.unit(state),
                          '--description=Automations host AP DHCP ' + state['run_id'],
                          '--property=Type=exec', '--property=Restart=no', '--property=KillMode=control-group',
                          '--property=UMask=0077', '--property=NoNewPrivileges=yes',
                          '--property=CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_RAW CAP_NET_ADMIN CAP_SETUID CAP_SETGID',
                          '--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_NETLINK AF_PACKET',
                          '--', *self.dns_args()])
        else:
            # --collect may already have unloaded the stopped transient unit. If
            # it is still present, only restart its fully verified fixed command.
            require(not self.verify_service(state, required=False), 'Owned AP DHCP service is already running.')
            self.command([SYSTEMCTL, 'start', self.unit(state)], timeout=30)
        self.verify_service(state)

    def stop_dhcp(self, state):
        if self.verify_service(state, required=False):
            self.command([SYSTEMCTL, 'stop', self.unit(state)], timeout=30)
            require(not self.verify_service(state, required=False), 'Owned AP DHCP service did not stop.')

    def select_template(self, name=None):
        try:
            return portal_module().select(name, self.path(TEMPLATES), owner_uid=self.uid, anchor=self.root)
        except ValueError as exc:
            raise Error(str(exc)) from None

    def portal_unit(self, state):
        return 'automations-host-ap-web-' + state['run_id'] + '.service'

    def portal_args(self):
        return [PYTHON, PORTAL, '--serve', '--directory', WEB, '--bind', ADDRESS.split('/')[0]]

    def portal_info(self, state):
        text = self.command([SYSTEMCTL, 'show', self.portal_unit(state),
            '--property=ActiveState,MainPID,Transient,Description,LoadState,FragmentPath,DropInPaths,Type,User,Group,KillMode,ExecStart'])
        return dict(line.split('=', 1) for line in text.splitlines() if '=' in line)

    def verify_portal(self, state, *, required=True):
        values = self.portal_info(state)
        if values.get('LoadState') == 'not-found':
            require(not required, 'Owned AP portal service is not running.')
            return False
        expected = (r'\{ path=' + re.escape(PYTHON) + r' ; argv\[\]=' + re.escape(' '.join(self.portal_args()))
            + r' ; ignore_errors=no ; start_time=[^;{}\r\n]+ ; stop_time=[^;{}\r\n]+'
            + r' ; pid=[0-9]+ ; code=[^;{}\r\n]+ ; status=[^;{}\r\n]+ \}')
        user = 'nobody' if self.uid == 0 else str(self.uid)
        require(values.get('Transient') == 'yes' and values.get('Type') == 'exec'
            and values.get('Description') == 'Automations host AP portal ' + state['run_id']
            and values.get('FragmentPath') == '/run/systemd/transient/' + self.portal_unit(state)
            and values.get('DropInPaths') == '' and values.get('User') == user
            and values.get('KillMode') == 'control-group' and re.fullmatch(expected, values.get('ExecStart', '')),
            'AP portal service identity changed.')
        if values.get('ActiveState') in ('inactive', 'failed'):
            require(not required, 'Owned AP portal service is not running.')
            return False
        require(values.get('ActiveState') == 'active' and re.fullmatch(r'[1-9][0-9]*', values.get('MainPID', '')),
                'AP portal service identity changed.')
        process = self.path('/proc/' + values['MainPID'])
        import pwd
        uid = pwd.getpwnam('nobody').pw_uid if self.uid == 0 else self.uid
        require(process.stat().st_uid == uid and (process/'cmdline').read_bytes().rstrip(b'\0').split(b'\0')
                == [word.encode() for word in self.portal_args()], 'AP portal process identity changed.')
        return True

    def start_portal(self, state):
        pages = portal_module()
        pages.verify_runtime(self.path(WEB), state['portal_files'], owner_uid=self.uid, anchor=self.root)
        self.trusted(PORTAL)
        values = self.portal_info(state)
        if values.get('LoadState') == 'not-found':
            self.command([SYSTEMD_RUN, '--quiet', '--collect', '--unit=' + self.portal_unit(state),
                '--description=Automations host AP portal ' + state['run_id'],
                '--property=Type=exec', '--property=Restart=no', '--property=KillMode=control-group',
                '--property=User=' + ('nobody' if self.uid == 0 else str(self.uid)),
                '--property=UMask=0077', '--property=NoNewPrivileges=yes',
                '--property=ProtectSystem=strict', '--property=ProtectHome=yes', '--property=PrivateTmp=yes',
                '--property=CapabilityBoundingSet=CAP_NET_BIND_SERVICE',
                '--property=AmbientCapabilities=CAP_NET_BIND_SERVICE', '--property=RestrictAddressFamilies=AF_INET AF_UNIX',
                '--', *self.portal_args()])
        else:
            require(not self.verify_portal(state, required=False), 'Owned AP portal service is already running.')
            self.command([SYSTEMCTL, 'start', self.portal_unit(state)], timeout=30)
        self.verify_portal(state)
        probe = ('import hashlib,time,urllib.request; expected=' + repr(state['portal_files']['index.html']) + '\n'
            'for attempt in range(20):\n'
            ' try:\n'
            '  response=urllib.request.urlopen("http://10.79.0.1/",timeout=1)\n'
            '  assert response.status==200 and hashlib.sha256(response.read()).hexdigest()==expected\n'
            '  break\n'
            ' except OSError:\n'
            '  if attempt==19: raise\n'
            '  time.sleep(.1)\n')
        self.command([PYTHON, '-c', probe], timeout=25)

    def stop_portal(self, state):
        if self.verify_portal(state, required=False):
            self.command([SYSTEMCTL, 'stop', self.portal_unit(state)], timeout=30)
            require(not self.verify_portal(state, required=False), 'Owned AP portal service did not stop.')

    def quiescent(self, state):
        adapter = self.adapter(state=state)
        current = self.platform().read_state(adapter)
        require(current.connection is None and current.mode == 'managed' and current.managed
                and current.nm_state in (30, 120) and not current.addresses and not current.autoconnect,
                'The owned AP radio did not reach an idle managed state after deactivation; no reactivation attempted.')
        self.verify_forwarding_off(adapter.name)
        return adapter

    def verify_share_off(self, state=None):
        # Share/Tor own routing state. They must be explicitly stopped before AP changes.
        for filename in ('/run/automations-host-share/state.json', '/run/automations-anonymity/state.json',
                         '/run/automations-host-tor/state.json'):
            path = self.path(filename)
            if path.exists() or path.is_symlink():
                self.trusted(filename, private=True)
                require(path.stat().st_size <= 65536, 'Cannot verify a host routing guard receipt.')
                receipt = json.loads(path.read_text(), object_pairs_hook=unique)
                require(type(receipt) is dict and bool(receipt), 'Cannot verify a host routing guard receipt.')
                raise Error('Stop host sharing and Tor before changing the AP; their selected interface must remain stable.')

    def preflight(self, adapter):
        current = self.platform().read_state(adapter)
        require(current.mode == 'managed' and current.managed and current.connection is None
                and current.nm_state in (30, 120) and not current.addresses,
                'Use an idle managed AP radio with no active connection or addresses; existing connections are preserved.')
        self.verify_forwarding_off(adapter.name)
        capabilities = self.command([IW, 'phy', adapter.phy, 'info'])
        require(re.search(r'^\s*\* AP\s*$', capabilities, re.M), 'The selected radio does not report AP capability.')
        rows = json.loads(self.command([IP, '-j', '-4', 'route', 'show', 'table', 'all']))
        for row in rows:
            destination = row.get('dst', 'default')
            if destination != 'default':
                require(not ipaddress.ip_network(destination, strict=False).overlaps(ipaddress.ip_network(NETWORK)),
                        'The AP subnet conflicts with an existing IPv4 route.')
        return current

    def select_interface(self, name=None, *, stdin=None, stdout=None):
        if name is not None:
            return name
        candidates = {}
        for name, adapter in sorted(self.platform().devices().items()):
            try:
                self.platform().guard(adapter, exclusive=True)
                self.preflight(adapter)
                candidates[name] = adapter
            except (RuntimeError, OSError, ValueError):
                continue
        choices = peer('adapter_selection.py', '/usr/local/libexec/automations-support/adapter_selection.py', '_host_ap_choices')
        try:
            name = choices.choose([(name, adapter.bus.upper() + ' ' + adapter.hardware_id)
                                   for name,adapter in candidates.items()],
                                  'Several AP adapters exist; use --interface IFACE in non-interactive commands.',
                                  stdin=stdin, stdout=stdout)
        except ValueError as exc:
            raise Error(str(exc)) from None
        require(self.adapter(name) == candidates[name], 'The selected AP hardware changed during selection.')
        return name

    def verify_forwarding_off(self, name):
        require(NAME.fullmatch(name), 'Invalid AP forwarding interface.')
        value = self.path('/proc/sys/net/ipv4/conf/' + name + '/forwarding').read_text().strip()
        require(value == '0', 'The AP radio already forwards packets; disable that external forwarding policy first.')

    def on(self, name, ssid, psk, *, hidden=False, dhcp=True, template='welcome'):
        self.mutation()
        validate_ssid(ssid)
        validate_psk(psk)
        require(type(hidden) is bool and type(dhcp) is bool, 'Invalid AP options.')
        pages = portal_module()
        template = self.select_template(template)
        source = pages.snapshot(template, self.path(TEMPLATES), owner_uid=self.uid, anchor=self.root)
        files = pages.render(source, ssid)
        with self.lock():
            require(self.load() is None, 'An owned AP already exists; stop it before changing its SSID or radio.')
            self.verify_share_off()
            adapter = self.adapter(name)
            original = self.preflight(adapter)
            require(not self.path(WEB).exists() and not self.path(WEB).is_symlink(), 'The reserved portal runtime directory already exists.')
            self.path(RUNTIME).mkdir(mode=0o700, exist_ok=True)
            self.trusted(RUNTIME, directory=True, private=True)
            self.trusted(NM_DIR, directory=True)
            state = dict(format='AUTOMATIONS_HOST_AP.v1', run_id=str(uuid.uuid4()), connection=str(uuid.uuid4()),
                         profile_identity=self.profile.identity, boot_id=self.boot(), phase='preparing',
                         adapter=dict(adapter._asdict()), ssid=ssid, hidden=hidden,
                         original_autoconnect=original.autoconnect, key_sha256='0' * 64, dhcp=dhcp,
                         security='WPA2-PSK' if psk else 'open',
                         template=template, template_sha256=pages.digest(source), portal_files=pages.manifest(files))
            contents = keyfile(state, psk)
            state['key_sha256'] = hashlib.sha256(contents.encode()).hexdigest()
            psk = None
            # Receipt precedes mutation, so interrupted activation remains recoverable.
            self.save(state)
            try:
                self.private_write(self.key_path(state), contents)
                contents = None
                self.private_write(RUNTIME + '/dnsmasq.conf', dhcp_config(state))
                pages.write_runtime(self.path(WEB), files, owner_uid=self.uid, anchor=self.root)
                self.adapter(state=state)
                self.command([NMCLI, 'device', 'set', name, 'autoconnect', 'no'])
                self.command([NMCLI, 'connection', 'load', self.key_path(state)])
                self.verify_profile(state)
                self.command([NMCLI, '--wait', str(ACTIVATION_SECONDS), 'connection', 'up', 'uuid',
                              state['connection'], 'ifname', name], timeout=ACTIVATION_SECONDS + 15)
                self.adapter(state=state)
                self.verify_profile(state, active=True)
                self.verify_forwarding_off(name)
                if dhcp:
                    self.start_dhcp(state)
                self.start_portal(state)
                state['phase'] = 'active'
                self.save(state)
                return self.status()
            except (Exception, KeyboardInterrupt) as error:
                try:
                    self.cleanup(state)
                except (Exception, KeyboardInterrupt):
                    raise Error('AP activation failed; owned state was retained because cleanup could not be verified. Use --off after inspection.') from None
                if isinstance(error, KeyboardInterrupt):
                    raise
                raise Error('AP activation failed; owned runtime changes were removed.') from error

    def status(self):
        state = self.load()
        if state is None:
            return dict(active=False, phase='off', interface=None, ssid=None, hidden=None, dhcp=False)
        self.adapter(state=state)
        require(state['phase'] == 'active', 'AP operation is unfinished; use --off for owned cleanup.')
        self.verify_profile(state, active=True)
        if state['dhcp']:
            self.verify_service(state)
        if 'template' in state:
            self.verify_portal(state)
        return dict(active=True, phase='active', interface=state['adapter']['name'], ssid=state['ssid'],
                    hidden=state['hidden'], dhcp=state['dhcp'], template=state.get('template'),
                    security=state.get('security', 'WPA2-PSK'))

    def cleanup(self, state):
        self.verify_share_off(state)
        adapter = self.adapter(state=state)
        # Validate all deletions before the first destructive operation.
        key = self.path(self.key_path(state))
        if key.exists() or key.is_symlink():
            self.verify_key(state)
        runtime = self.path(RUNTIME)
        require({item.name for item in runtime.iterdir()} <= {'state.json', 'dnsmasq.conf', 'leases'},
                'Unrecognized AP runtime files; nothing will be removed.')
        for item in runtime.iterdir():
            self.runtime_member(item.name)
        if 'template' in state:
            if self.path(WEB).exists() or self.path(WEB).is_symlink():
                portal_module().verify_runtime(self.path(WEB), state['portal_files'], owner_uid=self.uid, anchor=self.root, partial=True)
            self.verify_portal(state, required=False)
        active = self.nm_value('GENERAL.CON-UUID', 'device', 'show', adapter.name)
        require(active in ('', '--', state['connection']), 'Another connection replaced the AP; refusing to disconnect it.')
        known = self.nm_value('UUID', 'connection', 'show').splitlines()
        if state['connection'] in known:
            self.verify_profile(state)
        self.verify_forwarding_off(adapter.name)
        service_present = self.verify_service(state, required=False) if state['dhcp'] else False
        state['phase'] = 'cleanup'
        self.save(state)
        if 'template' in state:
            self.stop_portal(state)
        if service_present:
            self.stop_dhcp(state)
        if active == state['connection']:
            self.command([NMCLI, '--wait', '30', 'connection', 'down', 'uuid', state['connection']], timeout=40)
        self.adapter(state=state)
        require(self.nm_value('GENERAL.CON-UUID', 'device', 'show', adapter.name) in ('', '--'),
                'The AP radio acquired another connection; owned state retained.')
        if state['connection'] in known:
            self.command([NMCLI, 'connection', 'delete', 'uuid', state['connection']])
        if key.exists():
            self.verify_key(state)
            key.unlink()
        require(state['connection'] not in self.nm_value('UUID', 'connection', 'show').splitlines(),
                'The owned AP profile is still registered.')
        self.command([NMCLI, 'device', 'set', adapter.name, 'autoconnect',
                      'yes' if state['original_autoconnect'] else 'no'])
        # nmcli delete removes the owned runtime keyfile; no other profile is touched.
        if 'template' in state and self.path(WEB).exists():
            portal_module().remove_runtime(self.path(WEB), state['portal_files'], owner_uid=self.uid, anchor=self.root)
        for item in tuple(runtime.iterdir()):
            if item.name != 'state.json':
                self.runtime_member(item.name).unlink()
        require(self.load() == state, 'AP ownership receipt changed during cleanup.')
        self.trusted(RUNTIME + '/state.json', private=True).unlink()
        runtime.rmdir()

    def off(self):
        self.mutation()
        with self.lock():
            state = self.load()
            if state is not None:
                self.cleanup(state)
            return self.status()

    def visibility(self, hidden):
        self.mutation()
        require(type(hidden) is bool, 'Invalid SSID visibility.')
        with self.lock():
            state = self.load()
            require(state is not None and state['phase'] == 'active', 'Start an owned host AP before changing visibility.')
            self.verify_share_off(state)
            self.adapter(state=state)
            self.verify_profile(state, active=True)
            if state['hidden'] == hidden:
                return self.status()
            text = self.trusted(self.key_path(state), private=True).read_text()
            before, after = 'hidden=' + ('true' if state['hidden'] else 'false'), 'hidden=' + ('true' if hidden else 'false')
            require(text.count('\n' + before + '\n') == 1, 'Owned AP visibility setting is ambiguous.')
            changed = text.replace('\n' + before + '\n', '\n' + after + '\n')
            if state['dhcp']:
                self.verify_service(state)
            state['phase'] = 'changing'
            self.save(state)
            try:
                if 'template' in state:
                    self.stop_portal(state)
                if state['dhcp']:
                    self.stop_dhcp(state)
                self.command([NMCLI, '--wait', '30', 'connection', 'down', 'uuid', state['connection']], timeout=40)
                self.quiescent(state)
                state.update(hidden=hidden, key_sha256=hashlib.sha256(changed.encode()).hexdigest())
                self.private_write(self.key_path(state), changed, replace=True)
                self.save(state)
                self.command([NMCLI, 'connection', 'load', self.key_path(state)])
                self.verify_profile(state)
                self.quiescent(state)
                self.command([NMCLI, '--wait', str(ACTIVATION_SECONDS), 'connection', 'up', 'uuid',
                              state['connection'], 'ifname', state['adapter']['name']], timeout=ACTIVATION_SECONDS + 15)
                self.adapter(state=state)
                self.verify_profile(state, active=True)
                self.verify_forwarding_off(state['adapter']['name'])
                if state['dhcp']:
                    self.start_dhcp(state)
                if 'template' in state:
                    self.start_portal(state)
                state['phase'] = 'active'
                self.save(state)
                return self.status()
            except (Exception, KeyboardInterrupt):
                # Keep the last receipt consistent with the actual private file. An explicit --off
                # can recover without ever reading or printing a credential through nmcli.
                raise Error('AP visibility activation failed; owned state retained for --off cleanup.') from None


def print_status(value):
    print('Host access point: ' + value['phase'])
    print('Template directory: ' + TEMPLATES)
    if value['active']:
        print('Interface: ' + value['interface'])
        print('SSID: ' + json.dumps(value['ssid'], ensure_ascii=True))
        print('Visibility: ' + ('hidden' if value['hidden'] else 'visible'))
        print('Security: ' + ('open (no password)' if value.get('security') == 'open' else 'WPA2-PSK / CCMP')
              + '; client isolation enabled')
        print('IPv4: ' + ADDRESS + ('; DHCP enabled' if value['dhcp'] else '; DHCP disabled'))
        if value.get('template'):
            print('Portal template: ' + value['template'])
            print('Portal: http://10.79.0.1/')
        print('Internet requires an explicit auto share selection; no automatic forwarding or NAT is created.')


def read_password_file(service, filename):
    require(isinstance(filename, str) and filename.startswith('/'), 'Use an absolute private passphrase file path.')
    path = service.trusted(filename, private=True)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == service.uid and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600, 'The passphrase file must be private to root.')
        data = stream.read(65)
    require(len(data) <= 64, 'The passphrase file is too large.')
    try:
        value = data.decode('ascii').removesuffix('\n')
    except UnicodeError:
        raise Error('The private passphrase must contain printable ASCII.') from None
    return validate_psk(value)


def require_wifi_change_allowed(backend, adapter=None):
    """Host Wi-Fi mutation hook, called after selection, never from its identity guard.

    Independent radios remain usable while an owned AP is active. An unfinished,
    unsafe or changed AP receipt fails closed instead of allowing generic Wi-Fi
    commands to silently dismantle an AP whose lifecycle belongs to this helper.
    """
    profile = backend.host_profile
    # HostPlatform.root points at sysfs; convert only its documented /sys injection
    # to the matching test/production system root, rather than trusting user input.
    sysroot = Path(backend.root)
    require(sysroot.name == 'sys', 'Cannot identify the host Wi-Fi system root.')
    service = HostAP(profile, root=sysroot.parent, owner_uid=getattr(backend, 'owner_uid', 0))
    state = service.load()
    if state is None:
        return
    if adapter is None:
        raise Error('An owned host AP exists; select an independent Wi-Fi radio or stop the AP first.')
    same = (adapter.name == state['adapter']['name'] or adapter.phy_path == state['adapter']['phy_path']
            or adapter.device_path == state['adapter']['device_path'])
    require(not same, 'This radio belongs to the owned host AP; stop it with auto share ap --off first.')


def main(argv=None, *, profile=None, backend=None, command='ap', password_reader=getpass.getpass):
    parser = Parser(prog='auto ap' if command == 'ap' else 'auto share ap', description=__doc__)
    actions = parser.add_mutually_exclusive_group()
    if command == 'ap':
        for name in ('visible', 'invisible', 'status'):
            actions.add_argument('--' + name, dest='action', action='store_const', const=name)
    else:
        parser.add_argument('ssid', nargs='?', help='SSID for the temporary AP; a hidden password prompt follows (empty = open)')
        parser.add_argument('--interface', metavar='IFACE', help='Idle AP radio; otherwise select from eligible adapters')
        parser.add_argument('--password-file', metavar='PATH', help='Root-owned mode-0600 private passphrase file instead of a prompt')
        parser.add_argument('--template', metavar='NAME', help='Portal directory name; otherwise ask and list available templates')
        for name in ('on', 'off', 'status'):
            actions.add_argument('--' + name, dest='action', action='store_const', const=name)
    args = parser.parse_args(argv)
    if command != 'ap' and ((args.ssid is not None or args.interface or args.password_file or args.template is not None) and args.action in ('off', 'status')):
        parser.error('SSID, --interface and --password-file cannot be combined with --off/--status')
    try:
        service = backend or HostAP(profile if profile is not None else load_profile())
        if command == 'ap' and args.action in ('visible', 'invisible'):
            value = service.visibility(args.action == 'invisible')
        elif command != 'ap' and (args.ssid is not None or args.action == 'on'):
            require(args.password_file or sys.stdin.isatty(), 'AP creation needs a hidden passphrase prompt or private --password-file.')
            require(args.ssid is not None or sys.stdin.isatty(), 'Provide an SSID in non-interactive commands.')
            ssid = args.ssid if args.ssid is not None else input('AP SSID: ')
            template = service.select_template(args.template)
            interface = service.select_interface(args.interface)
            password = (read_password_file(service, args.password_file) if args.password_file else
                        password_reader('AP password (empty = open network): '))
            value = service.on(interface, ssid, password, template=template)
            password = None
        elif command != 'ap' and args.action == 'off':
            value = service.off()
        else:
            if command != 'ap' and (args.interface or args.password_file or args.template is not None):
                parser.error('--interface/--password-file require an SSID or --on')
            value = service.status()
        print_status(value)
        return 0
    except (Error, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        message = str(error) if isinstance(error, Error) else 'Cannot manage the owned host AP safely; private configuration was not disclosed.'
        print('ERROR: ' + message, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('AP operation interrupted; inspect --status before continuing.', file=sys.stderr)
        return 130


def share_main(argv=None, **kwargs):
    return main(argv, command='share-ap', **kwargs)


if __name__ == '__main__':
    raise SystemExit(main())
