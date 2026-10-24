#!/usr/bin/python3
"""Explicit, temporary IPv4 host/client egress; never rewrites existing firewall or NM profiles."""
from __future__ import annotations
import argparse
from contextlib import contextmanager
import fcntl
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import struct
import subprocess
import sys
import uuid

IP, NFT, NMCLI, IW = '/usr/sbin/ip', '/usr/sbin/nft', '/usr/bin/nmcli', '/usr/sbin/iw'
TABLE, PRIORITY, MARK, PROTOCOL = 51827, 10427, 0x01000000, 186
NFT_TABLE = 'automations_host_share'
RUNTIME, LOCK = '/run/automations-host-share', '/run/automations-host-share.lock'
SUPPORT = '/usr/local/libexec/automations-support/platform_support.py'
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,14}')
DIGEST = re.compile(r'[0-9a-f]{64}')
MAC = re.compile(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}')

class Error(RuntimeError):
    pass

def require(value, message):
    if not value: raise Error(message)

def run(args, input_text=None):
    try:
        return subprocess.run(args, input=input_text, text=True, capture_output=True,
            stdin=subprocess.DEVNULL if input_text is None else None, timeout=12, check=False,
            env={'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    except subprocess.TimeoutExpired:
        raise Error('Bounded command timed out: ' + Path(args[0]).name) from None

def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate state field.')
        result[key] = value
    return result

def ipv4(value):
    result = ipaddress.IPv4Address(value)
    require(not (result.is_loopback or result.is_link_local or result.is_multicast or result.is_unspecified),
            'A usable non-loopback IPv4 address is required.')
    return str(result)

def match(left, right, op='=='):
    return {'match': {'op': op, 'left': left, 'right': right}}

def meta(key): return {'meta': {'key': key}}
def payload(protocol, field): return {'payload': {'protocol': protocol, 'field': field}}
def network(value):
    net = ipaddress.IPv4Network(value)
    return {'prefix': {'addr': str(net.network_address), 'len': net.prefixlen}}

def nft_objects(state):
    """Deterministic objects; no executable expressions are taken from saved state."""
    selected = state['selection']
    uplink, clients = selected['uplink'], selected['clients']
    token = 'automations-host-share:' + state['run_id']
    result = [{'table': {'family': 'inet', 'name': NFT_TABLE, 'comment': token}}]
    chains = (('dns_out', 'nat', 'output', -100), ('route_out', 'route', 'output', -90),
              ('output_guard', 'filter', 'postrouting', 300), ('client_guard', 'filter', 'prerouting', -300),
              ('dns_in', 'nat', 'prerouting', -100), ('route_in', 'filter', 'prerouting', -90),
              ('forward_guard', 'filter', 'forward', 300), ('source_nat', 'nat', 'postrouting', 100))
    for name, kind, hook, priority in chains:
        result.append({'chain': {'family': 'inet', 'table': NFT_TABLE, 'name': name,
                       'type': kind, 'hook': hook, 'prio': priority, 'policy': 'accept'}})
    def rule(chain, *expressions):
        result.append({'rule': {'family': 'inet', 'table': NFT_TABLE, 'chain': chain,
            'expr': list(expressions), 'comment': token + ':' + str(len(result))}})
    v4, v6 = match(meta('nfproto'), 'ipv4'), match(meta('nfproto'), 'ipv6')
    returned, dropped = {'return': None}, {'drop': None}
    mark = {'mangle': {'key': meta('mark'), 'value': {'|': [meta('mark'), MARK]}}}
    local = match(payload('ip', 'daddr'), network('127.0.0.0/8'))
    dhcp = (v4, match(payload('udp', 'sport'), 67), match(payload('udp', 'dport'), 68),
            match(payload('ip', 'daddr'), '255.255.255.255'))
    # Keep loopback resolvers local. Intercept their nonlocal upstream DNS, not
    # the 127/8 stub destination; no route_localnet or resolver-file exception.
    rule('dns_out', v4, local, returned)
    for transport in ('udp', 'tcp'):
        rule('dns_out', v4, match(payload(transport, 'dport'), 53),
             {'dnat': {'addr': selected['dns'][0], 'family': 'ip'}})
    rule('route_out', v4, local, returned)
    rule('route_out', *dhcp, returned)
    rule('route_out', v4, mark)
    # Postrouting sees the final egress after the output route-chain reroute.
    rule('output_guard', match(meta('iif'), 0, '!='), returned)
    rule('output_guard', match(meta('oifname'), 'lo'), returned)
    rule('output_guard', v6, dropped)
    rule('output_guard', v4, match(meta('oif'), uplink['ifindex']), returned)
    for client in clients:
        out = match(meta('oif'), client['ifindex'])
        rule('output_guard', out, *dhcp, returned)
        rule('output_guard', v4, out, match(payload('ip', 'daddr'), network(client['network'])), returned)
    rule('output_guard', v4, dropped)
    for client in clients:
        incoming, outgoing = match(meta('iif'), client['ifindex']), match(meta('oif'), client['ifindex'])
        rule('client_guard', incoming, v6, dropped)
        for source in ('0.0.0.0', network(client['network'])):
            rule('client_guard', incoming, v4, match(payload('udp', 'sport'), 68),
                 match(payload('udp', 'dport'), 67), match(payload('ip', 'saddr'), source),
                 match(payload('ip', 'daddr'), {'set': ['255.255.255.255', client['address']]}), returned)
        rule('client_guard', incoming, v4, match(payload('ip', 'saddr'), network(client['network']), '!='), dropped)
        for transport in ('udp', 'tcp'):
            rule('dns_in', incoming, v4, match(payload(transport, 'dport'), 53),
                 {'dnat': {'addr': selected['dns'][0], 'family': 'ip'}})
        for source in ('0.0.0.0', network(client['network'])):
            rule('route_in', incoming, v4, match(payload('udp', 'sport'), 68),
                 match(payload('udp', 'dport'), 67), match(payload('ip', 'saddr'), source),
                 match(payload('ip', 'daddr'), {'set': ['255.255.255.255', client['address']]}), returned)
        rule('route_in', incoming, v4, mark)
        rule('forward_guard', incoming, v4, match(meta('oif'), uplink['ifindex']), returned)
        rule('forward_guard', incoming, dropped)
        for connection in ('established', 'related'):
            rule('forward_guard', outgoing, v4, match(meta('iif'), uplink['ifindex']),
                 match({'ct': {'key': 'state'}}, connection), returned)
        rule('forward_guard', outgoing, dropped)
    if clients and state['forwarding'][uplink['name']] == '0':
        rule('forward_guard', match(meta('iif'), uplink['ifindex']), dropped)
    rule('source_nat', v4, match(meta('oif'), uplink['ifindex']),
         match({'&': [meta('mark'), MARK]}, MARK), {'masquerade': None})
    return result

def routes(state):
    selected = state['selection']
    result = [dict(dst=item['network'], dev=item['name'], prefsrc=item['address'],
                   protocol=PROTOCOL, scope='link', table=TABLE)
              for item in [selected['uplink'], *selected['clients']]]
    result.extend((dict(dst='default', gateway=selected['gateway'], dev=selected['uplink']['name'],
                       protocol=PROTOCOL, metric=100, table=TABLE),
                   dict(type='unreachable', dst='default', protocol=PROTOCOL, metric=42760, table=TABLE)))
    return result

def route_args(row):
    args = [row['type']] if row.get('type') else []
    args.append(row['dst'])
    for key, flag in (('gateway', 'via'), ('dev', 'dev'), ('prefsrc', 'src'), ('scope', 'scope'),
                      ('metric', 'metric'), ('protocol', 'proto'), ('table', 'table')):
        if key in row: args.extend((flag, str(row[key])))
    return args

def dns_probe(selection):
    """One bounded UDP DNS exchange explicitly bound to the selected device/IP."""
    query_id = secrets.randbelow(65536)
    packet = struct.pack('!HHHHHH', query_id, 0x0100, 1, 0, 0, 0) + b'\0\0\x02\0\x01'
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as channel:
        channel.settimeout(3)
        channel.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                           selection['uplink']['name'].encode('ascii') + b'\0')
        channel.bind((selection['uplink']['address'], 0))
        channel.connect((selection['dns'][0], 53))
        channel.send(packet)
        response = channel.recv(4096)
    require(len(response) >= 12, 'Selected uplink DNS returned no valid response.')
    observed, flags, questions, answers, authorities, _ = struct.unpack('!HHHHHH', response[:12])
    require(observed == query_id and flags & 0x8000 and not flags & 0x020F
            and questions == 1 and answers + authorities > 0, 'Selected uplink DNS health check failed.')

class HostShare:
    def __init__(self, profile, *, root=Path('/'), runner=None, owner_uid=0, probe=dns_probe):
        require(profile.platform == 'kali-host' and type(profile.configured) is bool
                and isinstance(profile.protected_interfaces, tuple) and DIGEST.fullmatch(profile.identity),
                'A valid Kali host profile is required.')
        self.profile, self.root = profile, Path(root)
        self.run, self.uid, self.probe = runner or run, owner_uid, probe

    def path(self, absolute):
        require(absolute.startswith('/') and '..' not in Path(absolute).parts, 'Unsafe system path.')
        return self.root / absolute.lstrip('/')

    def trusted(self, absolute, directory=False, private=False):
        path = self.path(absolute)
        resolved = path.resolve(strict=True)
        require(resolved.is_relative_to(self.root.resolve()), 'System path escapes its root.')
        for candidate in set((path, *path.parents, resolved, *resolved.parents)):
            if not candidate.is_relative_to(self.root): continue
            info = candidate.lstat()
            require(info.st_uid == self.uid and (stat.S_ISLNK(info.st_mode) or not info.st_mode & 0o022),
                    'System path is not protected by its trusted owner.')
        info = path.lstat() if private else resolved.stat()
        require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
                and (directory or info.st_nlink == 1), 'Unsafe system file type.')
        if private:
            require(stat.S_IMODE(info.st_mode) == (0o700 if directory else 0o600), 'Unsafe runtime permissions.')
        return path

    def command(self, args, input_text=None):
        require(args[0] in (IP, NFT, NMCLI, IW), 'Unsupported executable.')
        executable = self.trusted(args[0])
        require(executable.stat().st_mode & 0o111, 'System tool is not executable.')
        result = self.run(list(args), input_text)
        require(result.returncode == 0, Path(args[0]).name + ' failed (exit ' + str(result.returncode) + ').')
        require(isinstance(result.stdout, str) and len(result.stdout) <= 4 * 1024 * 1024, 'Excessive tool output.')
        return result.stdout

    def ip(self, *args):
        value = json.loads(self.command([IP, '-j', '-N', *args]))
        require(isinstance(value, list), 'Invalid ip JSON response.')
        return value

    def nft(self, commands, check=False):
        self.command([NFT, '-j'] + (['--check'] if check else []) + ['-f', '-'],
                     json.dumps({'nftables': commands}, sort_keys=True))

    def firewall(self):
        value = json.loads(self.command([NFT, '-j', '-n', '-s', 'list', 'ruleset']))
        require(isinstance(value, dict) and isinstance(value.get('nftables'), list), 'Invalid nft JSON response.')
        return value['nftables']

    def extension(self, filename):
        absolute = '/usr/local/libexec/automations-support/' + filename
        path = self.path(absolute)
        if not path.exists() and not path.is_symlink():
            return None
        self.trusted(absolute)
        spec = importlib.util.spec_from_file_location('_host_share_' + filename.removesuffix('.py'), path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        exec(compile(path.read_bytes(), str(path), 'exec'), module.__dict__)
        return module

    def privacy_change_guard(self):
        extension = self.extension('host_egress.py')
        if extension is not None:
            try:
                extension.require_share_change_allowed(self)
            except extension.Error as error:
                raise Error(str(error)) from None
        else:
            path = self.path('/run/automations-host-tor/state.json')
            require(not path.exists() and not path.is_symlink(),
                    'A Tor guard exists but its verified lifecycle helper is unavailable.')

    def boot(self):
        return str(uuid.UUID(self.path('/proc/sys/kernel/random/boot_id').read_text().strip()))

    @contextmanager
    def lock(self):
        self.trusted('/run', directory=True)
        descriptor = os.open(self.path(LOCK), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(descriptor)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == self.uid and info.st_nlink == 1
                    and stat.S_IMODE(info.st_mode) == 0o600, 'Unsafe host sharing lock.')
            try: fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError: raise Error('Another host sharing operation is running.') from None
            yield
        finally: os.close(descriptor)

    def write_state(self, state):
        root = self.path(RUNTIME)
        root.mkdir(mode=0o700, exist_ok=True)
        self.trusted(RUNTIME, directory=True, private=True)
        target = root / 'state.json'
        if target.exists() or target.is_symlink(): self.trusted(RUNTIME + '/state.json', private=True)
        temporary = root / ('.state-' + secrets.token_hex(12))
        descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(descriptor, 'w') as stream:
                json.dump(state, stream, sort_keys=True); stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
            os.replace(temporary, target)
            parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try: os.fsync(parent)
            finally: os.close(parent)
        finally: temporary.unlink(missing_ok=True)

    def read_state(self):
        if not self.path(RUNTIME).exists(): return None
        self.trusted(RUNTIME, directory=True, private=True)
        target = self.path(RUNTIME + '/state.json')
        if not target.exists() and not target.is_symlink():
            require(not list(self.path(RUNTIME).iterdir()), 'Unrecognized incomplete sharing runtime.')
            return None
        self.trusted(RUNTIME + '/state.json', private=True)
        require(target.stat().st_size <= 65536, 'Sharing state is too large.')
        value = json.loads(target.read_text(), object_pairs_hook=unique)
        require(type(value) is dict and set(value) == {'format', 'run_id', 'profile_identity', 'boot_id',
                'phase', 'selection', 'forwarding'} and value['format'] == 'AUTOMATIONS_HOST_SHARE.v1'
                and value['profile_identity'] == self.profile.identity and value['boot_id'] == self.boot()
                and value['phase'] in ('preparing', 'active', 'cleanup')
                and str(uuid.UUID(value['run_id'])) == value['run_id'], 'Sharing state identity is invalid.')
        self.validate_selection(value['selection'])
        expected = {item['name'] for item in [value['selection']['uplink'], *value['selection']['clients']]}
        require(type(value['forwarding']) is dict
                and set(value['forwarding']) == (expected if value['selection']['clients'] else set())
                and all(setting in ('0', '1') for setting in value['forwarding'].values()), 'Invalid forwarding receipt.')
        return value

    def interface(self, name):
        require(NAME.fullmatch(name) and name not in self.profile.protected_interfaces and name != 'lo',
                'Interface is invalid or protected.')
        rows = self.ip('-d', 'address', 'show', 'dev', name)
        require(len(rows) == 1, 'Selected interface is missing or ambiguous.')
        row = rows[0]
        require(row.get('ifname') == name and type(row.get('ifindex')) is int and row['ifindex'] > 0
                and row.get('link_type') in ('ether', '[1]') and not row.get('master')
                and not row.get('linkinfo', {}).get('info_kind') and 'UP' in row.get('flags', [])
                and row.get('operstate') in ('UP', 'UNKNOWN'), 'Interface must be an up, unbridged physical interface.')
        net = self.path('/sys/class/net/' + name)
        device = (net / 'device').resolve(strict=True)
        require(device.is_relative_to(self.path('/sys/devices').resolve())
                and int((net / 'ifindex').read_text()) == row['ifindex'], 'Interface hardware identity is not available.')
        for protected in self.profile.protected_interfaces:
            protected_device = self.path('/sys/class/net/' + protected + '/device')
            require(not protected_device.exists() or protected_device.resolve() != device,
                    'Selected hardware belongs to a protected interface.')
        address = row.get('permaddr', row.get('address', '')).lower()
        require(MAC.fullmatch(address) and address != '00:00:00:00:00:00', 'Interface hardware address is invalid.')
        addresses = [item for item in row.get('addr_info', []) if item.get('family') == 'inet'
                     and item.get('scope') in ('global', '0', 0)]
        require(len(addresses) == 1, 'Interface needs exactly one healthy global IPv4 address.')
        item = addresses[0]
        require(type(item.get('prefixlen')) is int and 8 <= item['prefixlen'] <= 30
                and item.get('valid_life_time', 1) != 0, 'Unsupported IPv4 prefix or expired address.')
        local = ipv4(item['local'])
        subnet = ipaddress.IPv4Interface(local + '/' + str(item['prefixlen'])).network
        return dict(name=name, ifindex=row['ifindex'], device_path=str(device.relative_to(self.root)),
                    mac=address, wireless=(net / 'phy80211').exists(), address=local, network=str(subnet))

    def validate_selection(self, value):
        require(type(value) is dict and set(value) == {'mode', 'uplink', 'clients', 'gateway', 'dns'}
                and value['mode'] in ('lan', 'wifi') and type(value['clients']) is list
                and len(value['clients']) <= 8 and type(value['dns']) is list and 1 <= len(value['dns']) <= 4,
                'Invalid sharing selection.')
        interfaces = [value['uplink'], *value['clients']]
        for item in interfaces:
            require(type(item) is dict and set(item) == {'name', 'ifindex', 'device_path', 'mac', 'wireless', 'address', 'network'}
                    and NAME.fullmatch(item['name']) and item['name'] not in self.profile.protected_interfaces
                    and type(item['ifindex']) is int and item['ifindex'] > 0 and MAC.fullmatch(item['mac'])
                    and type(item['wireless']) is bool and item['device_path'].startswith('sys/devices/')
                    and '..' not in Path(item['device_path']).parts, 'Invalid interface binding.')
            local = ipaddress.IPv4Address(ipv4(item['address']))
            subnet = ipaddress.IPv4Network(item['network'])
            require(8 <= subnet.prefixlen <= 30 and local in subnet, 'Invalid interface subnet binding.')
        require(len({item['name'] for item in interfaces}) == len(interfaces)
                and len({item['ifindex'] for item in interfaces}) == len(interfaces)
                and len({item['device_path'] for item in interfaces}) == len(interfaces), 'Interfaces must be independent.')
        for index, item in enumerate(interfaces):
            require(all(not ipaddress.IPv4Network(item['network']).overlaps(ipaddress.IPv4Network(other['network']))
                        for other in interfaces[index+1:]), 'Selected interface networks overlap.')
        require(value['uplink']['wireless'] == (value['mode'] == 'wifi'), 'Uplink type does not match --lan/--wifi.')
        require(ipaddress.IPv4Address(ipv4(value['gateway'])) in ipaddress.IPv4Network(value['uplink']['network'])
                and value['gateway'] != value['uplink']['address'], 'Uplink gateway must be on-link.')
        require(len(set(value['dns'])) == len(value['dns']), 'Duplicate uplink DNS servers.')
        for address in value['dns']: ipv4(address)

    def select(self, mode, name, sources):
        require(mode in ('lan', 'wifi') and name, 'An explicit --to interface is required.')
        uplink = self.interface(name)
        clients = [self.interface(source) for source in sources]
        if mode == 'wifi':
            wireless = self.command([IW, 'dev', name, 'info'])
            require(re.search(r'^\s*type managed\s*$', wireless, re.M), 'Wi-Fi uplink must already be in managed mode.')
        nmstate = self.command([NMCLI, '--escape', 'no', '-g', 'GENERAL.STATE', 'device', 'show', name]).strip()
        require(nmstate.split(' ', 1)[0] == '100', 'Uplink must already have a connected NetworkManager profile.')
        gateway = self.default_gateway(name)
        dns_text = self.command([NMCLI, '--escape', 'no', '-g', 'IP4.DNS', 'device', 'show', name])
        dns = list(dict.fromkeys(value.strip() for value in re.split(r'[|\n]', dns_text) if value.strip()))
        result = dict(mode=mode, uplink=uplink, clients=clients, gateway=gateway, dns=dns)
        self.validate_selection(result)
        self.probe(result)
        return result

    def default_gateway(self, name):
        # iproute2 omits dev in JSON when a dev filter already names it. Query
        # the explicit main table without that filter, then select by identity.
        rows = self.ip('-4', 'route', 'show', 'table', 'main', 'exact', '0.0.0.0/0')
        require(all(isinstance(row, dict) and row.get('table', 'main') in ('main', '254', 254)
                    and row.get('dst') in ('default', '0.0.0.0/0') for row in rows),
                'Unexpected table or destination in main default route response.')
        defaults = [row for row in rows if row.get('dev') == name]
        require(len(defaults) == 1 and defaults[0].get('gateway')
                and defaults[0].get('type', 'unicast') in ('unicast', '1', 1),
                'Uplink requires one unambiguous existing IPv4 default gateway.')
        return defaults[0]['gateway']

    def forwarding(self, name, value=None):
        require(NAME.fullmatch(name), 'Invalid forwarding interface.')
        path = self.path('/proc/sys/net/ipv4/conf/' + name + '/forwarding')
        current = path.read_text().strip()
        require(current in ('0', '1'), 'Cannot read interface forwarding state.')
        if value is not None:
            require(value in ('0', '1'), 'Invalid forwarding value.')
            path.write_text(value + '\n')
            require(path.read_text().strip() == value, 'Forwarding readback failed.')
        return current

    @staticmethod
    def clean_object(item):
        kind, body = next(iter(item.items()))
        return {kind: {key: value for key, value in body.items() if key not in ('handle', 'index')}}

    @staticmethod
    def canonical_nft(items):
        # nft removes redundant nfproto checks implied by an IPv4 payload.
        items = json.loads(json.dumps(items))
        for item in items:
            if 'rule' not in item: continue
            expressions = item['rule']['expr']
            for expression in expressions:
                value = expression.get('match', {})
                # Native nft output can reorder anonymous IPv4 address sets.
                # Sort only literal members; retain duplicates, rule order and
                # all other expression fields for the strict ownership check.
                right = value.get('right')
                if (isinstance(right, dict) and set(right) == {'set'}
                        and isinstance(right['set'], list)
                        and all(isinstance(member, str) for member in right['set'])):
                    try:
                        addresses = [ipaddress.IPv4Address(member) for member in right['set']]
                    except ipaddress.AddressValueError:
                        pass
                    else:
                        right['set'] = [member for _, member in sorted(
                            zip(map(int, addresses), right['set']))]
                if value.get('left') == meta('nfproto') and value.get('right') in (2, 10):
                    value['right'] = {2: 'ipv4', 10: 'ipv6'}[value['right']]
                if value.get('left') == {'ct': {'key': 'state'}} and value.get('right') in (2, 4):
                    value['right'] = {2: 'established', 4: 'related'}[value['right']]
            implied = any(expression.get('match', {}).get('left', {}).get('payload', {}).get('protocol') == 'ip'
                          for expression in expressions)
            if implied:
                item['rule']['expr'] = [expression for expression in expressions
                    if expression != match(meta('nfproto'), 'ipv4')]
        # Preserve order within each chain; regroup only nft's display ordering.
        tables = [item for item in items if 'table' in item]
        chains = sorted((item for item in items if 'chain' in item), key=lambda item: item['chain']['name'])
        require(len(items) == len(tables) + len(chains) + sum('rule' in item for item in items), 'Unknown owned nft object.')
        return tables + chains + [item for chain in chains for item in items
                                 if 'rule' in item and item['rule']['chain'] == chain['chain']['name']]

    def objects(self, state=None):
        own, observed_indices = [], {}
        items = self.firewall()
        extension = self.extension('host_egress.py')
        if extension is not None:
            try:
                items = extension.firewall_view(self, items)
            except extension.Error as error:
                raise Error(str(error)) from None
        for item in items:
            if set(item) == {'metainfo'}: continue
            require(len(item) == 1, 'Unrecognized nft object.')
            kind, body = next(iter(item.items()))
            if body.get('name' if kind == 'table' else 'table') == NFT_TABLE:
                cleaned = self.clean_object(item)
                if state is not None and kind == 'rule':
                    binding = {entry['name']: entry['ifindex'] for entry in
                               [state['selection']['uplink'], *state['selection']['clients']]}
                    for expression in cleaned['rule']['expr']:
                        value = expression.get('match', {})
                        if value.get('left') in (meta('iif'), meta('oif')) and type(value.get('right')) is str:
                            name = value['right']
                            if name == '0':
                                value['right'] = 0
                                continue
                            if name not in observed_indices:
                                observed = self.ip('-d', 'address', 'show', 'dev', name)
                                observed_indices[name] = observed[0].get('ifindex') if len(observed) == 1 else None
                            require(name in binding and observed_indices[name] == binding[name], 'nft interface identity changed.')
                            value['right'] = binding[name]
                own.append(cleaned)
            else:
                encoded = json.dumps(body, sort_keys=True)
                require('"mark"' not in encoded and body.get('type') != 'route',
                        'Existing firewall mark or route policy conflicts with host sharing.')
        own = self.canonical_nft(own)
        all_routes = self.ip('-4', 'route', 'show', 'table', 'all')
        own_routes = [self.clean_route(row) for row in all_routes if str(row.get('table', '254')) == str(TABLE)]
        own_rules = []
        for rule in self.ip('-4', 'rule', 'show'):
            mark = int(str(rule.get('fwmark', '0')), 0)
            mask = int(str(rule.get('fwmask', '0xffffffff')), 0)
            if rule.get('priority') == PRIORITY or str(rule.get('table')) == str(TABLE) or mark & mask & MARK:
                own_rules.append(rule)
        if state is None:
            require(not own and not own_routes and not own_rules, 'Reserved sharing objects exist without an ownership receipt.')
        else:
            require(not own or own == self.canonical_nft(nft_objects(state)), 'Owned nft table changed; refusing unverified cleanup.')
            expected_routes = routes(state)
            require(len(own_routes) <= len(expected_routes) and all(row in expected_routes for row in own_routes)
                    and len({json.dumps(row, sort_keys=True) for row in own_routes}) == len(own_routes),
                    'Owned routing table changed; refusing unverified cleanup.')
            require(len(own_rules) <= 1 and all(self.rule_matches(rule) for rule in own_rules),
                    'Reserved routing rule changed; refusing unverified cleanup.')
        return own, own_routes, own_rules

    @staticmethod
    def clean_route(row):
        result = dict(row)
        result.pop('flags', None)
        if result.get('scope') in ('global', '0', 0): result.pop('scope')
        if result.get('scope') in ('253', 253): result['scope'] = 'link'
        result['protocol'] = int(result.get('protocol', -1))
        result['table'] = int(result.get('table', 254))
        if result.get('type') in ('unicast', '1', 1): result.pop('type')
        if result.get('type') in ('7', 7): result['type'] = 'unreachable'
        return result

    @staticmethod
    def rule_matches(rule):
        return (set(rule) <= {'priority', 'src', 'fwmark', 'fwmask', 'table', 'protocol'}
                and rule.get('priority') == PRIORITY and rule.get('src') == 'all'
                and int(str(rule.get('fwmark', '0')), 0) == MARK
                and int(str(rule.get('fwmask', '0')), 0) == MARK
                and str(rule.get('table')) == str(TABLE)
                and str(rule.get('protocol', PROTOCOL)) == str(PROTOCOL))

    def check_interfaces(self, selection):
        for item in [selection['uplink'], *selection['clients']]:
            require(self.interface(item['name']) == item, 'A selected interface, address or hardware identity changed.')

    def healthy(self, state):
        self.check_interfaces(state['selection'])
        own, present_routes, present_rules = self.objects(state)
        require(own == self.canonical_nft(nft_objects(state)) and len(present_routes) == len(routes(state))
                and len(present_rules) == 1, 'Sharing activation is incomplete.')
        require(all(self.forwarding(name) == '1' for name in state['forwarding']), 'Sharing forwarding state changed.')
        selected = self.ip('-4', 'route', 'get', state['selection']['dns'][0], 'mark', hex(MARK))
        require(len(selected) == 1 and selected[0].get('dev') == state['selection']['uplink']['name']
                and str(selected[0].get('table')) == str(TABLE), 'Selected policy route readback failed.')
        return True

    def status(self):
        state = self.read_state()
        if state is None:
            self.objects()
            return dict(active=False, phase='off', selection=None, ipv6='normal host policy')
        self.healthy(state)
        require(state['phase'] == 'active', 'Sharing is incomplete; use --off for verified cleanup.')
        return dict(active=True, phase='active', selection=state['selection'], ipv6='blocked except host loopback')

    def require_mutation(self):
        require(os.geteuid() == 0, 'Root privileges are required to change host sharing.')
        require(self.profile.configured is True, 'Configure an explicit Kali host profile before sharing.')

    def enable(self, mode, name, sources=()):
        self.require_mutation()
        require(NAME.fullmatch(name or '') and len(sources) <= 8 and len(set(sources)) == len(sources),
                'Choose one explicit uplink and distinct client interfaces.')
        with self.lock():
            self.privacy_change_guard()
            existing = self.read_state()
            if existing:
                selected = existing['selection']
                require(existing['phase'] == 'active' and selected['mode'] == mode
                        and selected['uplink']['name'] == name
                        and [item['name'] for item in selected['clients']] == list(sources),
                        'Run --off before changing or recovering an existing sharing selection.')
                self.healthy(existing)
                return self.status(), False
            self.objects()
            selected = self.select(mode, name, sources)
            forwarding = {item['name']: self.forwarding(item['name'])
                          for item in [selected['uplink'], *selected['clients']]} if selected['clients'] else {}
            state = dict(format='AUTOMATIONS_HOST_SHARE.v1', run_id=str(uuid.uuid4()),
                         profile_identity=self.profile.identity, boot_id=self.boot(), phase='preparing',
                         selection=selected, forwarding=forwarding)
            commands = [{'add': item} for item in nft_objects(state)]
            self.nft(commands, check=True)
            self.check_interfaces(selected)
            self.objects()
            self.write_state(state)
            try:
                self.nft(commands)  # Guard first: a partial setup cannot fall back to another uplink.
                for row in routes(state): self.command([IP, '-4', 'route', 'add', *route_args(row)])
                self.command([IP, '-4', 'rule', 'add', 'priority', str(PRIORITY), 'fwmark',
                              hex(MARK) + '/' + hex(MARK), 'lookup', str(TABLE), 'protocol', str(PROTOCOL)])
                self.check_interfaces(selected)
                for interface, original in forwarding.items():
                    require(self.forwarding(interface) == original, 'Forwarding changed before activation.')
                    if original != '1': self.forwarding(interface, '1')
                self.healthy(state)
                self.probe(selected)
                state['phase'] = 'active'
                self.write_state(state)
                return self.status(), True
            except (Exception, KeyboardInterrupt) as error:
                try: self.cleanup(state)
                except Exception as cleanup_error:
                    raise Error('Host sharing failed; rollback incomplete, guards retained where possible: '
                                + str(error) + '; ' + str(cleanup_error)) from None
                raise Error('Host sharing failed; verified owned changes rolled back: ' + str(error)) from None

    def cleanup(self, state):
        own, present_routes, present_rules = self.objects(state)
        self.check_interfaces(state['selection'])
        state['phase'] = 'cleanup'
        self.write_state(state)
        for name, original in state['forwarding'].items():
            current = self.forwarding(name)
            require(current == original or current == '1', 'Forwarding changed externally; no overwrite.')
            if current != original: self.forwarding(name, original)
        if present_rules:
            self.command([IP, '-4', 'rule', 'del', 'priority', str(PRIORITY), 'fwmark',
                          hex(MARK) + '/' + hex(MARK), 'lookup', str(TABLE), 'protocol', str(PROTOCOL)])
        for row in reversed(present_routes): self.command([IP, '-4', 'route', 'del', *route_args(row)])
        if own:
            self.objects(state)
            self.nft([{'delete': {'table': {'family': 'inet', 'name': NFT_TABLE}}}])
        self.objects()
        require(all(self.forwarding(name) == original for name, original in state['forwarding'].items()),
                'Forwarding restoration could not be verified.')
        require(self.read_state() == state, 'Sharing receipt changed during cleanup.')
        self.path(RUNTIME + '/state.json').unlink()
        directory = os.open(self.path(RUNTIME), os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory)
        finally: os.close(directory)

    def disable(self):
        self.require_mutation()
        with self.lock():
            self.privacy_change_guard()
            state = self.read_state()
            if state is None:
                self.objects()
                return self.status(), False
            self.cleanup(state)
            return self.status(), True


def load_profile():
    path = Path(SUPPORT)
    for item in (path, *path.parents):
        info = item.lstat()
        require(not stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                'Installed platform support is not root-protected.')
    spec = importlib.util.spec_from_file_location('automations_host_share_platform', path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.load_profile()

def print_status(value):
    print('Host sharing: ' + value['phase'])
    if value['active']:
        selected = value['selection']
        print('Selected IPv4 uplink: ' + selected['uplink']['name'] + ' (' + selected['mode'] + ')')
        print('Client networks: ' + (', '.join(item['name'] + ' ' + item['network'] for item in selected['clients'])
                                   or 'none; host traffic only'))
        print('Selected ordinary TCP/UDP DNS: ' + selected['dns'][0] + '; local resolvers remain local')
        print('IPv6: blocked for host external traffic and selected clients; loopback remains local')
        print('Existing firewall restrictions still apply; remote Internet reachability is not guaranteed.')
        print('Temporary until --off or reboot; no AP, DHCP or NetworkManager profile is created.')
    else: print('Host routing and IPv6 use normal system policy.')

def main(argv=None, profile=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ['ap']:
        try:
            backend = HostShare(profile if profile is not None else load_profile())
            module = backend.extension('host_ap.py')
            require(module is not None, 'The optional VM access-point backend is not installed.')
            return module.share_main(argv[1:], profile=backend.profile)
        except (Error, OSError, ValueError) as error:
            print('ERROR: ' + str(error), file=sys.stderr)
            return 1
    parser = argparse.ArgumentParser(prog='auto share', description=__doc__)
    actions = parser.add_mutually_exclusive_group()
    for action in ('status', 'off', 'lan', 'wifi'):
        actions.add_argument('--' + action, dest='action', action='store_const', const=action)
    parser.add_argument('--to', dest='uplink', metavar='IFACE', help='Explicit already-connected uplink')
    parser.add_argument('--from', dest='clients', metavar='IFACE[,IFACE]', help='Explicit client networks; omitted means host only')
    args = parser.parse_args(argv)
    if (args.uplink or args.clients is not None) and args.action not in ('lan', 'wifi'):
        parser.error('--to/--from require --lan or --wifi')
    if args.action in ('lan', 'wifi') and not args.uplink:
        parser.error('--lan/--wifi require an explicit --to interface')
    clients = args.clients.split(',') if args.clients is not None else []
    if args.clients is not None and (not clients or any(not NAME.fullmatch(item) for item in clients)):
        parser.error('--from needs explicit comma-separated interface names')
    try:
        if args.action in ('off', 'lan', 'wifi'):
            require(os.geteuid() == 0, 'Root privileges are required to change host sharing.')
        backend = HostShare(profile if profile is not None else load_profile())
        if args.action in ('lan', 'wifi'): value, _ = backend.enable(args.action, args.uplink, clients)
        elif args.action == 'off': value, _ = backend.disable()
        else: value = backend.status()
        print_status(value)
        return 0
    except (Error, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        print('ERROR: ' + str(error), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('ERROR: Host sharing interrupted; inspect --status before continuing.', file=sys.stderr)
        return 130

if __name__ == '__main__': raise SystemExit(main())
