"""Owned, temporary Tor routing for the Kali host platform.

Protocol, HTTPS verification and rotation remain in auto_tor.py. This module
owns only the host guard, its policy route and its protected runtime receipt.
"""

from __future__ import annotations

from contextlib import contextmanager
import copy
import fcntl
import importlib.machinery
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import stat
import sys
import uuid

TABLE = 'automations_host_tor'
ROUTE_TABLE, PRIORITY, PROTOCOL = 51828, 10426, 187
MARK = 0x02000000
RUNTIME = '/run/automations-host-tor'
STATE = RUNTIME + '/state.json'
LOCK = '/run/automations-host-share.lock'
SHARE = '/usr/local/libexec/automations-host/share'
SERVICE = 'automations-tor.service'
SS, SYSTEMCTL, CONNTRACK = '/usr/bin/ss', '/usr/bin/systemctl', '/usr/sbin/conntrack'
IP, NFT = '/usr/sbin/ip', '/usr/sbin/nft'
PHASES = ('starting', 'active', 'recovering', 'blocked', 'cleanup')
FORMAT = 'AUTOMATIONS_HOST_TOR.v1'
MAX_STATE = 65536


class Error(RuntimeError):
    pass


class Busy(Error):
    """Only contention before an operation has begun may be deferred."""


def require(value, message):
    if not value:
        raise Error(message)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'Duplicate Tor receipt field.')
        result[key] = value
    return result


def load_share(root=Path('/'), owner_uid=0):
    root = Path(root)
    path = root / SHARE.lstrip('/')
    for candidate in (path, *path.parents):
        if not candidate.is_relative_to(root):
            continue
        info = candidate.lstat()
        require(not stat.S_ISLNK(info.st_mode) and info.st_uid == owner_uid and not info.st_mode & 0o022,
                'The host sharing helper is not root-protected.')
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 512 * 1024,
            'The host sharing helper has an unsupported file type or size.')
    loader = importlib.machinery.SourceFileLoader('_automations_host_tor_share', str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules[loader.name] = module
    loader.exec_module(module)
    return module


def match(left, right, op='=='):
    return {'match': {'op': op, 'left': left, 'right': right}}


def meta(key):
    return {'meta': {'key': key}}


def payload(protocol, field):
    return {'payload': {'protocol': protocol, 'field': field}}


def network(value):
    subnet = ipaddress.IPv4Network(value)
    return {'prefix': {'addr': str(subnet.network_address), 'len': subnet.prefixlen}}


def nft_objects(state):
    """Construct only fixed expressions from an already validated receipt."""
    selected, phase = state['selection'], state['phase']
    uplink, clients = selected['uplink'], selected['clients']
    token = 'automations-host-tor:' + state['run_id']
    result = [{'table': {'family': 'inet', 'name': TABLE, 'comment': token}}]
    for name, kind, hook, priority, policy in (
            ('local_nat', 'nat', 'output', -110, 'accept'),
            ('client_nat', 'nat', 'prerouting', -110, 'accept'),
            ('client_guard', 'filter', 'prerouting', -310, 'accept'),
            ('input_guard', 'filter', 'input', -30, 'accept'),
            ('output_guard', 'filter', 'output', 0, 'drop'),
            ('forward_guard', 'filter', 'forward', -40, 'drop')):
        result.append({'chain': {'family': 'inet', 'table': TABLE, 'name': name,
                       'type': kind, 'hook': hook, 'prio': priority, 'policy': policy}})

    def rule(chain, *expressions):
        result.append({'rule': {'family': 'inet', 'table': TABLE, 'chain': chain,
            'expr': list(expressions), 'comment': token + ':' + str(len(result))}})

    v4, v6 = match(meta('nfproto'), 'ipv4'), match(meta('nfproto'), 'ipv6')
    accept, returned, drop = {'accept': None}, {'return': None}, {'drop': None}
    loop = match(meta('oifname'), 'lo')
    ctmark = {'ct': {'key': 'mark'}}
    mark = {'mangle': {'key': ctmark, 'value': {'|': [ctmark, MARK]}}}
    marked = match({'&': [ctmark, MARK]}, MARK)
    dnat = match({'ct': {'key': 'status'}}, 'dnat', 'in')
    established = match({'ct': {'key': 'state'}}, 'established')
    reply = match({'ct': {'key': 'direction'}}, 'reply')
    # Preserve only an observed SSH tuple with ACK and without SYN. Existing
    # TCP sockets can predate conntrack hooks, so their first packet may be NEW
    # even though the socket is established. New handshakes remain redirected.
    for item in state['management']:
        flow = (v4, match(payload('ip', 'saddr'), item['source']),
                match(payload('ip', 'daddr'), item['destination']),
                match(payload('tcp', 'sport'), item['source_port']),
                match(payload('tcp', 'dport'), item['destination_port']),
                match({'&': [payload('tcp', 'flags'), 0x12]}, 0x10),
                match(meta('oif'), uplink['ifindex']))
        rule('local_nat', *flow, returned)
        rule('output_guard', *flow, accept)
    # Preserve replies to local client-side services; this cannot open an
    # application-originated direct connection or an external forwarded path.
    for client in clients:
        dhcp_reply = (v4, match(meta('oif'), client['ifindex']),
                      match(payload('ip', 'saddr'), client['address']),
                      match(payload('udp', 'sport'), 67), match(payload('udp', 'dport'), 68))
        for destination in ('255.255.255.255', network(client['network'])):
            rule('local_nat', *dhcp_reply, match(payload('ip', 'daddr'), destination), returned)
            rule('output_guard', *dhcp_reply, match(payload('ip', 'daddr'), destination), accept)
        local_reply = (v4, match(meta('oif'), client['ifindex']),
                       match(payload('ip', 'saddr'), client['address']),
                       match(payload('ip', 'daddr'), network(client['network'])), established, reply)
        rule('local_nat', *local_reply, returned)
        rule('output_guard', *local_reply, accept)
    rule('local_nat', match(meta('skuid'), state['uid']), returned)
    rule('local_nat', v4, match(payload('ip', 'daddr'), network('127.0.0.0/8')), returned)
    rule('local_nat', v6, match(payload('ip6', 'daddr'), '::1'), returned)
    # The wildcard IPv4 DNS listener must receive the owned local address.
    # This fixes its reply source so reverse DNAT restores the requested DNS
    # peer. A loopback destination can produce an unmatched wildcard reply.
    # NAT still precedes host_share's DNS DNAT (-100); IPv6 stays loopback.
    for family, destination in (('ip', uplink['address']), ('ip6', '::1')):
        check = v4 if family == 'ip' else v6
        rule('local_nat', check, match(payload('tcp', 'dport'), 53), drop)
        rule('local_nat', check, match(payload('udp', 'dport'), 53), mark,
             {'dnat': {'family': family, 'addr': destination, 'port': 19053}})
    rule('local_nat', v4, match(meta('l4proto'), 'tcp'), mark,
         {'dnat': {'family': 'ip', 'addr': '127.0.0.1', 'port': 19040}})

    for client in clients:
        incoming = match(meta('iif'), client['ifindex'])
        source = match(payload('ip', 'saddr'), network(client['network']))
        rule('client_guard', incoming, v6, drop)
        for origin in ('0.0.0.0', network(client['network'])):
            dhcp_request = (incoming, v4, match(payload('ip', 'saddr'), origin),
                            match(payload('udp', 'sport'), 68), match(payload('udp', 'dport'), 67),
                            match(payload('ip', 'daddr'), {'set': ['255.255.255.255', client['address']]}))
            rule('client_guard', *dhcp_request, returned)
            rule('client_nat', *dhcp_request, returned)
        rule('client_guard', incoming, v4,
             match(payload('ip', 'saddr'), network(client['network']), '!='), drop)
        rule('client_guard', incoming, v4, match(payload('tcp', 'dport'), 53), drop)
        rule('client_nat', incoming, v4, source, match(payload('udp', 'dport'), 53), mark,
             {'redirect': {'port': 19053}})
        rule('client_nat', incoming, v4, source,
             match(payload('ip', 'daddr'), client['address']), returned)
        rule('client_nat', incoming, v4, source, match(meta('l4proto'), 'tcp'), mark,
             {'redirect': {'port': 19040}})
        if phase == 'active':
            for protocol, port in (('tcp', 19040), ('udp', 19053)):
                rule('input_guard', incoming, v4, source,
                     match(payload('ip', 'daddr'), client['address']),
                     match(payload(protocol, 'dport'), port), marked, dnat, accept)

    # An exposed wildcard Tor listener is never a remote SOCKS/Trans/DNS proxy.
    rule('input_guard', match(meta('iifname'), 'lo'), match(payload('tcp', 'dport'), 19050), accept)
    if phase == 'active':
        for protocol, port in (('tcp', 19040), ('udp', 19053)):
            rule('input_guard', match(meta('iifname'), 'lo'), match(payload(protocol, 'dport'), port), accept)
    for protocol in ('tcp', 'udp'):
        rule('input_guard', match(payload(protocol, 'dport'), {'set': [19040, 19050, 19053]}), drop)

    rule('output_guard', loop, v4, match(meta('skuid'), 0),
         match(payload('ip', 'daddr'), '127.0.0.1'), match(payload('tcp', 'dport'), 19050), accept)
    # Check these before the ordinary loopback exception, including old flows.
    rule('output_guard', match(payload('tcp', 'dport'), 19050), drop)
    if phase != 'active':
        for protocol in ('tcp', 'udp'):
            rule('output_guard', match(payload(protocol, 'dport'), {'set': [19040, 19053]}), drop)
    if phase == 'active':
        # OUTPUT still exposes the route's old oif after DNAT. The actual
        # loopback reroute happens after this hook, so admit only our original
        # marked DNAT flows to the fixed local transparent/DNS listeners.
        for family, destination, protocol, port in (
                ('ip', '127.0.0.1', 'tcp', 19040), ('ip', uplink['address'], 'udp', 19053),
                ('ip6', '::1', 'udp', 19053)):
            rule('output_guard', v4 if family == 'ip' else v6, match(meta('l4proto'), protocol),
                 match(payload(family, 'daddr'), destination), match(payload(protocol, 'dport'), port),
                 match({'ct': {'key': 'direction'}}, 'original'), marked, dnat, accept)
    rule('output_guard', loop, accept)
    # DHCP lease maintenance is the sole external UDP exception; no DNS bypass.
    rule('output_guard', v4, match(meta('oif'), uplink['ifindex']),
         match(payload('udp', 'sport'), 68), match(payload('udp', 'dport'), 67),
         match(payload('ip', 'saddr'), {'set': ['0.0.0.0', uplink['address']]}),
         match(payload('ip', 'daddr'), {'set': ['255.255.255.255', selected['gateway']]}), accept)
    if phase in ('starting', 'recovering', 'active'):
        rule('output_guard', match(meta('skuid'), state['uid']), match(payload('tcp', 'dport'), 53), drop)
        rule('output_guard', v4, match(meta('skuid'), state['uid']),
             match(meta('oif'), uplink['ifindex']), match(payload('ip', 'saddr'), uplink['address']),
             match(meta('l4proto'), 'tcp'), accept)
    return result


def route_objects(state):
    uplink = state['selection']['uplink']
    return [dict(dst=uplink['network'], dev=uplink['name'], prefsrc=uplink['address'],
                 scope='link', table=ROUTE_TABLE, protocol=PROTOCOL),
            *[dict(dst=client['network'], dev=client['name'], prefsrc=client['address'],
                   scope='link', table=ROUTE_TABLE, protocol=PROTOCOL)
              for client in state['selection']['clients']],
            dict(dst='default', gateway=state['selection']['gateway'], dev=uplink['name'],
                 prefsrc=uplink['address'], metric=100, table=ROUTE_TABLE, protocol=PROTOCOL),
            dict(type='unreachable', dst='default', metric=42760, table=ROUTE_TABLE, protocol=PROTOCOL)]


def canonical_uid_rule(row):
    """Accept exactly one unambiguous native or legacy single-UID rule."""
    require(type(row) is dict, 'Invalid host Tor UID rule object.')
    base = {'priority', 'src', 'table', 'protocol'}
    native, legacy = {'uid_start', 'uid_end'}, {'uidrange'}
    require(set(row) in (base | native, base | legacy), 'Owned host Tor UID rule fields changed.')
    if 'uidrange' in row:
        span = row['uidrange']
        require(type(span) is dict and set(span) == {'start', 'end'}, 'Invalid legacy Tor UID range.')
        first, last = span['start'], span['end']
    else:
        first, last = row['uid_start'], row['uid_end']
    require(type(first) is int and type(last) is int and 0 < first == last < 65534,
            'Invalid host Tor single-UID range.')
    require(type(row['priority']) is int and row['priority'] == PRIORITY and row['src'] == 'all'
            and type(row['table']) in (str, int) and str(row['table']) == str(ROUTE_TABLE)
            and type(row['protocol']) in (str, int) and str(row['protocol']) == str(PROTOCOL),
            'Owned host Tor UID rule identity changed.')
    return dict(priority=PRIORITY, src='all', uidrange={'start': first, 'end': last},
                table=ROUTE_TABLE, protocol=PROTOCOL)


class Runtime:
    Busy = Busy

    def __init__(self, profile=None, *, uplink=None, mode=None, management_networks=(), ssh_port=22,
                 share=None, root=Path('/'), runner=None, owner_uid=0,
                 account_lookup=pwd.getpwnam, backend=None):
        if backend is None:
            share = share or load_share(root, owner_uid)
            profile = profile or share.load_profile()
            backend = share.HostShare(profile, root=root, runner=runner, owner_uid=owner_uid)
        self.backend, self.profile = backend, backend.profile
        self.root, self.owner = backend.root, backend.uid
        self.account_lookup = account_lookup
        self.uplink, self.uplink_mode = uplink, mode
        self.management_networks, self.ssh_port = tuple(management_networks), ssh_port
        self.held = False
        require(self.profile.platform == 'kali-host', 'Tor requires the Kali host platform.')

    def namespace(self):
        value = os.readlink(self.backend.path('/proc/self/ns/net'))
        require(re.fullmatch(r'net:\[[0-9]+\]', value), 'Network namespace identity is unavailable.')
        return value

    def state(self):
        try:
            return self._state()
        except Error:
            raise
        except (RuntimeError, OSError, ValueError, TypeError, KeyError, AttributeError):
            raise Error('Host Tor receipt ownership, identity or format is invalid.') from None

    def _state(self):
        parent, path = self.backend.path(RUNTIME), self.backend.path(STATE)
        if not parent.exists() and not parent.is_symlink():
            return None
        self.backend.trusted(RUNTIME, directory=True, private=True)
        value = self.read_receipt(path) if path.exists() or path.is_symlink() else None
        self.temporary_files(value)
        return value

    def read_receipt(self, path):
        self.backend.trusted('/' + str(path.relative_to(self.root)), private=True)
        require(path.stat().st_size <= MAX_STATE, 'Host Tor receipt is too large.')
        value = json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=unique)
        expected = {'format', 'mode', 'run_id', 'profile_identity', 'boot_id', 'netns', 'phase',
                    'pending', 'uid', 'selection', 'share_run_id', 'management', 'management_networks', 'ssh_port'}
        require(type(value) is dict and set(value) == expected and value['format'] == FORMAT
                and value['mode'] == 'tor' and value['profile_identity'] == self.profile.identity
                and value['boot_id'] == self.backend.boot() and value['netns'] == self.namespace()
                and str(uuid.UUID(value['run_id'])) == value['run_id']
                and value['phase'] in PHASES and (value['pending'] is None or value['pending'] in PHASES)
                and type(value['uid']) is int and 0 < value['uid'] < 65534,
                'Host Tor receipt identity is invalid.')
        self.backend.validate_selection(value['selection'])
        require(value['share_run_id'] is None or str(uuid.UUID(value['share_run_id'])) == value['share_run_id'],
                'Invalid host sharing receipt binding.')
        require(value['share_run_id'] is not None or not value['selection']['clients'],
                'Host-only Tor cannot adopt client forwarding.')
        uplink = value['selection']['uplink']
        allowed = self.validate_management_networks(value['management_networks'], uplink)
        require(type(value['ssh_port']) is int and 1 <= value['ssh_port'] <= 65535
                and type(value['management']) is list and len(value['management']) <= 32,
                'Invalid Tor management receipt.')
        seen = set()
        for flow in value['management']:
            require(type(flow) is dict and set(flow) == {'source', 'destination', 'source_port', 'destination_port'}
                    and flow['source'] == uplink['address'] and flow['source_port'] == value['ssh_port']
                    and type(flow['destination_port']) is int and 1 <= flow['destination_port'] <= 65535
                    and any(ipaddress.IPv4Address(flow['destination']) in net for net in allowed),
                    'Invalid SSH flow binding.')
            encoded = json.dumps(flow, sort_keys=True)
            require(encoded not in seen, 'Duplicate SSH flow binding.')
            seen.add(encoded)
        return value

    def temporary_files(self, current):
        """Recognize complete interrupted writes, never merely a filename."""
        result = []
        for path in self.backend.path(RUNTIME).iterdir():
            if path.name == 'state.json':
                continue
            require(re.fullmatch(r'\.state-[0-9a-f]{24}', path.name),
                    'Unrecognized object in host Tor runtime; refusing removal.')
            value = self.read_receipt(path)
            if current is None:
                # Before the first publication no kernel mutation has happened.
                require(value['phase'] == 'starting' and value['pending'] is None,
                        'An unbound interrupted Tor receipt needs inspection.')
            else:
                immutable = lambda data: {key: item for key, item in data.items()
                                          if key not in ('phase', 'pending')}
                require(immutable(value) == immutable(current),
                        'Interrupted Tor receipt belongs to a different activation.')
            result.append(path)
        return result

    def discard_temporaries(self, expected):
        self.assert_operation()
        require(self.state() == expected, 'Host Tor receipt changed before temporary cleanup.')
        # Validate every directory entry before unlinking even one own file.
        paths = self.temporary_files(expected)
        for path in paths:
            path.unlink()
        self.sync_directory()

    @staticmethod
    def validate_management_networks(values, uplink):
        require(type(values) in (list, tuple) and len(values) <= 8, 'Invalid management networks.')
        connected = ipaddress.IPv4Network(uplink['network'])
        networks = [ipaddress.IPv4Network(value) for value in values]
        require(len(set(networks)) == len(networks) and all(net.subnet_of(connected) for net in networks),
                'Management networks must be explicit subsets of the selected directly connected subnet.')
        return networks

    def save(self, value, expected):
        require(self.state() == expected, 'Host Tor receipt changed; refusing overwrite.')
        self.backend.trusted('/run', directory=True)
        parent = self.backend.path(RUNTIME)
        parent.mkdir(mode=0o700, exist_ok=True)
        self.backend.trusted(RUNTIME, directory=True, private=True)
        temporary = parent / ('.state-' + secrets.token_hex(12))
        fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY, 0o600)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                json.dump(value, stream, sort_keys=True)
                stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
            require(self.state() == expected, 'Host Tor receipt changed before publication.')
            os.replace(temporary, self.backend.path(STATE))
            self.sync_directory()
        finally:
            temporary.unlink(missing_ok=True)

    def sync_directory(self):
        fd = os.open(self.backend.path(RUNTIME), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def external(self, args, accepted=(0,)):
        require(args[0] in (SS, SYSTEMCTL, CONNTRACK), 'Unsupported host Tor executable.')
        executable = self.backend.trusted(args[0])
        require(executable.stat().st_mode & 0o111, 'Host Tor tool is not executable.')
        result = self.backend.run(args, None)
        require(result.returncode in accepted and isinstance(result.stdout, str)
                and len(result.stdout) <= 4 * 1024 * 1024, 'A required host Tor tool failed.')
        return result.stdout

    def management(self, selection):
        uplink = selection['uplink']
        values = list(self.management_networks) or [uplink['network']]
        allowed = self.validate_management_networks(values, uplink)
        require(type(self.ssh_port) is int and 1 <= self.ssh_port <= 65535, 'Invalid SSH port.')
        text = self.external([SS, '-H', '-n', '-t', '-4', 'state', 'established',
                              '(', 'sport', '=', ':' + str(self.ssh_port), ')'])
        flows = []
        for line in text.splitlines():
            fields = line.split()
            require(4 <= len(fields) <= 8, 'Unrecognized established SSH socket output.')
            local, remote = fields[-2:]
            local_ip, local_port = local.rsplit(':', 1)
            remote_ip, remote_port = remote.rsplit(':', 1)
            ipaddress.IPv4Address(local_ip); peer = ipaddress.IPv4Address(remote_ip)
            require(local_port.isdecimal() and remote_port.isdecimal(), 'Unrecognized SSH socket ports.')
            if local_ip != uplink['address'] or int(local_port) != self.ssh_port:
                continue
            require(any(peer in net for net in allowed),
                    'Existing SSH management is outside the explicitly selected local networks.')
            flow = dict(source=local_ip, destination=str(peer), source_port=int(local_port),
                        destination_port=int(remote_port))
            require(1 <= flow['destination_port'] <= 65535 and flow not in flows and len(flows) < 32,
                    'Invalid or excessive established SSH sockets.')
            flows.append(flow)
        return values, sorted(flows, key=lambda flow: (flow['destination'], flow['destination_port']))

    def canonical(self, items, state=None):
        items = [copy.deepcopy(self.backend.clean_object(item)) for item in items]
        aliases = None
        for item in items:
            for expression in item.get('rule', {}).get('expr', []):
                check = expression.get('match', {})
                flags = {'payload': {'protocol': 'tcp', 'field': 'flags'}}
                left = check.get('left')
                if isinstance(left, dict) and set(left) == {'&'} and isinstance(left['&'], list) and len(left['&']) == 2 and left['&'][0] == flags:
                    mask = left['&'][1]
                    if (isinstance(mask, dict) and set(mask) == {'|'}
                            and isinstance(mask['|'], list) and len(mask['|']) == 2
                            and all(type(value) is int for value in mask['|'])
                            and set(mask['|']) == {2, 16}):
                        left['&'][1] = 18
                if (check.get('left') == {'meta': {'key': 'l4proto'}}
                        and type(check.get('right')) is int and check['right'] == 6):
                    check['right'] = 'tcp'
                if check.get('left') == {'meta': {'key': 'nfproto'}} and check.get('right') in (2, 10):
                    check['right'] = {2: 'ipv4', 10: 'ipv6'}[check['right']]
                right = check.get('right')
                if isinstance(right, dict) and set(right) == {'set'}:
                    right['set'] = sorted(right['set'], key=lambda value: json.dumps(value, sort_keys=True))
                if (check.get('left') in ({'meta': {'key': 'iif'}}, {'meta': {'key': 'oif'}})
                        and isinstance(check.get('right'), str)):
                    require(state is not None, 'Unbound firewall interface name.')
                    if aliases is None:
                        self.backend.check_interfaces(state['selection'])
                        aliases = {binding['name']: binding['ifindex'] for binding in
                                   [state['selection']['uplink'], *state['selection']['clients']]}
                    require(check['right'] in aliases, 'Unexpected firewall interface name.')
                    check['right'] = aliases[check['right']]
                if (check.get('left') == {'ct': {'key': 'direction'}}
                        and type(check.get('right')) is int and check['right'] in (0, 1)):
                    check['right'] = {0: 'original', 1: 'reply'}[check['right']]
                if (check.get('left') == {'ct': {'key': 'status'}} and check.get('op') == 'in'
                        and type(check.get('right')) is int and check['right'] == 32):
                    check['right'] = 'dnat'
            rule = item.get('rule')
            if rule is not None:
                implied = {expression.get('match', {}).get('left', {}).get('payload', {}).get('protocol')
                           for expression in rule['expr']} & {'tcp', 'udp'}
                # Native nft omits only a dependency already enforced by its
                # typed transport payload. Contradictory/non-equality matches
                # are retained and still fail the complete ownership check.
                dependencies = [match(meta('l4proto'), protocol) for protocol in implied]
                rule['expr'] = [expression for expression in rule['expr'] if expression not in dependencies]
            if rule is not None and any(expression.get('match', {}).get('left', {}).get(
                    'payload', {}).get('protocol') == 'ip6' for expression in rule['expr']):
                rule['expr'] = [expression for expression in rule['expr']
                                if expression != match(meta('nfproto'), 'ipv6')]
        return self.backend.canonical_nft(items)

    def guard(self, items, state, allow_absent=False):
        own = []
        for item in items:
            if set(item) == {'metainfo'}:
                continue
            require(type(item) is dict and len(item) == 1, 'Unrecognized firewall object.')
            kind, body = next(iter(item.items()))
            require(type(body) is dict, 'Unrecognized firewall object body.')
            if body.get('name' if kind == 'table' else 'table') == TABLE:
                require(body.get('family') == 'inet' and kind in ('table', 'chain', 'rule'),
                        'Unexpected reserved host Tor firewall object.')
                own.append(item)
        actual = self.canonical(own, state)
        if state is None:
            require(not actual, 'Host Tor firewall exists without its ownership receipt.')
            return None
        if not actual:
            require(allow_absent, 'The owned host Tor guard is absent; blocking is not verified.')
            return None
        for phase in (state['phase'], state['pending']):
            if phase is not None and actual == self.canonical(nft_objects({**state, 'phase': phase}), state):
                return phase
        raise Error('Owned host Tor firewall changed; refusing to overwrite or remove it.')

    def batch(self, state, phase, allow_absent=False):
        data = self.backend.firewall()
        actual = self.guard(data, state, allow_absent)
        commands = []
        if actual is not None:
            commands.append({'delete': {'table': {'family': 'inet', 'name': TABLE}}})
        if phase is not None:
            commands += [{'add': item} for item in nft_objects({**state, 'phase': phase})]
        if commands:
            self.backend.nft(commands, check=True)
            self.backend.nft(commands)
        self.guard(self.backend.firewall(), None if phase is None else {**state, 'phase': phase, 'pending': None})

    def routes(self, state, complete=True):
        expected = route_objects(state)
        actual = [self.backend.clean_route(row) for row in self.backend.ip('-4', 'route', 'show', 'table', 'all')
                  if str(row.get('table', 254)) == str(ROUTE_TABLE)]
        require(len(actual) <= len(expected) and all(row in expected for row in actual)
                and len({json.dumps(row, sort_keys=True) for row in actual}) == len(actual),
                'Owned host Tor routes changed; refusing unverified cleanup.')
        own = []
        for row in self.backend.ip('-4', 'rule', 'show'):
            if str(row.get('priority')) == str(PRIORITY) or str(row.get('table')) == str(ROUTE_TABLE):
                value = canonical_uid_rule(row)
                require(value['uidrange'] == {'start': state['uid'], 'end': state['uid']},
                        'Owned host Tor UID rule account changed.')
                own.append(value)
        require(len(own) <= 1 and (not complete or len(actual) == len(expected) and len(own) == 1),
                'Host Tor policy routing is incomplete.')
        return actual, own

    def vacant(self):
        require(not [row for row in self.backend.ip('-4', 'route', 'show', 'table', 'all')
                     if str(row.get('table', 254)) == str(ROUTE_TABLE)], 'Reserved Tor routing table is occupied.')
        for row in self.backend.ip('-4', 'rule', 'show'):
            require(str(row.get('priority')) != str(PRIORITY) and str(row.get('table')) != str(ROUTE_TABLE),
                    'Reserved Tor routing rule is occupied.')

    @staticmethod
    def route_args(row):
        args = ([row['type']] if row.get('type') else []) + [row['dst']]
        for key, flag in (('gateway', 'via'), ('dev', 'dev'), ('prefsrc', 'src'), ('scope', 'scope'),
                          ('metric', 'metric'), ('protocol', 'proto'), ('table', 'table')):
            if key in row:
                args += [flag, str(row[key])]
        return args

    def rule_args(self, state):
        return ['priority', str(PRIORITY), 'uidrange', str(state['uid']) + '-' + str(state['uid']),
                'lookup', str(ROUTE_TABLE), 'protocol', str(PROTOCOL)]

    def selection(self):
        record = self.backend.read_state()
        if record is not None:
            require(record['phase'] == 'active', 'Sharing is incomplete; Tor activation refused.')
            self.backend.healthy(record)
            selected = record['selection']
            require((self.uplink is None or self.uplink == selected['uplink']['name'])
                    and (self.uplink_mode is None or self.uplink_mode == selected['mode']),
                    'Explicit Tor uplink conflicts with active sharing.')
            return copy.deepcopy(selected), record['run_id']
        require(self.uplink and self.uplink_mode in ('lan', 'wifi'),
                'Without active sharing Tor requires an explicit --to and --lan/--wifi selection.')
        self.backend.objects()
        return self.backend.select(self.uplink_mode, self.uplink, []), None

    def healthy_selection(self, state):
        require(self.profile.configured is True, 'Configure an explicit Kali host profile before enabling Tor.')
        require(self.account_lookup('auto-tor').pw_uid == state['uid'], 'Dedicated Tor account identity changed.')
        self.backend.check_interfaces(state['selection'])
        require(self.backend.default_gateway(state['selection']['uplink']['name']) == state['selection']['gateway'],
                'Selected Tor gateway changed.')
        record = self.backend.read_state()
        if state['share_run_id'] is None:
            require(record is None and not state['selection']['clients'],
                    'Sharing appeared during host-only Tor; turn Tor off first.')
        else:
            require(record is not None and record['phase'] == 'active'
                    and record['run_id'] == state['share_run_id'] and record['selection'] == state['selection'],
                    'Selected sharing receipt changed; direct fallback remains blocked.')
            self.backend.healthy(record)

    def assert_operation(self):
        require(self.held, 'Host Tor mutation requires its serialized operation context.')

    @contextmanager
    def operation(self, mode):
        require(mode == 'tor' and not self.held, 'Unsupported or nested host privacy operation.')
        require(os.geteuid() == self.owner and self.profile.configured is True,
                'A trusted configured host profile and root privileges are required.')
        self.backend.trusted('/run', directory=True)
        fd = os.open(self.backend.path(LOCK), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == self.owner and info.st_nlink == 1
                    and stat.S_IMODE(info.st_mode) == 0o600, 'Unsafe shared host operation lock.')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Busy('Another host sharing or Tor operation is running.') from None
            self.state()  # Refuse invalid ownership/identity before an operation begins.
            self.held = True
            try:
                yield self
            except BaseException as original:
                try:
                    if self.state() is not None:
                        self.block()
                except BaseException:
                    raise Error('Host Tor operation failed and its guard could not be verified; '
                                'traffic blocking is not confirmed.') from original
                if isinstance(original, RuntimeError) and not isinstance(original, Error):
                    raise Error(str(original)) from None
                if type(original) is Busy:
                    raise Error(str(original)) from None
                raise
            finally:
                self.held = False
        finally:
            os.close(fd)

    def transition(self, phase):
        self.assert_operation()
        current = self.state()
        require(current is not None and phase in PHASES, 'No owned host Tor activation exists.')
        actual = self.guard(self.backend.firewall(), current,
                            allow_absent=current['phase'] in ('starting', 'cleanup'))
        # Persist both possible exact table definitions before the atomic swap.
        # A killed process can only leave one of these two owned definitions.
        intent = {**current, 'phase': actual or current['phase'], 'pending': phase}
        self.save(intent, current)
        self.batch(intent, phase, allow_absent=actual is None)
        self.save({**intent, 'phase': phase, 'pending': None}, intent)

    def purge(self):
        self.external([CONNTRACK, '-D', '--mark', hex(MARK) + '/' + hex(MARK)], accepted=(0, 1))

    def activate(self, uid, tcp_port, dns_port):
        self.assert_operation()
        require(self.state() is None and (tcp_port, dns_port) == (19040, 19053)
                and type(uid) is int and 0 < uid < 65534
                and self.account_lookup('auto-tor').pw_uid == uid, 'Invalid or existing host Tor activation.')
        self.guard(self.backend.firewall(), None)
        self.vacant()
        if self.backend.path(RUNTIME).exists():
            self.discard_temporaries(None)
        selected, share_id = self.selection()
        networks, management = self.management(selected)
        value = dict(format=FORMAT, mode='tor', run_id=str(uuid.uuid4()),
                     profile_identity=self.profile.identity, boot_id=self.backend.boot(), netns=self.namespace(),
                     phase='starting', pending=None, uid=uid, selection=selected, share_run_id=share_id,
                     management=management, management_networks=networks, ssh_port=self.ssh_port)
        self.backend.nft([{'add': item} for item in nft_objects(value)], check=True)
        self.save(value, None)
        self.batch(value, 'starting', allow_absent=True)
        for row in route_objects(value):
            self.backend.command([IP, '-4', 'route', 'add', *self.route_args(row)])
        self.backend.command([IP, '-4', 'rule', 'add', *self.rule_args(value)])
        self.routes(value)
        self.healthy_selection(value)
        self.purge()

    def ready(self):
        self.assert_operation()
        current = self.state()
        require(current is not None and current['phase'] in ('starting', 'recovering')
                and current['pending'] is None, 'No clean host Tor readiness check is pending.')
        self.guard(self.backend.firewall(), current)
        self.routes(current)
        self.healthy_selection(current)
        self.transition('active')

    def recover(self):
        self.assert_operation()
        current = self.state()
        require(current is not None, 'No host Tor guard exists for recovery.')
        self.guard(self.backend.firewall(), current)
        self.routes(current)
        self.healthy_selection(current)
        self.transition('recovering')
        self.purge()

    def block(self):
        self.assert_operation()
        if self.state() is None:
            self.guard(self.backend.firewall(), None)
            self.vacant()
            return
        self.transition('blocked')
        self.purge()

    def deactivate(self):
        self.assert_operation()
        current = self.state()
        if current is None:
            self.guard(self.backend.firewall(), None)
            self.vacant()
            if self.backend.path(RUNTIME).exists():
                self.discard_temporaries(None)
            return
        require(current['phase'] in ('blocked', 'cleanup') and current['pending'] is None,
                'Block Tor before removing its host guard.')
        raw = self.external([SYSTEMCTL, 'show', SERVICE, '--property=MainPID,ActiveState'])
        values = dict(line.split('=', 1) for line in raw.splitlines() if '=' in line)
        require(values.get('MainPID') == '0' and values.get('ActiveState') in ('inactive', 'failed'),
                'Stop the Tor service before removing its guard.')
        self.transition('cleanup')
        current = self.state()
        routes, rules = self.routes(current, complete=False)
        if rules:
            self.backend.command([IP, '-4', 'rule', 'del', *self.rule_args(current)])
        for row in reversed(routes):
            self.backend.command([IP, '-4', 'route', 'del', *self.route_args(row)])
        self.vacant()
        self.purge()
        self.discard_temporaries(current)
        self.batch(current, None)
        require(self.state() == current, 'Tor receipt changed during cleanup.')
        try:
            self.backend.path(STATE).unlink()
        except BaseException:
            self.batch(current, 'blocked', allow_absent=True)
            self.save({**current, 'phase': 'blocked'}, current)
            raise
        self.sync_directory()

    def status(self):
        current = self.state()
        if current is None:
            self.guard(self.backend.firewall(), None)
            self.vacant()
            record = self.backend.read_state()
            selected = record['selection'] if record is not None else None
            return dict(mode='off', phase='off', ready=False, interface=selected['uplink']['name'] if selected else None,
                        selection=selected, uid=None, tcp_port=None, dns_port=None, error=None)
        error = None
        try:
            self.guard(self.backend.firewall(), current)
            self.routes(current)
            self.healthy_selection(current)
            require(current['pending'] is None, 'An interrupted host Tor transition remains pending.')
        except (RuntimeError, OSError, ValueError, KeyError):
            error = 'The host Tor guard, policy route or selected uplink could not be verified.'
        return dict(mode='tor', phase='degraded' if error else current['phase'],
                    ready=not error and current['phase'] == 'active', interface=current['selection']['uplink']['name'],
                    selection=current['selection'], uid=current['uid'], tcp_port=19040, dns_port=19053, error=error)


def firewall_view(backend, items):
    """Read-only extension for HostShare.objects; never call objects/healthy here."""
    runtime = Runtime(backend=backend)
    state = runtime.state()
    runtime.guard(items, state)
    return [item for item in items if next(iter(item.values())).get(
        'name' if 'table' in item else 'table') != TABLE]


def require_share_change_allowed(backend):
    """Call under the shared lock before HostShare.enable/disable mutates anything."""
    runtime = Runtime(backend=backend)
    require(runtime.state() is None, 'Turn Tor off before changing or stopping host sharing.')
    runtime.guard(backend.firewall(), None)
    runtime.vacant()


def require_wifi_change_allowed(backend, adapter):
    """Read-only HostPlatform hook. Caller must serialize the whole mutation.

    HostPlatform.root is the sysfs root, unlike HostShare.root. Only when a Tor
    receipt exists do we load the fixed root-protected HostShare implementation.
    No discovery command, firewall command or process creation is performed.
    """
    sysroot = Path(backend.root)
    require(sysroot.name == 'sys', 'Unrecognized Wi-Fi system root.')
    root = sysroot.parent
    parent = root / RUNTIME.lstrip('/')
    if not parent.exists() and not parent.is_symlink():
        return
    module = load_share(root, getattr(backend, 'owner_uid', 0))
    host = module.HostShare(backend.host_profile, root=root,
                            owner_uid=getattr(backend, 'owner_uid', 0))
    current = Runtime(backend=host).state()
    if current is None:
        return
    require(isinstance(adapter.name, str) and type(adapter.index) is int and adapter.index > 0,
            'Unrecognized Wi-Fi adapter binding.')
    device = Path(adapter.device_path)
    require(device.is_absolute() and device.is_relative_to(root), 'Wi-Fi hardware escapes its system root.')
    relative = str(device.relative_to(root))
    for binding in [current['selection']['uplink'], *current['selection']['clients']]:
        require(adapter.name != binding['name'] and adapter.index != binding['ifindex']
                and relative != binding['device_path'],
                'Turn Tor off before changing a selected uplink or client adapter.')
