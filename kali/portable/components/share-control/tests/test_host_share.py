import contextlib
import copy
from dataclasses import dataclass
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
SPEC = importlib.util.spec_from_file_location('host_share_module', ROOT / 'portable/python/host_share.py')
share = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(share)

@dataclass(frozen=True)
class Profile:
    platform: str = 'kali-host'
    configured: bool = True
    protected_interfaces: tuple = ()
    ssh_service: str = 'ssh.service'
    identity: str = 'a' * 64

class FakeRunner:
    """All mutation and probe effects stay inside this fixture."""
    def __init__(self, root):
        self.root, self.calls = root, []
        self.nft_objects, self.routes, self.rules = [], [], []
        self.fail = None
        self.dns, self.nmstate, self.wifi_mode = '192.0.2.1\n', '100 (connected)', 'managed'
        self.interfaces = {}
        self.default = {}
        self.probes = []
        self.native_set_order = False
        for executable in (share.IP, share.NFT, share.NMCLI, share.IW):
            self.file(executable, 'fixture executable', 0o755)
        self.file('/proc/sys/kernel/random/boot_id', '00000000-0000-4000-8000-000000000001\n')
        (root / 'run').mkdir()
        self.add_interface('eth0', 2, '192.0.2.2', '192.0.2.1')
        self.add_interface('wifi0', 3, '198.51.100.2', '198.51.100.1', wireless=True)
        self.add_interface('ap0', 4, '10.42.0.1', None, wireless=True)
        self.add_interface('other0', 5, '203.0.113.2', '203.0.113.1')

    def file(self, path, text, mode=0o644):
        target = self.root / path.lstrip('/')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text); target.chmod(mode)
        return target

    def add_interface(self, name, index, address, gateway, wireless=False):
        device = self.root / 'sys/devices' / name
        device.mkdir(parents=True)
        net = self.root / 'sys/class/net' / name
        net.mkdir(parents=True)
        (net / 'device').symlink_to(device, target_is_directory=True)
        if wireless: (net / 'phy80211').mkdir()
        self.file('/sys/class/net/' + name + '/ifindex', str(index))
        self.file('/proc/sys/net/ipv4/conf/' + name + '/forwarding', '0\n')
        self.interfaces[name] = dict(ifname=name, ifindex=index, link_type='ether', flags=['UP'],
            operstate='UP', address='02:00:00:00:00:' + str(index).zfill(2),
            addr_info=[dict(family='inet', local=address, prefixlen=24, scope='global', valid_life_time=3600)])
        self.default[name] = [] if gateway is None else [dict(dst='default', gateway=gateway, dev=name)]

    def probe(self, selection):
        self.probes.append(copy.deepcopy(selection))
        if self.fail == 'probe' or self.fail == 'second-probe' and len(self.probes) > 1:
            raise share.Error('fixture DNS health failed')

    def __call__(self, args, input_text=None):
        self.calls.append((args, input_text))
        result = None
        if args[0] == share.NFT:
            if args == [share.NFT, '-j', '-n', '-s', 'list', 'ruleset']:
                result = {'nftables': copy.deepcopy(self.nft_objects)}
                if self.native_set_order:
                    for item in result['nftables']:
                        for expression in item.get('rule', {}).get('expr', []):
                            right = expression.get('match', {}).get('right')
                            if isinstance(right, dict) and set(right) == {'set'}:
                                right['set'] = sorted(right['set'])
            else:
                commands = json.loads(input_text)['nftables']
                if '--check' not in args:
                    if self.fail == 'nft-once':
                        self.fail = None
                        return subprocess.CompletedProcess(args, 1, '', 'fixture failure')
                    for command in commands:
                        if 'add' in command: self.nft_objects.append(command['add'])
                        elif 'delete' in command:
                            if self.fail == 'delete': raise share.Error('fixture nft delete failure')
                            self.nft_objects = [item for item in self.nft_objects
                                if next(iter(item.values())).get('table', next(iter(item.values())).get('name')) != share.NFT_TABLE]
                        else: raise AssertionError(command)
                result = ''
        elif args[0] == share.IP:
            if args[1:3] == ['-j', '-N']:
                query = args[3:]
                if query[:3] == ['-d', 'address', 'show']:
                    result = [self.interfaces[query[-1]]] if query[-1] in self.interfaces else []
                elif query == ['-4', 'route', 'show', 'table', 'main', 'exact', '0.0.0.0/0']:
                    result = [copy.deepcopy(row) for rows in self.default.values() for row in rows]
                elif query == ['-4', 'route', 'show', 'table', 'all']: result = copy.deepcopy(self.routes)
                elif query == ['-4', 'rule', 'show']: result = copy.deepcopy(self.rules)
                elif query[:3] == ['-4', 'route', 'get']:
                    default = next(row for row in self.routes if row['dst'] == 'default' and 'gateway' in row)
                    result = [dict(dev=default['dev'], table=share.TABLE)]
                else: raise AssertionError(args)
            elif args[1:3] == ['-4', 'route']:
                if args[3] == 'add' and self.fail == 'route-once':
                    self.fail = None
                    return subprocess.CompletedProcess(args, 1, '', '')
                words = args[4:]
                row = {}
                if words[0] == 'unreachable': row['type'], words = words[0], words[1:]
                row['dst'], words = words[0], words[1:]
                translation = dict(via='gateway', dev='dev', src='prefsrc', scope='scope', metric='metric', proto='protocol', table='table')
                for index in range(0, len(words), 2):
                    key, value = translation[words[index]], words[index+1]
                    row[key] = int(value) if key in ('table', 'metric', 'protocol') else value
                if args[3] == 'add': self.routes.append(row)
                elif args[3] == 'del': self.routes.remove(row)
                else: raise AssertionError(args)
                result = ''
            elif args[1:3] == ['-4', 'rule']:
                row = dict(priority=share.PRIORITY, src='all', fwmark=hex(share.MARK), fwmask=hex(share.MARK),
                           table=share.TABLE, protocol=share.PROTOCOL)
                if args[3] == 'add': self.rules.append(row)
                else: self.rules.remove(row)
                result = ''
            else: raise AssertionError(args)
        elif args[0] == share.NMCLI: result = self.dns if 'IP4.DNS' in args else self.nmstate
        elif args[0] == share.IW: result = 'Interface ' + args[2] + '\n\ttype ' + self.wifi_mode + '\n'
        else: raise AssertionError(args)
        return subprocess.CompletedProcess(args, 0, result if isinstance(result, str) else json.dumps(result), '')

    def mutations(self):
        return [(args, body) for args, body in self.calls if
                args[0] == share.NFT and '-f' in args and '--check' not in args or
                args[0] == share.IP and args[1:3] != ['-j', '-N']]

class HostShareTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.system = FakeRunner(self.root)
        self.backend = share.HostShare(Profile(), root=self.root, runner=self.system,
                                       owner_uid=os.geteuid(), probe=self.system.probe)
        self.patcher = patch.object(share.os, 'geteuid', return_value=0)
        self.patcher.start(); self.addCleanup(self.patcher.stop)

    def test_host_only_never_infers_clients_or_enables_forwarding(self):
        before = {name: self.backend.forwarding(name) for name in self.system.interfaces}
        value, changed = self.backend.enable('lan', 'eth0')
        self.assertTrue(changed and value['active'])
        self.assertEqual(value['selection']['clients'], [])
        self.assertEqual(self.backend.read_state()['forwarding'], {})
        self.assertEqual({name: self.backend.forwarding(name) for name in self.system.interfaces}, before)
        self.assertFalse(self.backend.disable()[0]['active'])
        self.assertEqual(self.system.nft_objects, [])
        self.assertEqual(self.system.routes, [])
        self.assertEqual(self.system.rules, [])

    def test_explicit_client_has_only_selected_forwarding_and_restores_originals(self):
        self.backend.forwarding('eth0', '1')
        state, _ = self.backend.enable('lan', 'eth0', ['ap0'])
        self.assertEqual([item['name'] for item in state['selection']['clients']], ['ap0'])
        self.assertEqual(self.backend.forwarding('ap0'), '1')
        self.assertEqual(self.backend.forwarding('other0'), '0')
        self.backend.disable()
        self.assertEqual(self.backend.forwarding('eth0'), '1')
        self.assertEqual(self.backend.forwarding('ap0'), '0')

    def test_idempotent_same_selection_but_changed_selection_requires_off(self):
        self.backend.enable('lan', 'eth0')
        count = len(self.system.mutations())
        self.assertFalse(self.backend.enable('lan', 'eth0')[1])
        with self.assertRaisesRegex(share.Error, '--off'): self.backend.enable('lan', 'eth0', ['ap0'])
        self.assertEqual(len(self.system.mutations()), count)

    def test_native_dhcp_set_order_allows_activation_status_and_owned_cleanup(self):
        self.system.native_set_order = True
        value, changed = self.backend.enable('lan', 'eth0', ['ap0'])
        self.assertTrue(changed and value['active'])
        self.assertTrue(self.backend.status()['active'])
        self.assertFalse(self.backend.disable()[0]['active'])
        self.assertEqual(self.system.nft_objects, [])
        self.assertEqual(self.system.routes, [])
        self.assertEqual(self.system.rules, [])
        self.assertEqual(self.backend.forwarding('ap0'), '0')

    def test_changed_dhcp_set_members_are_never_adopted_or_cleaned(self):
        self.system.native_set_order = True
        self.backend.enable('lan', 'eth0', ['ap0'])
        original = copy.deepcopy(self.system.nft_objects)
        for mutation in ('replace', 'remove', 'add', 'duplicate'):
            with self.subTest(mutation=mutation):
                self.system.nft_objects = copy.deepcopy(original)
                values = next(expression['match']['right']['set']
                              for item in self.system.nft_objects
                              for expression in item.get('rule', {}).get('expr', [])
                              if isinstance(expression.get('match', {}).get('right'), dict)
                              and set(expression['match']['right']) == {'set'})
                if mutation == 'replace': values[0] = '203.0.113.77'
                if mutation == 'remove': values.pop()
                if mutation == 'add': values.append('203.0.113.77')
                if mutation == 'duplicate': values.append(values[0])
                before = len(self.system.mutations())
                with self.assertRaisesRegex(share.Error, 'nft table changed'):
                    self.backend.disable()
                self.assertEqual(len(self.system.mutations()), before)
        self.system.nft_objects = original
        self.backend.disable()

    def test_set_normalization_preserves_expression_order_and_input(self):
        expression = share.match(share.payload('ip', 'daddr'),
                                 {'set': ['255.255.255.255', '10.79.0.1']})
        rule = {'rule': {'chain': 'test', 'expr': [expression, {'return': None}]}}
        chain = {'chain': {'name': 'test'}}
        original = copy.deepcopy([chain, rule])
        canonical = self.backend.canonical_nft(original)
        self.assertEqual(original[1]['rule']['expr'][0]['match']['right']['set'],
                         ['255.255.255.255', '10.79.0.1'])
        reordered = copy.deepcopy(original)
        reordered[1]['rule']['expr'].reverse()
        self.assertNotEqual(canonical, self.backend.canonical_nft(reordered))

    def test_root_and_configured_profile_required_before_changes(self):
        with patch.object(share.os, 'geteuid', return_value=1000), self.assertRaisesRegex(share.Error, 'Root'):
            self.backend.enable('lan', 'eth0')
        self.backend.profile = Profile(configured=False)
        with self.assertRaisesRegex(share.Error, 'explicit'): self.backend.enable('lan', 'eth0')
        self.assertEqual(self.system.mutations(), [])

    def test_explicit_selection_and_type_and_managed_wifi_required(self):
        for mode, name, sources in [('lan', None, []), ('lan', 'wifi0', []), ('wifi', 'eth0', []),
                                    ('lan', 'eth0', ['eth0']), ('lan', 'eth0', ['ap0', 'ap0'])]:
            with self.subTest(mode=mode, name=name), self.assertRaises(share.Error):
                self.backend.enable(mode, name, sources)
        self.system.wifi_mode = 'AP'
        with self.assertRaisesRegex(share.Error, 'managed'): self.backend.enable('wifi', 'wifi0')
        self.assertEqual(self.system.mutations(), [])

    def test_valid_wifi_can_be_used_with_explicit_dns(self):
        self.system.dns = '198.51.100.1\n'
        value, _ = self.backend.enable('wifi', 'wifi0')
        self.assertEqual(value['selection']['uplink']['name'], 'wifi0')

    def test_protected_interface_and_same_hardware_alias_refused(self):
        self.backend.profile = Profile(protected_interfaces=('eth0',))
        with self.assertRaisesRegex(share.Error, 'protected'): self.backend.enable('lan', 'eth0')
        alias = self.root / 'sys/class/net/other0/device'
        alias.unlink(); alias.symlink_to(self.root / 'sys/devices/eth0')
        with self.assertRaisesRegex(share.Error, 'protected'): self.backend.enable('lan', 'other0')
        self.assertEqual(self.system.mutations(), [])

    def test_invalid_link_gateway_dns_or_overlap_has_no_effect(self):
        for change in ('bridge', 'down', 'overlap', 'gateway', 'loopback-dns', 'disconnected'):
            before = copy.deepcopy(self.system.interfaces)
            old_gateway, old_dns, old_nm = copy.deepcopy(self.system.default), self.system.dns, self.system.nmstate
            if change == 'bridge': self.system.interfaces['ap0']['master'] = 'br0'
            if change == 'down': self.system.interfaces['ap0']['flags'] = []
            if change == 'overlap': self.system.interfaces['ap0']['addr_info'][0]['local'] = '192.0.2.3'
            if change == 'gateway': self.system.default['eth0'][0]['gateway'] = '10.0.0.1'
            if change == 'loopback-dns': self.system.dns = '127.0.0.53'
            if change == 'disconnected': self.system.nmstate = '30 (disconnected)'
            with self.subTest(change=change), self.assertRaises(share.Error): self.backend.enable('lan', 'eth0', ['ap0'])
            self.system.interfaces, self.system.default, self.system.dns, self.system.nmstate = before, old_gateway, old_dns, old_nm
        self.assertEqual(self.system.mutations(), [])

    def test_main_default_query_preserves_native_interface_identity(self):
        # Native iproute2 drops dev when the query itself filters by dev. The
        # exact main-table query must retain dev and ignore other uplinks.
        for table in (None, 'main', 254, '254'):
            with self.subTest(table=table):
                row = self.system.default['eth0'][0]
                row.pop('table', None)
                if table is not None: row['table'] = table
                selected = self.backend.select('lan', 'eth0', [])
                self.assertEqual(selected['gateway'], '192.0.2.1')
        queries = [args for args, _ in self.system.calls if args[:6] ==
                   [share.IP, '-j', '-N', '-4', 'route', 'show']]
        self.assertTrue(queries)
        self.assertTrue(all(args[6:] == ['table', 'main', 'exact', '0.0.0.0/0'] for args in queries))
        self.assertEqual(self.system.mutations(), [])

    def test_non_main_ambiguous_or_unidentified_defaults_are_refused(self):
        original = copy.deepcopy(self.system.default)
        for case in ('foreign-table', 'unknown-table', 'duplicate', 'missing-dev', 'missing-gateway',
                     'wrong-destination', 'wrong-type'):
            with self.subTest(case=case):
                self.system.default = copy.deepcopy(original)
                row = self.system.default['eth0'][0]
                if case == 'foreign-table': row['table'] = 100
                if case == 'unknown-table': row['table'] = 'vpn'
                if case == 'duplicate': self.system.default['eth0'].append(copy.deepcopy(row))
                if case == 'missing-dev': row.pop('dev')
                if case == 'missing-gateway': row.pop('gateway')
                if case == 'wrong-destination': row['dst'] = '192.0.2.0/24'
                if case == 'wrong-type': row['type'] = 'blackhole'
                with self.assertRaises(share.Error): self.backend.enable('lan', 'eth0')
                self.assertEqual(self.system.mutations(), [])

    def test_ipv6_is_blocked_for_host_external_and_client_traffic(self):
        self.backend.enable('lan', 'eth0', ['ap0'])
        rules = [item['rule'] for item in self.system.nft_objects if 'rule' in item]
        self.assertTrue(any(rule['chain'] == 'output_guard' and share.match(share.meta('nfproto'), 'ipv6') in rule['expr']
                            and {'drop': None} in rule['expr'] for rule in rules))
        self.assertTrue(any(rule['chain'] == 'client_guard' and share.match(share.meta('nfproto'), 'ipv6') in rule['expr']
                            and {'drop': None} in rule['expr'] for rule in rules))
        self.assertFalse(any('snat' in json.dumps(rule) and 'ip6' in json.dumps(rule) for rule in rules))

    def test_dns_tcp_udp_and_loopback_resolver_exemption(self):
        self.backend.enable('lan', 'eth0', ['ap0'])
        rules = [item['rule'] for item in self.system.nft_objects if 'rule' in item]
        host = [rule for rule in rules if rule['chain'] == 'dns_out']
        self.assertIn({'return': None}, host[0]['expr'])
        self.assertIn('127.0.0.0', json.dumps(host[0]))
        self.assertEqual(len(host), 3)
        for rule in host[1:]: self.assertIn({'dnat': {'addr': '192.0.2.1', 'family': 'ip'}}, rule['expr'])
        self.assertEqual(len([rule for rule in rules if rule['chain'] == 'dns_in']), 2)

    def test_collisions_are_not_adopted_or_removed(self):
        for kind in ('table', 'route', 'rule', 'mark'):
            if kind == 'table': self.system.nft_objects = [{'table': {'family': 'inet', 'name': share.NFT_TABLE}}]
            if kind == 'route': self.system.routes = [dict(dst='default', dev='other0', table=share.TABLE)]
            if kind == 'rule': self.system.rules = [dict(priority=share.PRIORITY, src='all', table=123)]
            if kind == 'mark': self.system.nft_objects = [{'rule': {'table': 'foreign', 'expr': [{'mangle': {'key': share.meta('mark'), 'value': 1}}]}}]
            with self.subTest(kind=kind), self.assertRaises(share.Error): self.backend.enable('lan', 'eth0')
            with self.assertRaises(share.Error): self.backend.disable()
            self.system.nft_objects, self.system.routes, self.system.rules = [], [], []
        self.assertEqual(self.system.mutations(), [])

    def test_foreign_firewall_is_preserved_and_can_restrict_sharing(self):
        foreign = [{'table': {'family': 'inet', 'name': 'other'}}, {'chain': {'family': 'inet', 'table': 'other',
                    'name': 'input', 'type': 'filter', 'hook': 'input', 'prio': 0, 'policy': 'drop'}}]
        self.system.nft_objects = copy.deepcopy(foreign)
        self.backend.enable('lan', 'eth0')
        self.backend.disable()
        self.assertEqual(self.system.nft_objects, foreign)

    def test_dns_health_failure_before_change_and_after_change_rolls_back(self):
        self.system.fail = 'probe'
        with self.assertRaisesRegex(share.Error, 'DNS health'): self.backend.enable('lan', 'eth0')
        self.assertEqual(self.system.mutations(), [])
        self.system.probes, self.system.fail = [], 'second-probe'
        with self.assertRaisesRegex(share.Error, 'rolled back'): self.backend.enable('lan', 'eth0', ['ap0'])
        self.assertFalse(self.backend.status()['active'])
        self.assertEqual(self.backend.forwarding('ap0'), '0')

    def test_partial_kernel_failure_rolls_back_only_own_objects(self):
        for failure in ('nft-once', 'route-once'):
            self.system.fail = failure
            with self.subTest(failure=failure), self.assertRaisesRegex(share.Error, 'rolled back'):
                self.backend.enable('lan', 'eth0')
            self.assertFalse(self.backend.status()['active'])

    def test_failed_cleanup_retains_receipt_and_guard(self):
        self.backend.enable('lan', 'eth0', ['ap0'])
        self.system.fail = 'delete'
        with self.assertRaisesRegex(share.Error, 'delete failure'): self.backend.disable()
        self.assertEqual(self.backend.read_state()['phase'], 'cleanup')
        self.assertTrue(self.system.nft_objects)
        self.assertEqual(self.backend.forwarding('ap0'), '0')
        self.system.fail = None
        self.assertFalse(self.backend.disable()[0]['active'])

    def test_nft_tamper_and_reordered_rules_prevent_cleanup(self):
        self.backend.enable('lan', 'eth0')
        before = len(self.system.mutations())
        rules = [index for index, item in enumerate(self.system.nft_objects) if item.get('rule', {}).get('chain') == 'output_guard']
        self.system.nft_objects[rules[0]], self.system.nft_objects[rules[1]] = self.system.nft_objects[rules[1]], self.system.nft_objects[rules[0]]
        with self.assertRaisesRegex(share.Error, 'nft table changed'): self.backend.disable()
        self.assertEqual(len(self.system.mutations()), before)

    def test_route_tamper_or_hardware_replacement_prevents_cleanup(self):
        self.backend.enable('lan', 'eth0')
        before = len(self.system.mutations())
        self.system.routes[0]['dev'] = 'other0'
        with self.assertRaisesRegex(share.Error, 'routing table changed'): self.backend.disable()
        self.system.routes[0]['dev'] = 'eth0'
        self.system.interfaces['eth0']['address'] = '02:00:00:00:00:99'
        with self.assertRaisesRegex(share.Error, 'identity changed'): self.backend.disable()
        self.assertEqual(len(self.system.mutations()), before)

    def test_runtime_permissions_profile_and_boot_are_bound(self):
        self.backend.enable('lan', 'eth0')
        state = self.root / share.RUNTIME.lstrip('/') / 'state.json'
        self.assertEqual(state.stat().st_mode & 0o777, 0o600)
        self.assertEqual(state.parent.stat().st_mode & 0o777, 0o700)
        self.backend.profile = Profile(identity='b' * 64)
        with self.assertRaisesRegex(share.Error, 'identity'): self.backend.disable()
        self.backend.profile = Profile()
        self.system.file('/proc/sys/kernel/random/boot_id', '00000000-0000-4000-8000-000000000002')
        with self.assertRaisesRegex(share.Error, 'identity'): self.backend.disable()

    def test_lock_serialization(self):
        with self.backend.lock(), self.assertRaisesRegex(share.Error, 'Another host sharing'):
            with self.backend.lock(): pass

    def test_help_never_loads_profile_and_noninteractive_ambiguity_never_mutates(self):
        with patch.object(share, 'load_profile', side_effect=AssertionError('must not load')):
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(SystemExit) as result: share.main(['--help'])
            self.assertEqual(result.exception.code, 0)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(share.main(['--lan','--from','host'],backend=self.backend,
                                           stdin=io.StringIO(),stdout=io.StringIO()),1)
            self.assertEqual(self.system.mutations(),[])

    def test_interactive_uplink_and_sources_use_shared_bounded_choices(self):
        class Terminal(io.StringIO):
            def isatty(self):return True
        terminal=Terminal('eth0\n2\n');output=Terminal()
        uplink=self.backend.select_uplink('lan',stdin=terminal,stdout=output)
        self.assertEqual(uplink,'eth0')
        sources=self.backend.source_selection(uplink,stdin=terminal,stdout=output)
        self.assertEqual(sources,['ap0'])
        self.assertIn('Select an external interface:',output.getvalue())
        self.assertIn('this Kali host only',output.getvalue())
        self.assertEqual(self.system.mutations(),[])

    def test_noninteractive_source_choice_requires_explicit_client_or_host(self):
        with self.assertRaisesRegex(share.Error,'--from'):
            self.backend.source_selection('eth0',stdin=io.StringIO(),stdout=io.StringIO())
        self.assertEqual(self.backend.source_selection('eth0','host'),[])
        self.assertEqual(self.backend.source_selection('eth0','ap0'),['ap0'])
        with self.assertRaises(share.Error):self.backend.source_selection('eth0','host,ap0')
        with self.assertRaises(share.Error):self.backend.source_selection('eth0','eth0')
        self.assertEqual(self.system.mutations(),[])

    def test_cli_interface_alias_and_explicit_host_selection(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(share.main(['--lan','--interface','eth0','--from','host'],backend=self.backend),0)
        self.assertEqual(self.backend.read_state()['selection']['clients'],[])
        self.backend.disable()

    def test_cli_status_requires_sudo_before_backend_reads(self):
        for args in ([], ['--status']):
            errors = io.StringIO()
            with patch.object(share.os, 'geteuid', return_value=1000), \
                    patch.object(self.backend, 'status', side_effect=AssertionError('must not read')), \
                    contextlib.redirect_stderr(errors):
                self.assertEqual(share.main(args, backend=self.backend), 77)
            self.assertIn('sudo auto share', errors.getvalue())
            self.assertIn('firewall', errors.getvalue())
        self.assertEqual(self.system.mutations(), [])

    def test_status_explains_host_only_and_ipv6_limits(self):
        self.backend.enable('lan', 'eth0')
        output = io.StringIO()
        with contextlib.redirect_stdout(output): share.print_status(self.backend.status())
        self.assertIn('host traffic only', output.getvalue())
        self.assertIn('IPv6: blocked', output.getvalue())
        self.assertIn('reachability is not guaranteed', output.getvalue())

if __name__ == '__main__': unittest.main()
