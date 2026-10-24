"""Host Tor tests: fixture files and captured commands only, never real networking."""
import copy
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fixtures = load('host_share_fixture_for_tor', ROOT / 'portable/components/share-control/tests/test_host_share.py')
share = fixtures.share
tor = load('host_egress_under_test', ROOT / 'portable/python/host_egress.py')
UID = 60001


class Runner(fixtures.FakeRunner):
    def __init__(self, root):
        super().__init__(root)
        self.service_active = False
        self.names = False
        self.native_uid_rules = False
        self.native_names = {row['ifindex']: row['ifname'] for row in self.interfaces.values()}
        self.sockets = '0 0 192.0.2.2:22 192.0.2.50:55000\n'
        for executable in (tor.SS, tor.SYSTEMCTL, tor.CONNTRACK):
            self.file(executable, 'fixture executable', 0o755)
        link = root / 'proc/self/ns/net'
        link.parent.mkdir(parents=True)
        link.symlink_to('net:[4026531992]')
        self.file('/usr/local/libexec/automations-support/host_egress.py',
                  (ROOT / 'portable/python/host_egress.py').read_text())
        self.file(tor.SHARE, (ROOT / 'portable/python/host_share.py').read_text(), 0o755)

    def __call__(self, args, input_text=None):
        if args[0] in (tor.SS, tor.SYSTEMCTL, tor.CONNTRACK):
            self.calls.append((args, input_text))
            if args[0] == tor.SS:
                result = self.sockets
            elif args[0] == tor.SYSTEMCTL:
                result = 'MainPID=45\nActiveState=active\n' if self.service_active else 'MainPID=0\nActiveState=inactive\n'
            else:
                result = ''
            return subprocess.CompletedProcess(args, 0, result, '')
        if args[0] == tor.NFT:
            self.calls.append((args, input_text))
            if 'list' in args:
                data = copy.deepcopy(self.nft_objects)
                if self.names:
                    for item in data:
                        for expression in item.get('rule', {}).get('expr', []):
                            check = expression.get('match', {})
                            if check.get('left') in ({'meta': {'key': 'iif'}}, {'meta': {'key': 'oif'}}):
                                check['right'] = self.native_names.get(check['right'], check['right'])
                result = json.dumps({'nftables': data})
            else:
                if '--check' not in args:
                    if self.fail == 'nft-once':
                        self.fail = None
                        return subprocess.CompletedProcess(args, 1, '', '')
                    for command in json.loads(input_text)['nftables']:
                        if 'add' in command:
                            self.nft_objects.append(command['add'])
                        elif 'delete' in command:
                            name = command['delete']['table']['name']
                            if self.fail == 'delete':
                                raise share.Error('fixture delete failure')
                            self.nft_objects = [item for item in self.nft_objects if
                                next(iter(item.values())).get('table', next(iter(item.values())).get('name')) != name]
                        else:
                            raise AssertionError(command)
                result = ''
            return subprocess.CompletedProcess(args, 0, result, '')
        if args[:3] == [tor.IP, '-4', 'rule'] and 'uidrange' in args:
            self.calls.append((args, input_text))
            row = dict(priority=tor.PRIORITY, src='all', uidrange={'start': UID, 'end': UID},
                       table=tor.ROUTE_TABLE, protocol=tor.PROTOCOL)
            if args[3] == 'add':
                self.rules.append(row)
            elif args[3] == 'del':
                self.rules.remove(row)
            else:
                raise AssertionError(args)
            return subprocess.CompletedProcess(args, 0, '', '')
        if args == [tor.IP, '-j', '-N', '-4', 'rule', 'show'] and self.native_uid_rules:
            result = super().__call__(args, input_text)
            rows = json.loads(result.stdout)
            for row in rows:
                if 'uidrange' in row:
                    span = row.pop('uidrange')
                    row.update(uid_start=span['start'], uid_end=span['end'],
                               table=str(row['table']), protocol=str(row['protocol']))
            return subprocess.CompletedProcess(args, 0, json.dumps(rows), '')
        return super().__call__(args, input_text)


def evaluate(state, chain, **values):
    """Evaluate the emitted expression subset against concrete packet cases."""
    packet = dict(nfproto='ipv4', l4proto='tcp', skuid=1000, iif=2, oif=2,
                  iifname='eth0', oifname='eth0', saddr='192.0.2.2', daddr='203.0.113.8',
                  sport=45000, dport=443, ct_state='new', ct_direction='original', ct_mark=0,
                  ct_status=[], flags=2)
    packet.update(values)

    def read(value):
        if not isinstance(value, dict):
            return value
        if 'meta' in value:
            return packet[value['meta']['key']]
        if 'payload' in value:
            field = value['payload']
            protocol = field['protocol']
            if protocol in ('tcp', 'udp') and protocol != packet['l4proto']:
                return None
            if protocol in ('ip', 'ip6') and (protocol == 'ip') != (packet['nfproto'] == 'ipv4'):
                return None
            return packet[field['field']]
        if 'ct' in value:
            return packet['ct_' + value['ct']['key']]
        if 'prefix' in value:
            prefix = value['prefix']
            return ipaddress.ip_network(str(prefix['addr']) + '/' + str(prefix['len']))
        if 'set' in value:
            return value['set']
        for operator in ('&', '|'):
            if operator in value:
                left, right = map(read, value[operator])
                return left & right if operator == '&' else left | right
        raise AssertionError(value)

    def matches(expression):
        left, right = read(expression['left']), read(expression['right'])
        if left is None:
            return False
        if isinstance(right, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            equal = ipaddress.ip_address(left) in right
        elif isinstance(right, list):
            equal = left in right
        elif expression['op'] == 'in':
            equal = right in left
        else:
            equal = left == right
        return not equal if expression['op'] == '!=' else equal

    objects = tor.nft_objects(state)
    for item in objects:
        rule = item.get('rule', {})
        if rule.get('chain') != chain:
            continue
        expressions = rule['expr']
        if not all(matches(expression['match']) for expression in expressions if 'match' in expression):
            continue
        for expression in expressions:
            for verdict in ('accept', 'drop', 'return', 'dnat', 'redirect'):
                if verdict in expression:
                    return verdict
    return next(item['chain']['policy'] for item in objects if item.get('chain', {}).get('name') == chain)


class HostEgressTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.runner = Runner(self.root)
        self.backend = share.HostShare(fixtures.Profile(), root=self.root, runner=self.runner,
                                       owner_uid=os.geteuid(), probe=self.runner.probe)
        self.runtime = self.make_runtime()

    def make_runtime(self, **kwargs):
        return tor.Runtime(backend=self.backend, uplink=kwargs.pop('uplink', 'eth0'),
                           mode=kwargs.pop('mode', 'lan'),
                           account_lookup=lambda name: SimpleNamespace(pw_uid=UID), **kwargs)

    def activate(self, ready=True):
        with self.runtime.operation('tor'):
            self.runtime.activate(UID, 19040, 19053)
            if ready:
                self.runtime.ready()
        return self.runtime.state()

    def enable_share(self):
        with patch.object(share.os, 'geteuid', return_value=0):
            self.backend.enable('lan', 'eth0', ['ap0'])
        return copy.deepcopy(self.backend.read_state())

    def test_first_host_only_activation_and_full_cleanup_preserve_native_state(self):
        foreign = [{'table': {'family': 'inet', 'name': 'foreign', 'comment': 'untouched'}}]
        self.runner.nft_objects = copy.deepcopy(foreign)
        before = {name: self.backend.forwarding(name) for name in self.runner.interfaces}
        state = self.activate()
        self.assertTrue(self.runtime.status()['ready'])
        self.assertIsNone(state['share_run_id'])
        self.assertEqual(state['selection']['clients'], [])
        self.assertIsNone(self.backend.read_state())
        self.assertEqual(len(self.runner.routes), 3)
        self.assertEqual(self.runner.rules[0]['uidrange'], {'start': UID, 'end': UID})
        self.assertEqual(self.backend.path(tor.STATE).stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.backend.path(tor.RUNTIME).stat().st_mode & 0o777, 0o700)
        with self.runtime.operation('tor'):
            self.runtime.block()
            self.runtime.deactivate()
        self.assertEqual(self.runtime.status()['mode'], 'off')
        self.assertEqual(self.runner.nft_objects, foreign)
        self.assertEqual(self.runner.routes, [])
        self.assertEqual(self.runner.rules, [])
        self.assertEqual(before, {name: self.backend.forwarding(name) for name in self.runner.interfaces})
        self.assertFalse(any(args[0] == share.NMCLI and 'modify' in args for args, _ in self.runner.calls))

    def test_active_share_selection_is_adopted_without_changing_share_receipt(self):
        sharing = self.enable_share()
        self.runtime = self.make_runtime(uplink=None, mode=None)
        state = self.activate()
        self.assertEqual(state['share_run_id'], sharing['run_id'])
        self.assertEqual(state['selection'], sharing['selection'])
        routes = [row for row in self.runner.routes if row.get('table') == tor.ROUTE_TABLE]
        # UID routing applies to Tor's replies too: the longest-prefix client
        # route must win over the selected uplink default for both DNS and TCP.
        destination = ipaddress.IPv4Address('10.42.0.88')
        candidates = [(ipaddress.IPv4Network(row['dst']).prefixlen, row) for row in routes
                      if row['dst'] != 'default' and destination in ipaddress.IPv4Network(row['dst'])]
        self.assertEqual(max(candidates, key=lambda item: item[0])[1], dict(
            dst='10.42.0.0/24', dev='ap0', prefsrc='10.42.0.1', scope='link',
            table=tor.ROUTE_TABLE, protocol=tor.PROTOCOL))
        self.assertTrue(self.backend.healthy(sharing))
        self.assertEqual(self.backend.read_state(), sharing)
        with self.runtime.operation('tor'):
            self.runtime.block()
            self.runtime.deactivate()
        self.assertTrue(self.backend.healthy(sharing))
        self.assertEqual(self.backend.read_state(), sharing)

    def test_missing_explicit_host_selection_and_conflicting_share_are_refused_before_mutation(self):
        self.runtime = self.make_runtime(uplink=None, mode=None)
        with self.assertRaisesRegex(tor.Error, 'explicit'), self.runtime.operation('tor'):
            self.runtime.activate(UID, 19040, 19053)
        self.assertEqual(self.runner.mutations(), [])
        self.enable_share()
        self.runtime = self.make_runtime(uplink='wifi0', mode='wifi')
        before = len(self.runner.mutations())
        with self.assertRaisesRegex(tor.Error, 'conflicts'), self.runtime.operation('tor'):
            self.runtime.activate(UID, 19040, 19053)
        self.assertEqual(len(self.runner.mutations()), before)
        self.assertIsNone(self.runtime.state())

    def test_invalid_uid_or_listener_ports_are_refused_without_firewall_changes(self):
        for uid, tcp, dns in ((0, 19040, 19053), (UID + 1, 19040, 19053), (UID, 9040, 19053)):
            with self.subTest(uid=uid, tcp=tcp), self.assertRaises(tor.Error), self.runtime.operation('tor'):
                self.runtime.activate(uid, tcp, dns)
        self.assertEqual(self.runner.mutations(), [])

    def test_share_lock_contention_is_typed_busy_before_any_operation(self):
        with self.backend.lock(), self.assertRaises(tor.Busy):
            with self.runtime.operation('tor'):
                self.fail('must not enter')
        self.assertEqual(self.runner.mutations(), [])

    def test_recovery_and_operation_failure_keep_blocking_ordinary_and_old_flows(self):
        self.activate()
        with self.runtime.operation('tor'):
            self.runtime.recover()
        state = self.runtime.state()
        self.assertEqual(state['phase'], 'recovering')
        self.assertEqual(evaluate(state, 'output_guard', oif=1, oifname='lo', daddr='127.0.0.1', dport=19040,
                                  ct_state='established'), 'drop')
        self.assertEqual(evaluate(state, 'output_guard', oif=1, oifname='lo', daddr='127.0.0.1', dport=19050,
                                  skuid=0), 'accept')
        with self.assertRaisesRegex(tor.Error, 'simulated'), self.runtime.operation('tor'):
            self.runtime.ready()
            raise tor.Error('simulated service failure')
        state = self.runtime.state()
        self.assertEqual(state['phase'], 'blocked')
        self.assertEqual(evaluate(state, 'output_guard', skuid=UID), 'drop')
        self.assertEqual(evaluate(state, 'output_guard', ct_state='established'), 'drop')

    def test_partial_route_failure_retains_owned_blocked_guard_and_can_clean_up(self):
        self.runner.fail = 'route-once'
        with self.assertRaises(tor.Error), self.runtime.operation('tor'):
            self.runtime.activate(UID, 19040, 19053)
        self.assertEqual(self.runtime.state()['phase'], 'blocked')
        self.runtime.guard(self.runner.nft_objects, self.runtime.state())
        with self.runtime.operation('tor'):
            self.runtime.deactivate()
        self.assertIsNone(self.runtime.state())

    def test_live_service_prevents_removing_blocked_guard(self):
        self.activate()
        self.runner.service_active = True
        with self.assertRaisesRegex(tor.Error, 'Stop'), self.runtime.operation('tor'):
            self.runtime.block()
            self.runtime.deactivate()
        self.assertEqual(self.runtime.state()['phase'], 'blocked')
        self.assertTrue(self.runner.nft_objects)

    def test_interrupted_atomic_swap_accepts_only_either_owned_definition(self):
        self.activate(ready=False)
        current = self.runtime.state()
        intent = {**current, 'pending': 'active'}
        self.runtime.save(intent, current)
        self.runner.nft_objects = tor.nft_objects({**intent, 'phase': 'active'})
        self.assertEqual(self.runtime.status()['phase'], 'degraded')
        with self.runtime.operation('tor'):
            self.runtime.block()
        self.assertEqual(self.runtime.state()['phase'], 'blocked')

    def test_state_publish_failure_after_swap_closes_guard(self):
        self.activate(ready=False)
        original = self.runtime.save
        failed = False

        def fail_active(value, expected):
            nonlocal failed
            if value['phase'] == 'active' and value['pending'] is None and not failed:
                failed = True
                raise tor.Error('publication failure')
            return original(value, expected)

        with patch.object(self.runtime, 'save', side_effect=fail_active):
            with self.assertRaisesRegex(tor.Error, 'publication'), self.runtime.operation('tor'):
                self.runtime.ready()
        self.assertTrue(failed)
        self.assertEqual(self.runtime.state()['phase'], 'blocked')

    def test_orphan_foreign_reserved_objects_and_tampering_are_never_overwritten(self):
        self.runner.nft_objects = [{'table': {'family': 'inet', 'name': tor.TABLE, 'comment': 'foreign'}}]
        before = copy.deepcopy(self.runner.nft_objects)
        with self.assertRaisesRegex(tor.Error, 'receipt'), self.runtime.operation('tor'):
            self.runtime.activate(UID, 19040, 19053)
        self.assertEqual(self.runner.nft_objects, before)
        self.assertEqual(self.runner.mutations(), [])
        self.runner.nft_objects = []
        self.activate()
        self.runner.nft_objects[-1]['rule']['comment'] = 'altered'
        before = len(self.runner.mutations())
        with self.assertRaises(tor.Error), self.runtime.operation('tor'):
            self.runtime.block()
        self.assertEqual(len(self.runner.mutations()), before)

    def test_foreign_reserved_route_and_uid_rule_are_not_adopted(self):
        for case in ('route', 'rule'):
            if case == 'route':
                self.runner.routes = [dict(dst='default', table=tor.ROUTE_TABLE, dev='other0')]
            else:
                self.runner.routes = []
                self.runner.rules = [dict(priority=tor.PRIORITY, table=99)]
            with self.subTest(case=case), self.assertRaises(tor.Error), self.runtime.operation('tor'):
                self.runtime.activate(UID, 19040, 19053)
            self.assertEqual(self.runner.mutations(), [])

    def test_receipt_rejects_changed_boot_namespace_profile_and_private_permissions(self):
        self.activate()
        path = self.backend.path(tor.STATE)
        original = path.read_text()
        for key, value in (('boot_id', '00000000-0000-4000-8000-000000000002'),
                           ('netns', 'net:[9]'), ('profile_identity', 'b' * 64), ('uid', True),
                           ('run_id', 'bad')):
            changed = json.loads(original); changed[key] = value
            path.write_text(json.dumps(changed))
            with self.subTest(field=key), self.assertRaises(tor.Error):
                self.runtime.state()
        path.write_text(original)
        path.chmod(0o644)
        with self.assertRaises(tor.Error):
            self.runtime.state()
        path.chmod(0o600)
        path.write_text(original[:-2] + ',"uid":60001}\n')
        with self.assertRaises(tor.Error):
            self.runtime.state()

    def test_receipt_symlink_hardlink_and_compare_and_swap_refuse_unverified_changes(self):
        state = self.activate()
        path = self.backend.path(tor.STATE)
        original = path.read_text()
        saved = path.with_name('saved')
        path.rename(saved)
        path.symlink_to(saved)
        with self.assertRaises(tor.Error):
            self.runtime.state()
        path.unlink()
        os.link(saved, path)
        with self.assertRaises(tor.Error):
            self.runtime.state()
        saved.unlink()
        self.assertEqual(self.runtime.state(), state)
        with self.assertRaisesRegex(tor.Error, 'changed'):
            self.runtime.save({**state, 'phase': 'blocked'}, None)
        self.assertEqual(path.read_text(), original)

    def test_hardware_bound_nft_interface_names_are_normalized_but_replacement_is_refused(self):
        self.runner.names = True
        self.activate()
        self.assertTrue(self.runtime.status()['ready'])
        self.runner.interfaces['eth0']['ifindex'] = 91
        before = len(self.runner.mutations())
        with self.assertRaises(tor.Error), self.runtime.operation('tor'):
            self.runtime.block()
        self.assertEqual(len(self.runner.mutations()), before)

    def test_native_ipv6_inference_and_rhs_set_order_preserve_exact_guard_semantics(self):
        state = self.activate()
        native = copy.deepcopy(self.runner.nft_objects)
        transformed_ipv6 = transformed_set = False
        for item in native:
            rule = item.get('rule')
            if rule is None:
                continue
            ipv6 = any(expression.get('match', {}).get('left', {}).get('payload', {}).get(
                       'protocol') == 'ip6' for expression in rule['expr'])
            if ipv6:
                old = len(rule['expr'])
                rule['expr'] = [expression for expression in rule['expr']
                                if expression != tor.match(tor.meta('nfproto'), 'ipv6')]
                transformed_ipv6 |= old != len(rule['expr'])
            for expression in rule['expr']:
                right = expression.get('match', {}).get('right')
                if isinstance(right, dict) and 'set' in right:
                    right['set'].reverse()
                    transformed_set = True
        self.assertTrue(transformed_ipv6 and transformed_set)
        self.assertEqual(self.runtime.guard(native, state), 'active')
        changed = next(expression['match']['right']['set'] for item in native
                       for expression in item.get('rule', {}).get('expr', [])
                       if isinstance(expression.get('match', {}).get('right'), dict)
                       and 'set' in expression['match']['right'])
        changed.append('198.51.100.99')
        with self.assertRaises(tor.Error):
            self.runtime.guard(native, state)

    def test_captured_native_first_smoke_has_exact_starting_guard_after_tcp_enum_normalization(self):
        path = Path(__file__).with_name('fixtures') / 'host_tor_native_nft_starting.json'
        fixture = json.loads(path.read_text())
        state, native = fixture['state'], fixture['nftables']
        self.assertEqual(fixture['provenance']['native_object_count'], 28)
        self.assertEqual(fixture['provenance']['normalization_failure_count'], 2)
        self.assertEqual(fixture['provenance']['source_sha256'],
                         '8ec17d8c2a2b8088d33fb81903d85c3c06659451db22926a9328aab9e5c5d084')
        # Retain the historical capture unchanged on disk. Its old DNS target
        # is refused; upgrade only DNS and exact SSH ACK matching in memory
        # for enum comparisons. The recorded capture is never rewritten.
        with self.assertRaisesRegex(tor.Error, 'firewall changed'):
            self.runtime.guard(native, state)
        replacements = 0
        for item in native:
            for expression in item.get('rule', {}).get('expr', []):
                if expression.get('dnat') == {'family': 'ip', 'addr': '127.0.0.1', 'port': 19053}:
                    expression['dnat']['addr'] = state['selection']['uplink']['address']
                    replacements += 1
                check = expression.get('match', {})
                if (item.get('rule', {}).get('chain') in ('local_nat', 'output_guard')
                        and check.get('left') == {'ct': {'key': 'state'}}
                        and check.get('right') in ('established', 2)):
                    expression['match'] = tor.match({'&': [tor.payload('tcp', 'flags'), 18]}, 16)['match']
        self.assertEqual(replacements, 1)
        original = copy.deepcopy(native)
        self.assertEqual(self.runtime.guard(native, state), 'starting')
        self.assertEqual(native, original, 'Read-only comparison must not rewrite the native evidence.')
        protocol_rules = [index for index, item in enumerate(native) if any(
            expression.get('match', {}).get('left') == tor.meta('l4proto')
            for expression in item.get('rule', {}).get('expr', []))]
        self.assertEqual(len(protocol_rules), 2)
        for index in protocol_rules:
            for wrong in (17, 250, '6', 6.0):
                changed = copy.deepcopy(native)
                expression = next(expression['match'] for expression in changed[index]['rule']['expr']
                                  if expression.get('match', {}).get('left') == tor.meta('l4proto'))
                expression['right'] = wrong
                with self.subTest(rule=index, wrong=wrong), self.assertRaises(tor.Error):
                    self.runtime.guard(changed, state)
        changed = copy.deepcopy(native)
        rule = changed[protocol_rules[-1]]['rule']
        uid = next(expression['match'] for expression in rule['expr']
                   if expression.get('match', {}).get('left') == tor.meta('skuid'))
        uid['right'] = 6
        with self.assertRaises(tor.Error):
            self.runtime.guard(changed, state)

    def test_captured_native_numeric_ip_rule_and_routes_are_exactly_owned(self):
        fixture = json.loads((Path(__file__).with_name('fixtures') / 'host_tor_native_ip_rules.json').read_text())
        self.assertEqual(fixture['provenance']['source_sha256'],
                         'dee050e1572cad4b5c33dbe1beb02b3c96a7b24fc755b72b5f916fcaec8ffcd4')
        self.runner.rules, self.runner.routes = fixture['rules'], fixture['routes']
        routes, rules = self.runtime.routes(fixture['state'])
        self.assertCountEqual(routes, tor.route_objects(fixture['state']))
        self.assertEqual(rules, [dict(priority=tor.PRIORITY, src='all', uidrange={'start': UID, 'end': UID},
                                      table=tor.ROUTE_TABLE, protocol=tor.PROTOCOL)])
        self.assertEqual(len(routes), 3)
        # A different dedicated UID remains a foreign rule, even though its
        # endpoints are a well-formed native single-UID range.
        self.runner.rules[1].update(uid_start=UID + 1, uid_end=UID + 1)
        with self.assertRaises(tor.Error):
            self.runtime.routes(fixture['state'])

    def test_native_uid_rule_format_survives_full_lifecycle_and_cleanup(self):
        self.runner.native_uid_rules = True
        self.activate()
        self.assertTrue(self.runtime.status()['ready'])
        with self.runtime.operation('tor'):
            self.runtime.recover()
            self.runtime.ready()
            self.runtime.block()
            self.runtime.deactivate()
        self.assertEqual(self.runtime.status()['mode'], 'off')
        self.assertEqual(self.runner.rules, [])
        self.assertEqual(self.runner.routes, [])

    def test_uid_rule_parser_rejects_ambiguous_extra_missing_or_wrongly_typed_fields(self):
        base = dict(priority=tor.PRIORITY, src='all', uid_start=UID, uid_end=UID,
                    table=str(tor.ROUTE_TABLE), protocol=str(tor.PROTOCOL))
        legacy = {key: value for key, value in base.items() if key not in ('uid_start', 'uid_end')}
        legacy['uidrange'] = {'start': UID, 'end': UID}
        self.assertEqual(tor.canonical_uid_rule(base), tor.canonical_uid_rule(legacy))
        invalid = [dict(base, uidrange={'start': UID, 'end': UID}), dict(base, unknown=1),
                   dict(base, uid_start=str(UID)), dict(base, uid_end=True), dict(base, uid_end=float(UID)),
                   dict(base, uid_end=UID + 1), dict(base, uid_start=0, uid_end=0),
                   dict(base, priority=str(tor.PRIORITY)), dict(base, table=float(tor.ROUTE_TABLE)),
                   dict(base, protocol='0187'), dict(base, protocol=True), dict(base, src='192.0.2.2'),
                   dict(legacy, uidrange={'start': UID, 'end': UID, 'extra': 0}),
                   dict(legacy, uidrange={'start': UID, 'end': str(UID)})]
        for missing in ('uid_start', 'uid_end', 'protocol', 'table'):
            row = copy.deepcopy(base); row.pop(missing); invalid.append(row)
        for index, row in enumerate(invalid):
            with self.subTest(case=index), self.assertRaises(tor.Error):
                tor.canonical_uid_rule(row)

    def test_string_reserved_priority_cannot_hide_a_malformed_foreign_rule(self):
        state = self.activate()
        self.runner.rules.append(dict(priority=str(tor.PRIORITY), src='all', table=123))
        with self.assertRaises(tor.Error):
            self.runtime.routes(state)

    def test_complete_owned_crash_temporary_is_removed_before_off_and_next_activation_works(self):
        state = self.activate()
        temporary = self.backend.path(tor.RUNTIME) / ('.state-' + '1' * 24)
        temporary.write_text(json.dumps({**state, 'phase': 'active', 'pending': 'blocked'}))
        temporary.chmod(0o600)
        self.assertEqual(self.runtime.state(), state)
        with self.runtime.operation('tor'):
            self.runtime.block()
            self.runtime.deactivate()
        self.assertEqual(list(self.backend.path(tor.RUNTIME).iterdir()), [])
        self.assertEqual(self.runtime.status()['mode'], 'off')
        self.activate()
        self.assertTrue(self.runtime.status()['ready'])

    def test_complete_unpublished_first_receipt_can_be_retried_without_adopting_kernel_objects(self):
        state = self.activate(ready=False)
        temporary = self.backend.path(tor.RUNTIME) / ('.state-' + '2' * 24)
        temporary.write_text(json.dumps(state)); temporary.chmod(0o600)
        self.backend.path(tor.STATE).unlink()
        # Reproduce the earlier crash point: the initial receipt was written,
        # but no nft/routing mutation has happened before its publication.
        self.runner.nft_objects, self.runner.routes, self.runner.rules = [], [], []
        self.assertEqual(self.runtime.status()['mode'], 'off')
        self.activate()
        self.assertFalse(temporary.exists())
        self.assertNotEqual(self.runtime.state()['run_id'], state['run_id'])

    def test_foreign_incomplete_or_unsafe_runtime_entries_are_not_removed(self):
        state = self.activate()
        directory = self.backend.path(tor.RUNTIME)
        owned = directory / ('.state-' + '3' * 24)
        owned.write_text(json.dumps(state)); owned.chmod(0o600)
        for case in ('foreign-name', 'other-run', 'partial', 'unsafe-mode'):
            path = directory / ('foreign' if case == 'foreign-name' else '.state-' + '4' * 24)
            value = {**state, 'run_id': '00000000-0000-4000-8000-000000000003'} if case == 'other-run' else state
            path.write_text('{' if case == 'partial' else json.dumps(value))
            path.chmod(0o644 if case == 'unsafe-mode' else 0o600)
            before = len(self.runner.mutations())
            with self.subTest(case=case), self.assertRaises(tor.Error), self.runtime.operation('tor'):
                self.runtime.block()
                self.runtime.deactivate()
            self.assertEqual(len(self.runner.mutations()), before)
            self.assertTrue(path.exists() and owned.exists() and self.backend.path(tor.STATE).exists())
            path.unlink()

    def test_firewall_extension_has_no_health_or_objects_recursion_and_rejects_tamper(self):
        self.activate()
        foreign = {'table': {'family': 'inet', 'name': 'foreign'}}
        with (patch.object(self.backend, 'healthy', side_effect=AssertionError('recursive')),
              patch.object(self.backend, 'objects', side_effect=AssertionError('recursive'))):
            self.assertEqual(tor.firewall_view(self.backend, [foreign, *self.runner.nft_objects]), [foreign])
        with self.assertRaises(tor.Error):
            tor.require_share_change_allowed(self.backend)
        self.runner.nft_objects[-1]['rule']['comment'] = 'tampered'
        with self.assertRaises(tor.Error):
            tor.firewall_view(self.backend, self.runner.nft_objects)

    def test_wifi_guard_preserves_legacy_absence_and_blocks_selected_hardware_aliases(self):
        backend = SimpleNamespace(root=self.root / 'sys', host_profile=fixtures.Profile(), owner_uid=os.geteuid())
        adapter = SimpleNamespace(name='other0', index=5, device_path=self.root / 'sys/devices/other0')
        with patch.object(tor, 'load_share', side_effect=AssertionError('unexpected load')):
            tor.require_wifi_change_allowed(backend, adapter)
        self.activate()
        tor.require_wifi_change_allowed(backend, adapter)
        for name, index, device in (('eth0', 5, 'other0'), ('renamed', 2, 'other0'), ('renamed', 5, 'eth0')):
            target = SimpleNamespace(name=name, index=index, device_path=self.root / 'sys/devices' / device)
            with self.subTest(name=name, index=index, device=device), self.assertRaises(tor.Error):
                tor.require_wifi_change_allowed(backend, target)

    def test_mutations_require_operation_context(self):
        for call in (lambda: self.runtime.activate(UID, 19040, 19053), self.runtime.ready,
                     self.runtime.recover, self.runtime.block, self.runtime.deactivate):
            with self.assertRaisesRegex(tor.Error, 'serialized'):
                call()

    def test_packet_guard_has_no_general_lan_dns_old_flow_or_ipv6_bypass(self):
        state = self.activate()
        for packet in ({}, {'ct_state': 'established'}, {'l4proto': 'udp', 'dport': 53},
                       {'l4proto': 'udp', 'dport': 443}, {'nfproto': 'ipv6', 'saddr': '2001:db8::2',
                                                        'daddr': '2001:db8::3'},
                       {'daddr': '192.0.2.1', 'dport': 53}, {'skuid': UID, 'oif': 5},
                       {'skuid': UID, 'saddr': '192.0.2.3'}, {'skuid': UID, 'dport': 53}):
            with self.subTest(packet=packet):
                self.assertEqual(evaluate(state, 'output_guard', **packet), 'drop')
        self.assertEqual(evaluate(state, 'output_guard', skuid=UID), 'accept')
        exact = dict(saddr='192.0.2.2', daddr='192.0.2.50', sport=22, dport=55000, ct_state='established', flags=16)
        self.assertEqual(evaluate(state, 'output_guard', **exact), 'accept')
        self.assertEqual(evaluate(state, 'local_nat', **exact), 'return')
        self.assertEqual(evaluate(state, 'output_guard', **{**exact, 'dport': 55001}), 'drop')
        self.assertEqual(evaluate(state, 'local_nat', l4proto='udp', dport=53), 'dnat')
        self.assertEqual(evaluate(state, 'local_nat', dport=53), 'drop')
        self.assertEqual(evaluate(state, 'forward_guard'), 'drop')

    def test_dhcp_is_limited_to_selected_uplink_and_client_local_lease_traffic(self):
        self.enable_share()
        state = self.activate()
        request = dict(iif=4, l4proto='udp', saddr='0.0.0.0', daddr='255.255.255.255', sport=68, dport=67)
        for source in ('0.0.0.0', '10.42.0.88'):
            self.assertEqual(evaluate(state, 'client_guard', **{**request, 'saddr': source}), 'return')
            self.assertEqual(evaluate(state, 'client_nat', **{**request, 'saddr': source}), 'return')
        self.assertEqual(evaluate(state, 'client_guard', **{**request, 'saddr': '203.0.113.8'}), 'drop')
        self.assertEqual(evaluate(state, 'client_guard', **{**request, 'daddr': '203.0.113.8'}), 'drop')
        reply = dict(oif=4, oifname='ap0', l4proto='udp', saddr='10.42.0.1',
                     daddr='255.255.255.255', sport=67, dport=68)
        self.assertEqual(evaluate(state, 'output_guard', **reply), 'accept')
        self.assertEqual(evaluate(state, 'local_nat', **reply), 'return')
        for change in ({'oif': 5}, {'saddr': '10.42.0.2'}, {'daddr': '203.0.113.8'}, {'dport': 53}):
            self.assertEqual(evaluate(state, 'output_guard', **{**reply, **change}), 'drop')
        uplink = dict(l4proto='udp', saddr='0.0.0.0', daddr='255.255.255.255', sport=68, dport=67)
        self.assertEqual(evaluate(state, 'output_guard', **uplink), 'accept')
        self.assertEqual(evaluate(state, 'output_guard', **{**uplink, 'oif': 5}), 'drop')

    def test_exposed_listeners_require_marked_redirect_from_selected_client_and_active_phase(self):
        self.enable_share()
        state = self.activate()
        packet = dict(iif=4, iifname='ap0', saddr='10.42.0.88', daddr='10.42.0.1', dport=19040,
                      ct_mark=tor.MARK, ct_status=['dnat'])
        self.assertEqual(evaluate(state, 'input_guard', **packet), 'accept')
        for change in ({'ct_mark': 0}, {'ct_status': []}, {'iif': 5}, {'saddr': '203.0.113.8'}):
            self.assertEqual(evaluate(state, 'input_guard', **{**packet, **change}), 'drop')
        self.assertEqual(evaluate({**state, 'phase': 'recovering'}, 'input_guard', **packet), 'drop')
        self.assertEqual(evaluate(state, 'input_guard', dport=19050), 'drop')
        self.assertEqual(evaluate(state, 'client_nat', iif=4, saddr='10.42.0.88', l4proto='udp', dport=53), 'redirect')
        self.assertEqual(evaluate(state, 'client_guard', iif=4, saddr='10.42.0.88', dport=53), 'drop')

    def test_active_local_dnat_uses_fixed_destination_and_conntrack_even_before_oif_reroute(self):
        state = self.activate()
        flows = [dict(daddr='127.0.0.1', dport=19040, l4proto='tcp'),
                 dict(daddr=state['selection']['uplink']['address'], dport=19053, l4proto='udp'),
                 dict(nfproto='ipv6', saddr='2001:db8::2', daddr='::1', dport=19053, l4proto='udp')]
        for flow in flows:
            # The native proof shows OUTPUT still has eth0/upl0 here. A lo-only
            # test would miss the real failure and the reason for this rule.
            packet = dict(oif=2, oifname='eth0', skuid=1000, ct_mark=tor.MARK,
                          ct_status=['dnat'], ct_direction='original', **flow)
            with self.subTest(flow=flow):
                self.assertEqual(evaluate(state, 'output_guard', **packet), 'accept')
            for change in ({'ct_mark': 0}, {'ct_status': []}, {'ct_status': ['snat']},
                           {'ct_direction': 'reply'}, {'dport': 19050}, {'dport': 19054},
                           {'daddr': '127.0.0.2' if flow.get('nfproto') != 'ipv6' else '::2'},
                           {'l4proto': 'udp' if flow['l4proto'] == 'tcp' else 'tcp'}):
                with self.subTest(flow=flow, change=change):
                    self.assertEqual(evaluate(state, 'output_guard', **{**packet, **change}), 'drop')
            for phase in ('starting', 'recovering', 'blocked', 'cleanup'):
                for tracking in ('new', 'established'):
                    with self.subTest(flow=flow, phase=phase, tracking=tracking):
                        self.assertEqual(evaluate({**state, 'phase': phase}, 'output_guard',
                                                  **{**packet, 'ct_state': tracking}), 'drop')

    def test_only_three_active_output_admissions_are_added_and_none_admits_socks(self):
        state = self.activate()
        for phase in tor.PHASES:
            rules = [item['rule'] for item in tor.nft_objects({**state, 'phase': phase})
                     if item.get('rule', {}).get('chain') == 'output_guard' and
                     any(expression.get('match', {}).get('left') == {'ct': {'key': 'status'}}
                         for expression in item['rule']['expr'])]
            self.assertEqual(len(rules), 3 if phase == 'active' else 0)
            for rule in rules:
                self.assertNotIn(tor.match(tor.payload('tcp', 'dport'), 19050), rule['expr'])
                self.assertIn(tor.match({'ct': {'key': 'direction'}}, 'original'), rule['expr'])
                self.assertIn(tor.match({'&': [{'ct': {'key': 'mark'}}, tor.MARK]}, tor.MARK), rule['expr'])

    def test_captured_native_local_dnat_candidate_is_the_exact_active_template(self):
        fixture = json.loads((Path(__file__).with_name('fixtures') / 'host_tor_native_wildcard_dns_active.json').read_text())
        self.assertEqual(fixture['provenance']['successful_native_cases'], 11)
        self.assertTrue(fixture['provenance']['strict_dns_peer_matched'])
        state, native = fixture['state'], fixture['native_nft']
        before = copy.deepcopy(native)
        self.assertEqual(self.runtime.canonical(tor.nft_objects(state), state),
                         self.runtime.canonical(fixture['submitted_nft'], state))
        self.assertEqual(self.runtime.guard(native, state), 'active')
        self.assertEqual(len([item for item in native if 'metainfo' not in item]), 29)
        self.assertEqual(native, before)

    def test_native_dnat_normalization_does_not_hide_changed_status_direction_or_transport(self):
        fixture = json.loads((Path(__file__).with_name('fixtures') / 'host_tor_native_wildcard_dns_active.json').read_text())
        state, native = fixture['state'], fixture['native_nft']
        indexes = [index for index, item in enumerate(native) if item.get('rule', {}).get('chain') == 'output_guard'
                   and any(expression.get('match', {}).get('left') == {'ct': {'key': 'status'}}
                           for expression in item['rule']['expr'])]
        self.assertEqual(len(indexes), 3)
        for index in indexes:
            for wrong in (16, 48, 64, 32.0, '32', True):
                changed = copy.deepcopy(native)
                status = next(expression['match'] for expression in changed[index]['rule']['expr']
                              if expression.get('match', {}).get('left') == {'ct': {'key': 'status'}})
                status['right'] = wrong
                with self.subTest(index=index, status=wrong), self.assertRaises(tor.Error):
                    self.runtime.guard(changed, state)
            for wrong in (False, 'reply', 1):
                changed = copy.deepcopy(native)
                direction = next(expression['match'] for expression in changed[index]['rule']['expr']
                                 if expression.get('match', {}).get('left') == {'ct': {'key': 'direction'}})
                direction['right'] = wrong
                with self.subTest(index=index, direction=wrong), self.assertRaises(tor.Error):
                    self.runtime.guard(changed, state)
        # A typed TCP dependency can disappear only if the payload already
        # enforces TCP. Neither UDP nor an inverted TCP test is redundant.
        for extra in (tor.match(tor.meta('l4proto'), 'udp'), tor.match(tor.meta('l4proto'), 'tcp', '!=')):
            changed = copy.deepcopy(native)
            changed[indexes[0]]['rule']['expr'].insert(0, extra)
            with self.subTest(extra=extra), self.assertRaises(tor.Error):
                self.runtime.guard(changed, state)

    def test_legacy_loopback_dns_template_is_not_adopted_after_upgrade(self):
        fixture = json.loads((Path(__file__).with_name('fixtures') / 'host_tor_native_local_dnat_active.json').read_text())
        with self.assertRaisesRegex(tor.Error, 'firewall changed'):
            self.runtime.guard(fixture['native_nft'], fixture['state'])

    def test_host_dns_uses_selected_own_address_without_changing_tcp_or_ipv6(self):
        state = self.activate()
        for address in ('192.0.2.2', '198.51.100.20'):
            selected = copy.deepcopy(state)
            selected['selection']['uplink']['address'] = address
            for phase in tor.PHASES:
                objects = tor.nft_objects({**selected, 'phase': phase})
                destinations = [expr['dnat'] for item in objects
                                for expr in item.get('rule', {}).get('expr', []) if 'dnat' in expr]
                self.assertIn({'family': 'ip', 'addr': address, 'port': 19053}, destinations)
                self.assertNotIn({'family': 'ip', 'addr': '127.0.0.1', 'port': 19053}, destinations)
                self.assertIn({'family': 'ip', 'addr': '127.0.0.1', 'port': 19040}, destinations)
                self.assertIn({'family': 'ip6', 'addr': '::1', 'port': 19053}, destinations)

    def test_observed_ssh_ack_survives_cold_conntrack_but_never_admits_new_syn(self):
        state = self.activate()
        exact = dict(saddr='192.0.2.2', daddr='192.0.2.50', sport=22, dport=55000)
        for tracking in ('new', 'established', 'untracked'):
            for flags in (16, 17, 20, 24):
                with self.subTest(tracking=tracking, flags=flags):
                    packet = {**exact, 'ct_state': tracking, 'flags': flags}
                    self.assertEqual(evaluate(state, 'local_nat', **packet), 'return')
                    self.assertEqual(evaluate(state, 'output_guard', **packet), 'accept')
        for flags in (0, 2, 4, 18, 19):
            with self.subTest(flags=flags):
                self.assertEqual(evaluate(state, 'local_nat', **exact, flags=flags), 'dnat')
                self.assertEqual(evaluate(state, 'output_guard', **exact, flags=flags), 'drop')
        for changed in ({'sport': 23}, {'dport': 55001}, {'saddr': '192.0.2.3'},
                        {'daddr': '192.0.2.51'}, {'oif': 5}, {'l4proto': 'udp'}):
            with self.subTest(changed=changed):
                self.assertEqual(evaluate(state, 'output_guard', **{**exact, 'flags': 16, **changed}), 'drop')

    def test_native_ssh_flags_mask_normalizes_only_exact_syn_ack_bits(self):
        state = self.activate()
        original = tor.nft_objects(state)
        def with_mask(mask):
            items = json.loads(json.dumps(original))
            changed = 0
            for item in items:
                for expression in item.get('rule', {}).get('expr', []):
                    if expression.get('match', {}).get('left') == {'&': [tor.payload('tcp', 'flags'), 18]}:
                        expression['match']['left']['&'][1] = copy.deepcopy(mask)
                        changed += 1
            self.assertEqual(changed, 2)
            return items
        for mask in ({'|': [2, 16]}, {'|': [16, 2]}):
            self.assertEqual(self.runtime.guard(with_mask(mask), state), 'active')
        for mask in ({'|': [2]}, {'|': [16]}, {'|': [2, 16, 4]}, {'|': [2, 2]},
                     {'|': [2, 16.0]}, {'|': [True, 16]}, {'&': [2, 16]}):
            with self.subTest(mask=mask), self.assertRaises(tor.Error):
                self.runtime.guard(with_mask(mask), state)


if __name__ == '__main__':
    unittest.main()
