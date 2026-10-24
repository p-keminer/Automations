"""Offline-only common routing lifecycle and strict composition fixtures."""
import copy
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[4]


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


egress=load('egress_test',ROOT/'pi4/python/egress.py')
fixture=load('privacy_share_fixture',ROOT/'pi4/components/share-control/tests/test_share_control.py')
share=fixture.share
ssh=load('privacy_ssh_fixture',ROOT/'pi4/python/auto_ssh.py')


class Platform(fixture.Fixture):
    def __init__(self,root):
        super().__init__(root)
        self.privacy_active=False
    def command(self,args,input_text=None,accepted=(0,)):
        if args[:2]==['/usr/bin/systemctl','show'] and args[2].startswith('automations-'):
            return 'MainPID='+('777' if self.privacy_active else '0')+'\nActiveState='+('active' if self.privacy_active else 'inactive')+'\n'
        return super().command(args,input_text,accepted)


class RoutingTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.p=Platform(Path(self.temp.name))
        helper=self.p.path('usr/local/libexec/automations-support/egress.py')
        helper.parent.mkdir(parents=True)
        helper.write_bytes((ROOT/'pi4/python/egress.py').read_bytes())
        helper.chmod(0o644)
        self.r=egress.Runtime(share,self.p,lambda name:types.SimpleNamespace(pw_uid=60001 if name=='auto-tor' else 60002))

    def on(self,mode='proxy',ipv6=False):
        if ipv6:
            self.p.selection['ipv6']=dict(addresses=['2001:db8:1::2'],address='2001:db8:1::2',network='2001:db8:1::/64',gateway='fe80::1')
        if not self.p.load(): self.p.change('lan')
        with self.r.operation(mode) as op:
            op.activate(60001 if mode=='tor' else 60002,egress.MODES[mode]['tcp_port'],19053)
            self.p.privacy_active=True
            op.ready()

    def test_proxy_on_off_preserves_share_core_and_rules(self):
        self.p.change('lan')
        before=copy.deepcopy(self.p.fw)
        state=self.p.load()
        self.on()
        self.assertTrue(self.r.status()['ready'])
        self.assertTrue(self.p.healthy(state))
        with self.r.operation('proxy') as op:
            op.block()
            self.p.privacy_active=False
            op.deactivate()
        self.assertEqual(self.r.status()['phase'],'off')
        self.assertEqual(before,self.p.fw)
        self.assertEqual(state,self.p.load())
        self.assertFalse(any('flush' in args for args,_ in self.p.calls))
        self.assertEqual(self.r.status()['interface'],'eth0')

    def test_no_uplink_does_not_start_or_create_state(self):
        with self.assertRaisesRegex(egress.Error,'healthy explicit'):
            with self.r.operation('proxy') as op: op.activate(60002,19081,19053)
        self.assertIsNone(self.r.state())
        self.assertFalse(egress.relevant(self.p.fw))

    def test_activation_failure_keeps_a_closed_guard(self):
        self.p.change('lan')
        with self.assertRaisesRegex(RuntimeError,'backend unavailable'):
            with self.r.operation('proxy') as op:
                op.activate(60002,19081,19053)
                raise RuntimeError('backend unavailable')
        state=self.r.state()
        self.assertEqual(state['phase'],'blocked')
        egress.check_objects(self.p.fw,state)
        self.assertFalse(any(v.get('comment','').startswith('auto-privacy:transport-ip') for _,v in egress.relevant(self.p.fw)))

    def test_interrupt_after_activation_keeps_guard(self):
        self.p.change('lan')
        with self.assertRaises(KeyboardInterrupt):
            with self.r.operation('tor') as op:
                op.activate(60001,19040,19053)
                raise KeyboardInterrupt()
        self.assertEqual(self.r.state()['phase'],'blocked')

    def test_nft_preflight_failure_is_recovered_to_blocked(self):
        self.p.change('lan')
        self.p.fail=lambda args: '--check' in args
        with self.assertRaises(egress.Error):
            with self.r.operation('proxy') as op: op.activate(60002,19081,19053)
        self.assertEqual(self.r.state()['phase'],'blocked')
        egress.check_objects(self.p.fw,self.r.state())

    def test_mutual_exclusion_does_not_alter_active_mode(self):
        self.on('tor')
        before=copy.deepcopy(self.p.fw)
        with self.assertRaisesRegex(egress.Error,'mutually exclusive'):
            with self.r.operation('proxy'): pass
        self.assertEqual(before,self.p.fw)
        self.assertEqual(self.r.state()['phase'],'active')

    def test_held_share_lock_is_typed_busy_without_entering_or_mutating(self):
        self.on('tor')
        before=copy.deepcopy(self.p.fw),self.r.state()
        self.p.calls=[]
        with self.p.lock(),self.assertRaises(egress.Busy) as caught:
            with self.r.operation('tor'):
                self.fail('A contended operation must not be entered.')
        self.assertIs(type(caught.exception),egress.Busy)
        self.assertIs(self.r.Busy,egress.Busy)
        self.assertEqual(before,(self.p.fw,self.r.state()))
        self.assertEqual(self.p.calls,[])
        self.assertFalse(self.r.held)

    def test_other_lock_error_is_not_busy_even_with_the_same_message(self):
        self.on('tor')
        before=copy.deepcopy(self.p.fw),self.r.state()
        @contextmanager
        def invalid_lock():
            raise share.Error('Another sharing operation is running.')
            yield
        with patch.object(self.p,'lock',invalid_lock),self.assertRaises(egress.Error) as caught:
            with self.r.operation('tor'):
                self.fail('An invalid lock must not be entered.')
        self.assertIs(type(caught.exception),egress.Error)
        self.assertEqual(before,(self.p.fw,self.r.state()))

    def test_busy_after_lock_acquisition_is_an_ordinary_preflight_error(self):
        self.on('tor')
        before=copy.deepcopy(self.p.fw),self.r.state()
        with patch.object(self.p,'validate',side_effect=share.Busy('Preflight failed after acquisition.')):
            with self.assertRaises(egress.Error) as caught:
                with self.r.operation('tor'):
                    self.fail('Failed preflight must not enter the operation body.')
        self.assertIs(type(caught.exception),egress.Error)
        self.assertEqual(before,(self.p.fw,self.r.state()))

    def test_busy_inside_operation_remains_fail_closed(self):
        self.on('tor')
        with self.assertRaises(egress.Error) as caught:
            with self.r.operation('tor'):
                raise share.Busy('An operation failed after entry.')
        self.assertIs(type(caught.exception),egress.Error)
        self.assertEqual(self.r.state()['phase'],'blocked')
        egress.check_objects(self.p.fw,self.r.state())

    def test_runtime_busy_inside_operation_cannot_masquerade_as_contention(self):
        self.on('tor')
        with self.assertRaises(egress.Error) as caught:
            with self.r.operation('tor'):
                raise egress.Busy('An operation failed after entry.')
        self.assertIs(type(caught.exception),egress.Error)
        self.assertEqual(self.r.state()['phase'],'blocked')
        egress.check_objects(self.p.fw,self.r.state())

    def test_share_mutations_are_rejected_before_side_effects(self):
        self.on()
        before=copy.deepcopy(self.p.fw)
        self.p.calls=[]
        for action in ('off','lan','wifi'):
            with self.assertRaisesRegex(share.Error,'Turn Tor or proxy off'): self.p.change(action)
        self.assertEqual(before,self.p.fw)
        self.assertEqual([],self.p.calls)

    def test_wrong_uid_or_ports_cannot_create_guard(self):
        self.p.change('lan')
        for uid,port in ((0,19081),(65534,19081),(60001,19081),(60002,443)):
            with self.assertRaises(egress.Error):
                with self.r.operation('proxy') as op: op.activate(uid,port,19053)
            self.assertIsNone(self.r.state())

    def test_off_requires_block_and_service_stopped(self):
        self.on()
        with self.assertRaisesRegex(egress.Error,'Block anonymity'):
            with self.r.operation('proxy') as op: op.deactivate()
        with self.assertRaisesRegex(egress.Error,'Stop the anonymity service'):
            with self.r.operation('proxy') as op: op.block(); op.deactivate()
        self.assertEqual(self.r.state()['phase'],'blocked')

    def test_off_is_idempotent_without_state(self):
        before=copy.deepcopy(self.p.fw)
        with self.r.operation('proxy') as op: op.block(); op.deactivate()
        self.assertEqual(before,self.p.fw)

    def test_foreign_privacy_rule_prevents_cleanup(self):
        self.on()
        self.p.fw['nftables'].append({'rule':egress.rule('egress',[egress.ACCEPT],'foreign')})
        before=copy.deepcopy(self.p.fw)
        with self.assertRaises(egress.Error):
            with self.r.operation('proxy') as op: op.block()
        self.assertEqual(before,self.p.fw)
        self.assertEqual(self.r.status()['phase'],'degraded')

    def test_altered_admission_is_not_hidden_from_core(self):
        self.on()
        entry=next(row['rule'] for row in self.p.fw['nftables'] if row.get('rule',{}).get('comment')=='auto-privacy:input-ip-proxy')
        entry['expr'][0]=egress.meta('iifname','eth0')
        with self.assertRaises(share.Error): self.p.firewall()

    def test_missing_helper_never_relaxes_core_guard(self):
        self.on()
        self.p.path('usr/local/libexec/automations-support/egress.py').unlink()
        with self.assertRaises(OSError): self.p.firewall()

    def test_orphan_owned_table_never_looks_off(self):
        self.p.fw['nftables'].append({'table':{'family':'inet','name':egress.TABLE}})
        with self.assertRaises(egress.Error): self.r.status()

    def test_dualstack_proxy_and_ipv4_only_tor(self):
        self.on('proxy',True)
        state=self.r.state()
        names=[v.get('comment','') for _,v in egress.objects(state)]
        self.assertIn('auto-privacy:input-ip6-proxy',names)
        state['mode']='tor';state['uid']=60001
        names=[v.get('comment','') for _,v in egress.objects(state)]
        self.assertNotIn('auto-privacy:input-ip6-tor',names)
        self.assertIn('auto-privacy:dns-ip6-udp',names)
        self.assertIn('auto-privacy:dns-tcp-block-ip6',names)

    def test_share_frontend_dns_is_preserved_and_helper_only_redirected(self):
        self.on()
        own=egress.objects(self.r.state())
        dns=[v for k,v in own if k=='rule' and v.get('comment','').startswith('auto-privacy:dns-ip')]
        self.assertEqual(len(dns),4)
        for row in dns: self.assertEqual(row['expr'][0],egress.meta('skuid',65534))
        self.assertEqual(self.p.read(share.UNIT),share.unit_text(self.p.load()['selection']))

    def test_unsafe_state_symlink_or_mode_is_rejected(self):
        self.on()
        path=self.p.path(egress.STATE)
        path.chmod(0o644)
        with self.assertRaises(egress.Error): self.r.state()
        path.chmod(0o600)
        saved=path.read_text();path.unlink()
        other=path.parent/'other.json';other.write_text(saved);other.chmod(0o600)
        path.symlink_to(other)
        with self.assertRaises(egress.Error): self.r.state()

    def test_unverified_guard_never_claims_ready(self):
        self.on()
        self.p.fw['nftables']=[row for row in self.p.fw['nftables'] if row.get('table',{}).get('name')!=egress.TABLE]
        status=self.r.status()
        self.assertFalse(status['ready'])
        self.assertIn('could not be verified',status['error'])

    def test_legacy_components_cannot_activate_before_any_mutation(self):
        self.p.change('lan')
        with patch.object(share,'PRIVACY_API',0):
            with self.assertRaisesRegex(egress.Error,'share-control'):
                with self.r.operation('proxy') as op:op.activate(60002,19081,19053)
        self.assertIsNone(self.r.state())
        path=self.p.path('usr/local/libexec/automations/ssh');path.parent.mkdir(parents=True)
        for text in ('# old component\n','PRIVACY_API = 0\n','PRIVACY_API = 1\nPRIVACY_API = 2\n'):
            path.write_text(text);path.chmod(0o755)
            with self.assertRaisesRegex(egress.Error,'ssh-control'):
                with self.r.operation('proxy') as op:op.activate(60002,19081,19053)
            self.assertIsNone(self.r.state())
        path.write_bytes((ROOT/'pi4/python/auto_ssh.py').read_bytes())
        self.on();self.assertTrue(self.r.status()['ready'])

    def ssh_platform(self):
        def command(args,input_text=None):
            if args[0]=='nft':
                if args[-1]=='ruleset':return json.dumps(self.p.fw)
                return json.dumps({'nftables':[row for row in self.p.fw['nftables'] if
                    row.get('chain',{}).get('table')=='pi4' and row['chain'].get('name')=='input' or
                    row.get('rule',{}).get('table')=='pi4' and row['rule'].get('chain')=='input']})
            if args[0]=='ip':return json.dumps([{'ifname':'ctrl0'},{'ifname':'eth0'}])
            raise AssertionError(args)
        return ssh.Platform(self.p.root,command,self.p.owner)

    def test_ssh_input_validation_with_exact_privacy_rules(self):
        self.on('proxy',True)
        control=self.ssh_platform()
        with control.lock():handle=control.handle()
        self.assertEqual(handle,17)
        row=next(row for row in self.p.fw['nftables'] if row.get('rule',{}).get('expr')==share.SSH_INPUT)
        self.p.fw['nftables'].remove(row)
        with control.lock():self.assertIsNone(control.handle())
        self.p.fw['nftables'].append(row)
        with control.lock():self.assertEqual(control.handle(),17)
        self.assertTrue(self.r.status()['ready'])

    def test_ssh_refuses_modified_privacy_output_and_input(self):
        self.on()
        control=self.ssh_platform()
        original=copy.deepcopy(self.p.fw)
        for name in ('auto-privacy:input-ip-proxy','auto-privacy:share-local-dnat-0'):
            self.p.fw=copy.deepcopy(original)
            row=next(row['rule'] for row in self.p.fw['nftables'] if row.get('rule',{}).get('comment')==name)
            row['expr']=[egress.ACCEPT]
            with self.assertRaises(ssh.Error):control.handle()
        self.p.fw=original
        self.p.path('usr/local/libexec/automations-support/egress.py').unlink()
        with self.assertRaises(OSError):control.handle()

    def test_ssh_serializes_with_share_and_privacy_even_before_activation(self):
        control=self.ssh_platform()
        with self.p.lock():
            with self.assertRaisesRegex(ssh.Error,'sharing or anonymity'):
                with control.lock():pass
        with control.lock():pass

    def test_host_prefix_normalization_keeps_strict_addresses(self):
        left=egress.rule('egress',[egress.payload('ip6','daddr',egress.prefix('::1/128')),egress.ACCEPT],'test')
        right=egress.rule('egress',[egress.payload('ip6','daddr','::1'),egress.ACCEPT],'test')
        self.assertEqual(egress.normalize(left),egress.normalize(right))
        right['expr'][0]=egress.payload('ip6','daddr','::2')
        self.assertNotEqual(egress.normalize(left),egress.normalize(right))

    def test_local_redirect_admissions_require_dnat_mark_and_exact_loopback(self):
        self.on()
        original=copy.deepcopy(self.p.fw)
        for field in ('mark','destination','dnat'):
            self.p.fw=copy.deepcopy(original)
            row=next(row['rule'] for row in self.p.fw['nftables'] if row.get('rule',{}).get('comment')=='auto-privacy:share-local-dnat-0')
            if field=='mark':row['expr'][3]['match']['right']=0
            if field=='destination':row['expr'][0]['match']['right']='1.1.1.1'
            if field=='dnat':row['expr'].pop(2)
            with self.assertRaises(share.Error):self.p.firewall()


if __name__=='__main__': unittest.main()
