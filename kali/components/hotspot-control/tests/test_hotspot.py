"""Isolation/secret/markup contracts; live association is a separate hardware test."""
import copy
import importlib.util
import json
import io
import tempfile
from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

ROOT=Path(__file__).resolve().parents[3]
def module(name,file):
    spec=importlib.util.spec_from_file_location(name,ROOT/'python'/file)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
h=module('hotspot','auto_hotspot.py')
share=module('share_ap_test','auto_share.py')
privacy=module('privacy_ap_test','egress.py')
BASE={'mode':'wifi','interface':'wlan0','address':'192.0.2.10','network':'192.0.2.0/24','gateway':'192.0.2.1','dns':['192.0.2.1'],
    'ipv6':None,'control6':{'network':'fd12:3456:789a:1::/64','address':'fd12:3456:789a:1::1','linklocal':'fe80::1234'}}


class HotspotTests(unittest.TestCase):
    def test_stale_active_metadata_is_not_reported_as_up(self):
        with patch.object(h.Path,'exists',return_value=True),patch.object(h,'run',return_value='inactive\n'):
            self.assertFalse(h.service_ready({'phase':'active'}))
        with patch.object(h.Path,'exists',return_value=True),patch.object(h,'run',return_value='active\n'),patch.object(h,'radio_present',return_value=True):
            self.assertTrue(h.service_ready({'phase':'active'}))
            self.assertFalse(h.service_ready({'phase':'starting'}))

    def test_live_daemon_and_namespace_without_radio_are_not_up(self):
        with patch.object(h.Path,'exists',return_value=True),patch.object(h,'run',return_value='active\n'),patch.object(h,'radio_present',return_value=False):
            self.assertFalse(h.service_ready({'phase':'active'}))

    def test_radio_requires_kernel_phy_and_moved_namespace_interface_instance(self):
        s={'adapter':['wlan0',17,'phy2','/host/phy2','/usb','148f:3572'],'radio_index':4}
        valid='Interface wlan0\n\tifindex 4\n\ttype AP\n\twiphy 2\n'
        with patch.object(h,'inside',return_value=valid) as inside:
            self.assertTrue(h.radio_present(s))
            inside.assert_called_once_with('/usr/sbin/iw','dev','wlan0','info',accepted=(0,237))
        for invalid in ('',valid.replace('wiphy 2','wiphy 6'),valid.replace('ifindex 4','ifindex 17'),valid.replace('type AP','type managed'),valid.replace('Interface wlan0','Interface wlan1')):
            with self.subTest(invalid=invalid),patch.object(h,'inside',return_value=invalid):
                self.assertFalse(h.radio_present(s))
        with patch.object(h,'inside',side_effect=h.Error('command unavailable')):
            with self.assertRaisesRegex(h.Error,'unavailable'):h.radio_present(s)

    def test_worker_detects_usb_loss_even_when_all_daemons_survive(self):
        child=Mock();child.poll.return_value=None
        with patch.object(h,'radio_present',side_effect=[True,False]),patch.object(h.time,'monotonic',side_effect=[0,1.2]),patch.object(h.time,'sleep'):
            with self.assertRaisesRegex(h.Error,'adapter disappeared'):
                h.watch_radio({'adapter':[]},[child],lambda:False)

    def test_radio_watch_stops_normally_and_keeps_checks_off_the_fast_tick(self):
        child=Mock();child.poll.return_value=None
        with patch.object(h,'radio_present',return_value=True) as present,patch.object(h.time,'monotonic',side_effect=[5,5.3]),patch.object(h.time,'sleep'):
            stopped=Mock(side_effect=[False,False,True])
            h.watch_radio({},[child],stopped)
            present.assert_called_once()

    def test_missing_radio_cleanup_removes_runtime_without_iw_enodev(self):
        adapter=SimpleNamespace(name='wlan0',index=4,phy='phy2',usb_id='148f:3572',device_path='/original-usb')
        platform=SimpleNamespace(locked=nullcontext,devices=lambda:{})
        wifi=SimpleNamespace(Adapter=lambda *args:adapter,Platform=lambda:platform)
        helper=SimpleNamespace(GUEST=share.GUEST)
        original_exists=h.Path.exists
        def exists(p):
            if str(p)=='/run/netns/'+h.NS:return True
            if str(p)=='/sys/class/net/autoap0':return False
            return original_exists(p)
        with tempfile.TemporaryDirectory() as root:
            base=Path(root)/'runtime';base.mkdir()
            with patch.object(h,'BASE',base),patch.object(h,'WEB',Path(root)/'web'),patch.object(h,'modules',return_value=(helper,wifi,None)),patch.object(h,'load',return_value={'adapter':[]}),patch.object(h.Path,'exists',exists),patch.object(h,'inside',return_value='[]') as inside,patch.object(h,'run') as run:
                h.cleanup()
                self.assertFalse(base.exists())
                self.assertEqual(inside.call_args.args,('/usr/sbin/ip','-j','link','show'))
                run.assert_called_once_with(['/usr/sbin/ip','netns','delete',h.NS])

    def test_cleanup_refuses_reused_name_with_different_interface_identity(self):
        adapter=SimpleNamespace(name='wlan0',index=4,phy='phy2')
        platform=SimpleNamespace(locked=nullcontext)
        wifi=SimpleNamespace(Adapter=lambda *args:adapter,Platform=lambda:platform)
        with patch.object(h,'modules',return_value=(SimpleNamespace(GUEST=share.GUEST),wifi,None)),patch.object(h,'load',return_value={'adapter':[]}),patch.object(h.Path,'exists',return_value=True),patch.object(h,'inside',return_value='[{"ifname":"wlan0","ifindex":17}]'),patch.object(h,'run') as run:
            with self.assertRaisesRegex(h.Error,'interface identity changed'):h.cleanup()
            run.assert_not_called()

    def test_excluded_control_wlan_gets_no_router_advertisement_or_shared_dns6(self):
        selected={**copy.deepcopy(BASE),'guest':dict(share.GUEST),'sources':['autoap0'],
            'ipv6':{'addresses':['2001:4860::2'],'address':'2001:4860::2','network':'2001:4860::/64','gateway':'fe80::1'}}
        share.validate_selection(selected)
        self.assertNotIn('--enable-ra',share.unit_text(selected))
        self.assertNotIn('auto-share:dns6-',json.dumps(share.input_rules(selected)))
        selected['sources'].append('ctrl0')
        self.assertIn('--enable-ra',share.unit_text(selected))

    def test_socket_not_yet_created_is_readiness_not_fatal_start_failure(self):
        with patch.object(h,'inside',side_effect=['Failed to connect','state=ENABLED\nchannel=6\nbssid[0]=00:11:22:33:44:55']),patch.object(h.time,'sleep') as sleep:
            result=h.wait_radio('wlan1',[],lambda:False)
            self.assertEqual(result['channel'],'6');sleep.assert_called_once_with(.2)
            self.assertEqual(h.inside.call_args.kwargs['accepted'],(0,1,255))

    def test_readiness_failure_or_cancellation_is_bounded(self):
        with patch.object(h,'inside',return_value='unavailable'),patch.object(h.time,'monotonic',side_effect=[0,26]):
            with self.assertRaisesRegex(h.Error,'did not become ready'):h.wait_radio('wlan1',[],lambda:False)
        with patch.object(h,'inside') as inside:
            with self.assertRaisesRegex(h.Error,'service exited'):h.wait_radio('wlan1',[],lambda:True)
            inside.assert_not_called()

    def test_each_source_combination_admits_only_selected_clients_in_share_and_tor(self):
        for sources in ([],['ctrl0'],['autoap0'],['ctrl0','autoap0']):
            selected={**copy.deepcopy(BASE),'guest':dict(share.GUEST),'sources':sources}
            share.validate_selection(selected)
            rules=[v for kind,v in share.nft_objects(selected) if kind=='rule']
            comments={x['comment'] for x in rules}
            self.assertEqual('auto-share:out-ip-v2' in comments,'ctrl0' in sources)
            self.assertEqual('auto-share:guest-out' in comments,'autoap0' in sources)
            self.assertEqual('auto-share:dns-udp-v1' in comments,'ctrl0' in sources)
            self.assertEqual('auto-share:guest-dns-udp-peer' in comments,'autoap0' in sources)
            self.assertIn('auto-share:pi-out-ip-v2',comments)
            state={'version':1,'mode':'tor','uid':120,'selection':selected,'phase':'active'}
            privacy_comments={v.get('comment') for kind,v in privacy.objects(state) if kind=='rule'}
            self.assertEqual('auto-privacy:client-tcp-ip' in privacy_comments,'ctrl0' in sources)
            self.assertEqual('auto-privacy:client-tcp-guest' in privacy_comments,'autoap0' in sources)
            self.assertEqual('auto-privacy:input-ip-tor' in privacy_comments,'ctrl0' in sources)
            self.assertEqual('auto-privacy:input-guest-tor' in privacy_comments,'autoap0' in sources)
            self.assertIn('auto-privacy:local-tcp-ip',privacy_comments)
            # Exclusion must override the platform's established-input admission,
            # including DNS sockets opened before the source selection changed.
            for name in set(['ctrl0','autoap0'])-set(sources):
                self.assertIn('auto-share:excluded-dns-'+name+'-tcp',comments)
                self.assertIn('auto-privacy:excluded-'+name,privacy_comments)

    def test_status_shows_both_web_paths_even_while_off(self):
        from contextlib import redirect_stdout
        out=io.StringIO()
        with patch.object(h,'modules',return_value=(None,None,None)),patch.object(h,'load',return_value=None),redirect_stdout(out):
            self.assertEqual(h.status(),0)
        self.assertIn('Web files: /run/automations-hotspot-www',out.getvalue())
        self.assertIn('Template directory: /usr/local/share/automations/hotspot',out.getvalue())
        self.assertIn('Welcome template:',out.getvalue())

    def test_utf8_ssid_boundaries_and_controls(self):
        h.validate_ssid('ä'*16)
        for bad in ('','ä'*17,'evil\ninterface=ctrl0','a\0b'):
            with self.assertRaises(h.Error):h.validate_ssid(bad)

    def test_open_and_wpa2_without_extra_policy(self):
        self.assertIsNone(h.password_psk('','Open'))
        self.assertEqual(len(h.password_psk('a'*8,'SSID')),64)
        self.assertEqual(len(h.password_psk(' '*8,'SSID')),64)
        for value in ('short','x'*64,'ä'*8):
            with self.assertRaises(h.Error):h.password_psk(value,'SSID')

    def test_key_depends_on_ssid_and_is_not_written_as_plaintext(self):
        key=h.password_psk('abcdefgh','First')
        self.assertNotEqual(key,h.password_psk('abcdefgh','Second'))
        config=h.hostapd_config('wlan1','First',key)
        self.assertIn('wpa=2\n',config);self.assertNotIn('abcdefgh',config)
        self.assertIn('ap_isolate=1',config)
        self.assertNotIn('wpa_psk=',h.hostapd_config('wlan0','Open',None))
        with self.assertRaises(h.Error):h.hostapd_config('ctrl0','SSID',None)

    def test_template_escapes_ssid_in_body_and_title(self):
        text=h.render('<title>{{SSID}}</title><h1>{{SSID}}</h1>','<img src=x onerror=1>')
        self.assertNotIn('<img',text);self.assertEqual(text.count('&lt;img'),2)
        with self.assertRaises(h.Error):h.render('no placeholder','SSID')

    def test_service_cannot_start_at_boot_and_cleans_on_exit(self):
        unit=(ROOT/'components/hotspot-control/files/automations-hotspot.service').read_text()
        self.assertNotIn('[Install]',unit);self.assertNotIn('Restart=always',unit)
        self.assertIn('ExecStopPost=',unit);self.assertIn('Type=notify',unit)
        self.assertIn('KillMode=control-group',unit)

    def test_namespace_exposes_no_admin_ports_or_private_routes(self):
        text=h.namespace_firewall('wlan1',share.GUEST)
        self.assertIn('tcp dport {53,80,443}',text)
        self.assertNotIn('dport 22',text);self.assertNotIn('2222',text)
        self.assertIn('policy drop',text);self.assertIn('192.168.0.0/16',text)
        self.assertIn('169.254.0.0/16',text);self.assertIn('10.0.0.0/8',text)

    def test_forged_guest_role_rejected(self):
        self.assertEqual(privacy.GUEST,share.GUEST)
        self.assertEqual(h.support().GUEST,share.GUEST)
        for key,value in [('interface','ctrl0'),('network','10.78.0.0/24'),('peer','8.8.8.8')]:
            selected=copy.deepcopy(BASE);selected['guest']={**share.GUEST,key:value}
            with self.assertRaises(share.Error):share.validate_selection(selected)

    def test_share_guest_is_conditional_and_uses_only_selected_uplink(self):
        old=json.dumps(share.nft_objects(BASE));self.assertNotIn('autoap0',old)
        selected={**copy.deepcopy(BASE),'guest':dict(share.GUEST)}
        share.validate_selection(selected)
        rules=[v for kind,v in share.nft_objects(selected) if kind=='rule']
        own=[x for x in rules if x.get('comment')=='auto-share:guest-out']
        self.assertEqual(len(own),1)
        self.assertIn('wlan0',json.dumps(own));self.assertNotIn('wlan1',json.dumps(own))
        self.assertIn('auto-share:guest-redirect-udp',json.dumps(rules))
        self.assertIn('auto-share:pi-no-fallback-v2',json.dumps(rules))

    def test_tor_intercepts_guest_tcp_and_keeps_default_forward_drop(self):
        state={'version':1,'mode':'tor','uid':120,'selection':{**copy.deepcopy(BASE),'guest':dict(share.GUEST)},'phase':'active'}
        rules=privacy.objects(state)
        forwarded=[v for kind,v in rules if kind=='chain' and v.get('name')=='forward']
        self.assertEqual(forwarded[0]['policy'],'drop')
        guest=[v for kind,v in rules if kind=='rule' and v.get('comment')=='auto-privacy:client-tcp-guest']
        self.assertEqual(len(guest),1);self.assertIn('19040',json.dumps(guest))
        state['phase']='recovering'
        self.assertIn('recovery-close-recovery_input-tcp',json.dumps(privacy.objects(state)))

    def test_no_arbitrary_raw_template_routes_or_logins(self):
        template=(ROOT/'python/templates/hotspot/welcome.html').read_text()
        self.assertIn('Willkommen in',template);self.assertIn('{{SSID}}',template)
        self.assertNotIn('<form',template);self.assertNotIn('<script',template)
        config=h.nginx_config(share.GUEST)
        self.assertIn('10.79.0.1:443',config);self.assertIn('10.79.0.1:80',config)
        self.assertNotIn('proxy_pass',config);self.assertIn('form-action',config)


if __name__=='__main__':unittest.main()
