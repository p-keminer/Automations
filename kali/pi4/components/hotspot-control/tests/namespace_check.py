#!/usr/bin/python3
"""Opt-in packet acceptance in fresh namespaces, never the host network.

Run: sudo unshare -n python3 pi4/components/hotspot-control/tests/namespace_check.py
Uses real nft/NAT/routing and mock TCP/DNS backends, not radio/captive-OS tests.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[4]
def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
n=load('hotspot_native_privacy',ROOT/'pi4/components/anonymity-runtime/tests/namespace_check.py')
h=load('hotspot_native_controller',ROOT/'pi4/python/auto_hotspot.py')
share=n.share


def main():
    assert os.geteuid()==0 and os.readlink('/proc/self/ns/net')!=os.readlink('/proc/1/ns/net'),'Fresh root namespace required'
    assert [v['ifname'] for v in json.loads(n.run(['/usr/sbin/ip','-j','link']).stdout)]==['lo'],'Namespace is not empty'
    assert not [x for x in n.raw_firewall().get('nftables',[]) if 'metainfo' not in x],'Namespace firewall is not empty'
    children=[]
    trace=tempfile.TemporaryFile(mode='w+')
    def ip(*args):return n.run(['/usr/sbin/ip',*args])
    def remote(space,args,check=True,input=None):
        return n.run(['/usr/bin/nsenter','-t',str(space.pid),'-n','--',*args],input,check)
    def start(mode,space=None,code=None):
        argv=['/usr/bin/python3',str(Path(n.__file__).resolve()),'--serve',mode] if code is None else ['/usr/bin/python3','-u','-c',code]
        if space:argv=['/usr/bin/nsenter','-t',str(space.pid),'-n','--',*argv]
        process=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);children.append(process)
        if not(select.select([process.stdout],[],[],4)[0] and process.stdout.readline().strip()=='ready'):
            raise AssertionError((mode,process.poll(),process.stderr.read() if process.poll() is not None else 'startup deadline'))
        return process
    def request(target,port,expected,space=None,udp=False):
        argv=['/usr/bin/python3',str(Path(n.__file__).resolve()),'--probe',target,str(port),str(int(udp)),'60003']
        r=remote(space,argv,False) if space else n.run(argv,check=False)
        ok=r.returncode!=0 if expected is None else r.returncode==0 and r.stdout.strip()==expected
        if not ok:
            print('Probe failure namespace: '+str(space.pid if space else 'root'),flush=True)
            if Path('/usr/sbin/conntrack').exists():print(n.run(['/usr/sbin/conntrack','-L'],check=False).stdout,flush=True)
            print(n.run(['/usr/sbin/ip','route','get',n.TARGET4,'uid','65534'],check=False).stdout,flush=True)
            print(n.run(['/usr/bin/ss','-lunp'],check=False).stdout,flush=True)
            trace.flush();trace.seek(0);print(trace.read(24000),flush=True)
        assert ok,(target,port,expected,r.stdout,r.stderr)
    try:
        spaces=[]
        for _ in range(5):
            child=subprocess.Popen(['/usr/bin/unshare','-n','/usr/bin/sleep','240']);children.append(child);spaces.append(child)
            for _ in range(100):
                if os.readlink(f'/proc/{child.pid}/ns/net')!=os.readlink('/proc/self/ns/net'):break
                time.sleep(.01)
            else:raise AssertionError('Child namespace did not start')
        control,guest,gateway,selected,alternate=spaces
        for local,peer,space,a,b in (
            ('ctrl0','ctrlpeer',control,'10.78.0.1/24','10.78.0.20/24'),
            ('eth0','wan0',selected,'192.168.1.2/24','192.168.1.1/24'),
            ('eth1','wan1',alternate,'192.168.2.2/24','192.168.2.1/24'),
            ('autoap0','ap-uplink',gateway,'169.254.95.1/30','169.254.95.2/30')):
            ip('link','add',local,'type','veth','peer','name',peer);ip('link','set',peer,'netns',str(space.pid))
            ip('address','add',a,'dev',local);ip('link','set',local,'up')
            remote(space,['/usr/sbin/ip','address','add',b,'dev',peer]);remote(space,['/usr/sbin/ip','link','set',peer,'up'])
        for space in spaces:remote(space,['/usr/sbin/ip','link','set','lo','up'])
        ip('link','set','lo','up')
        # Real netlink identity/loss/reuse checks for the AP worker. The PHY
        # directory is a fixture; USB/radio removal remains a hardware test.
        with tempfile.TemporaryDirectory() as phy:
            def inside_gateway(*args,**kw):return remote(gateway,list(args)).stdout
            remote(gateway,['/usr/sbin/ip','link','add','watchtest','type','veth','peer','name','watchpeer'])
            rows=json.loads(remote(gateway,['/usr/sbin/ip','-j','link','show','dev','watchtest']).stdout)
            saved={'adapter':['watchtest',rows[0]['ifindex'],'phy2',phy,phy,'148f:3572']}
            with patch.object(h,'inside',side_effect=inside_gateway):
                assert h.namespace_link('watchtest')['ifindex']==saved['adapter'][1],'Recorded interface was not detected'
                remote(gateway,['/usr/sbin/ip','link','delete','watchtest'])
                assert h.namespace_link('watchtest') is None,'Missing interface still appeared present'
                remote(gateway,['/usr/sbin/ip','link','add','watchtest','type','veth','peer','name','watchpeer'])
                assert h.namespace_link('watchtest')['ifindex']!=saved['adapter'][1],'Reused name admitted another interface instance'
                remote(gateway,['/usr/sbin/ip','link','delete','watchtest'])
        # The gateway's wlan1 is a simulated AP link, with the production firewall.
        remote(gateway,['/usr/sbin/ip','link','add','wlan1','type','veth','peer','name','station'])
        remote(gateway,['/usr/sbin/ip','link','set','station','netns',str(guest.pid)])
        remote(gateway,['/usr/sbin/ip','address','add','10.79.0.1/24','dev','wlan1'])
        remote(gateway,['/usr/sbin/ip','link','set','wlan1','up'])
        remote(guest,['/usr/sbin/ip','address','add','10.79.0.20/24','dev','station'])
        remote(guest,['/usr/sbin/ip','link','set','station','up'])
        remote(guest,['/usr/sbin/ip','route','add','default','via','10.79.0.1'])
        remote(control,['/usr/sbin/ip','route','add','default','via','10.78.0.1'])
        remote(gateway,['/usr/sbin/ip','route','add','default','via','169.254.95.1'])
        remote(gateway,['/usr/sbin/sysctl','-q','-w','net.ipv4.ip_forward=1','net.ipv6.conf.all.disable_ipv6=1'])
        remote(gateway,['/usr/sbin/nft','-f','-'],input=h.namespace_firewall('wlan1',share.GUEST))
        ip('route','add','10.79.0.0/24','via','169.254.95.2','dev','autoap0')
        for space in (selected,alternate):
            remote(space,['/usr/sbin/ip','address','add',n.TARGET4+'/32','dev','lo'])
            remote(space,['/usr/sbin/ip','-6','address','add',n.TARGET6+'/128','dev','lo','nodad'])
        ip('route','add','default','via','192.168.2.1','dev','eth1')
        ip('-6','address','add',n.fixture.SELECTION['control6']['address']+'/64','dev','ctrl0','nodad')
        for name in ('ctrl0','eth0','autoap0'):Path('/proc/sys/net/ipv4/conf/'+name+'/forwarding').write_text('1\n')
        baseline=n.fixture.baseline()
        n.nft([{'add':{kind:{k:v for k,v in value.items() if k!='handle'}}} for row in baseline['nftables'] for kind,value in row.items()])
        n.nft([{'add':{'table':{'family':'inet','name':'test_trace'}}}]+[
            command for name,hook in [('pre','prerouting'),('out','output')] for command in (
                {'add':{'chain':{'family':'inet','table':'test_trace','name':name,'type':'filter','hook':hook,'prio':-301,'policy':'accept'}}},
                {'add':{'rule':{'family':'inet','table':'test_trace','chain':name,'expr':[
                    share.payload('udp','dport',{'set':[53,1053]}),{'mangle':{'key':{'meta':{'key':'nftrace'}},'value':1}}]}}})])
        monitor=subprocess.Popen(['/usr/sbin/nft','monitor','trace'],stdout=trace,stderr=trace,text=True);children.append(monitor)
        start('selected',selected);start('alternate',alternate);start('control');start('frontend');start('backend')
        # Deliberately listening on 22 in the guest namespace proves a firewall
        # denial, rather than relying on a missing SSH daemon.
        start('welcome',gateway,code='''import selectors,socket
s=selectors.DefaultSelector()
for p in (22,80,443):
 a=socket.socket();a.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);a.bind(("0.0.0.0",p));a.listen(8);s.register(a,selectors.EVENT_READ)
print("ready",flush=True)
while True:
 for k,_ in s.select():
  c,_=k.fileobj.accept()
  with c:c.recv(64);c.sendall(b"welcome")
''')
        platform=share.Platform()
        for sources in (['ctrl0','autoap0'],['autoap0'],['ctrl0'],[]):
            selection={**copy.deepcopy(n.fixture.SELECTION),'dns':[n.TARGET4],'guest':dict(share.GUEST),'sources':sources}
            share.validate_selection(selection);platform.add_routes(selection)
            n.nft(share.nft_add(selection)['nftables'])
            share.firewall_check(n.raw_firewall(),selection);platform.routes_check(selection)
            for space,role in ((control,'ctrl0'),(guest,'autoap0')):
                enabled=role in sources
                request(n.TARGET4,443,'selected' if enabled else None,space)
                request(n.TARGET4,53,'selected' if enabled else None,space,udp=True)
                request(n.TARGET4,53,'selected' if enabled else None,space)
                request('10.78.0.1',1053,None,space) if not enabled else None
            request(n.TARGET4,443,'selected')
            request('10.79.0.1',80,'welcome',guest);request('10.79.0.1',443,'welcome',guest)
            for target,port in (('10.79.0.1',22),('10.78.0.1',443),('169.254.95.1',443),('192.168.1.1',443)):
                request(target,port,None,guest)
            request('10.78.0.1',443,'control',control)
            for phase in ('active','recovering'):
                state={'version':1,'mode':'tor','uid':60002,'phase':phase,'selection':selection}
                n.install(state);n.egress.check_objects(n.raw_firewall(),state);n.purge(share.MARK)
                for space,role in ((control,'ctrl0'),(guest,'autoap0')):
                    enabled=role in sources and phase=='active'
                    request(n.TARGET4,443,'private-tcp' if enabled else None,space)
                    request(n.TARGET4,53,'private-dns' if enabled else None,space,udp=True)
                    request(n.TARGET4,443,None,space,udp=True)
                    request('10.78.0.1',19040,None,space)
                request(n.TARGET4,443,'private-tcp' if phase=='active' else None)
                n.remove(state);n.purge(n.egress.MARK)
            n.nft(share.nft_delete(n.raw_firewall(),selection)['nftables']);platform.remove_routes(selection)
            n.purge(share.MARK)
            print('PASS: source selection '+str(sources)+'; IPv4 TCP/DNS, Tor/recovery, local access and guest isolation',flush=True)
        request(n.TARGET4,443,None,guest);request(n.TARGET4,443,None,control)
        request('10.79.0.1',80,'welcome',guest)
        print('PASS: share off preserves the welcome page and blocks guest Internet',flush=True)
    finally:
        for process in reversed(children):
            if process.poll() is None:process.terminate()
        for process in reversed(children):
            try:process.wait(timeout=3)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=3)


if __name__=='__main__':main()
