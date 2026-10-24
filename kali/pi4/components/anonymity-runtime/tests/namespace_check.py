#!/usr/bin/python3
"""Opt-in native test: sudo unshare -n python3 namespace_check.py.

Only a fresh network namespace is accepted. No named namespaces, host network
changes, real network endpoints, service managers or package downloads are used.
Controlled echo backends test routing, not Tor circuits or proxy trust.
"""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import socket
import select
import selectors

ROOT=Path(__file__).resolve().parents[4]


def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value


egress=load('native_egress',ROOT/'pi4/python/egress.py')
fixture=load('native_share_fixture',ROOT/'pi4/components/share-control/tests/test_share_control.py')
share=fixture.share


def run(args,input=None,check=True,timeout=8):
    return subprocess.run(args,input=input,capture_output=True,text=True,check=check,timeout=timeout)


def nft(batch):
    raw=json.dumps({'nftables':batch})
    run(['/usr/sbin/nft','--check','--json','-f','-'],raw)
    run(['/usr/sbin/nft','--json','-f','-'],raw)


def raw_firewall():
    return json.loads(run(['/usr/sbin/nft','-j','list','ruleset']).stdout)


def purge(mark):
    if Path('/usr/sbin/conntrack').exists():
        result=run(['/usr/sbin/conntrack','-D','--mark',str(mark)],check=False)
        assert result.returncode in (0,1),result.stderr
    else:
        # All probes use fresh ephemeral sockets. Existing-flow mark deletion
        # is covered separately by lifecycle fixtures, not this host's tooling.
        print('LIMIT: conntrack CLI unavailable; native existing-flow purge not exercised',flush=True)


def install(state):
    commands=[]
    for kind,value in egress.objects(state):
        if not(kind=='rule' and value.get('table')!=egress.TABLE): commands.append({'add':{kind:value}})
    commands += [{'insert':{'rule':value}} for value in reversed(egress.extension_rules(state))]
    nft(commands)


def remove(state):
    values=egress.check_objects(raw_firewall(),state)
    commands=[{'delete':{'rule':{key:value[key] for key in ('family','table','chain','handle')}}}
              for kind,value in values if kind=='rule' and value.get('table')!=egress.TABLE]
    commands.append({'delete':{'table':{'family':'inet','name':egress.TABLE}}})
    nft(commands)


def roundtrip():
    assert os.geteuid()==0,'Requires root in a fresh network namespace'
    assert os.readlink('/proc/self/ns/net')!=os.readlink('/proc/1/ns/net'),'Refusing init network namespace'
    assert [v['ifname'] for v in json.loads(run(['/usr/sbin/ip','-j','link','show']).stdout)]==['lo'],'Namespace is not empty'
    assert not [x for x in raw_firewall().get('nftables',[]) if 'metainfo' not in x],'Namespace firewall is not empty'
    baseline=fixture.baseline()
    nft([{'add':{kind:{k:v for k,v in value.items() if k!='handle'}}}
         for row in baseline['nftables'] for kind,value in row.items()])
    nft([{'add':{'table':{'family':'inet','name':'auto_share'}}},
         {'add':{'chain':{'family':'inet','table':'auto_share','name':'egress','type':'filter','hook':'output','prio':10,'policy':'accept'}}}])
    selection=copy.deepcopy(fixture.SELECTION)
    selection['ipv6']={'addresses':['2001:db8:1::2'],'address':'2001:db8:1::2','network':'2001:db8:1::/64','gateway':'fe80::1'}
    for mode in ('tor','proxy'):
        for phase in (('starting','recovering','active','blocked') if mode=='tor' else ('starting','blocked')):
            state={'version':1,'mode':mode,'uid':60001 if mode=='tor' else 60002,'phase':phase,'selection':selection}
            install(state)
            try:
                egress.check_objects(raw_firewall(),state)
            except BaseException:
                print(json.dumps({'state':state,'firewall':raw_firewall()}))
                raise
            remove(state)
    print('PASS: native Tor/proxy dual-stack rules and blocked guards round-trip exactly',flush=True)
    nft([{'delete':{'table':{'family':'inet','name':'auto_share'}}}])
    return selection


TARGET4,TARGET6='203.0.113.8','2001:db8:ffff::8'


def server(mode):
    # Mock backends have no route-changing or service-manager code. A distinct
    # numeric UID exercises the actual skuid filters without creating accounts.
    if mode=='backend': os.setgroups([]);os.setgid(60002);os.setuid(60002)
    if mode=='frontend': os.setgroups([]);os.setgid(65534);os.setuid(65534)
    registrations=[]
    selector=selectors.DefaultSelector()
    if mode=='backend': ports=[(19081,'private-tcp'),(19040,'private-tcp'),
                              (19050,'probe-socks'),(19053,'private-dns')]
    elif mode=='frontend': ports=[(1053,'frontend')]
    elif mode=='control': ports=[(443,'control'),(2222,'shell')]
    else: ports=[(443,mode),(53,mode)]
    for port,label in ports:
        hosts=((socket.AF_INET,'0.0.0.0'),(socket.AF_INET6,'::'))
        # A UDP reply from an unconnected wildcard socket would use the link
        # address, not the queried destination, and a connected DNS probe drops
        # that unrelated source. These mock Internet endpoints own TARGET4/6.
        if mode in ('selected','alternate'):hosts=((socket.AF_INET,TARGET4),(socket.AF_INET6,TARGET6))
        if port==19053:hosts=((socket.AF_INET,'127.0.0.1'),(socket.AF_INET6,'::1'))
        if port==1053:hosts=((socket.AF_INET,'10.78.0.1'),(socket.AF_INET,'127.0.0.1'),
                            (socket.AF_INET6,'::1'),(socket.AF_INET6,'fd12:3456:789a:1::1'))
        for family,host in hosts:
            for kind in (socket.SOCK_STREAM,socket.SOCK_DGRAM):
                sock=socket.socket(family,kind)
                sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
                if family==socket.AF_INET6:sock.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
                sock.bind((host,port))
                if kind==socket.SOCK_STREAM:sock.listen(16)
                selector.register(sock,selectors.EVENT_READ,(kind,label,family));registrations.append(sock)
    print('ready',flush=True)
    def reply(label,family,data):
        if label!='frontend':return label.encode()
        if data==b'pi4':return b'10.78.0.1'
        with socket.socket(family,socket.SOCK_DGRAM) as upstream:
            upstream.settimeout(1)
            upstream.sendto(data,(TARGET4 if family==socket.AF_INET else TARGET6,53))
            return upstream.recvfrom(1024)[0]
    while True:
        for key,_ in selector.select(1):
            kind,label,family=key.data;sock=key.fileobj
            try:
                if kind==socket.SOCK_DGRAM:
                    data,peer=sock.recvfrom(1024);sock.sendto(reply(label,family,data),peer)
                else:
                    connection,_=sock.accept();connection.settimeout(1)
                    with connection:
                        data=connection.recv(1024);connection.sendall(reply(label,family,data))
            except (OSError,TimeoutError):pass


def probe(target,port,udp,uid):
    if uid>=0:os.setgroups([]);os.setgid(uid);os.setuid(uid)
    family=socket.AF_INET6 if ':' in target else socket.AF_INET
    with socket.socket(family,socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as sock:
        sock.settimeout(1)
        sock.connect((target,port));sock.send(b'probe');print(sock.recv(1024).decode(),flush=True)


def packets(selection):
    children=[]
    def ip(*args):return run(['/usr/sbin/ip',*args])
    def remote(process,args,check=True):
        return run(['/usr/bin/nsenter','-t',str(process.pid),'-n','--',*args],check=check)
    def start(mode,space=None):
        argv=['/usr/bin/python3',str(Path(__file__).resolve()),'--serve',mode]
        if space:argv=['/usr/bin/nsenter','-t',str(space.pid),'-n','--',*argv]
        process=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        children.append(process)
        assert select.select([process.stdout],[],[],3)[0] and process.stdout.readline().strip()=='ready',mode
        return process
    def request(target,port,expected,space=None,uid=60003,udp=False):
        argv=['/usr/bin/python3',str(Path(__file__).resolve()),'--probe',target,str(port),str(int(udp)),str(uid)]
        result=remote(space,argv,False) if space else run(argv,check=False)
        if expected is None:assert result.returncode!=0,(target,port,result.stdout)
        else:assert result.returncode==0 and result.stdout.strip()==expected,(target,port,result.stdout,result.stderr)
    try:
        spaces=[]
        for _ in range(3):
            child=subprocess.Popen(['/usr/bin/unshare','-n','/usr/bin/sleep','180']);children.append(child);spaces.append(child)
            for _ in range(100):
                if os.readlink(f'/proc/{child.pid}/ns/net')!=os.readlink('/proc/self/ns/net'):break
                time.sleep(.01)
            else:raise AssertionError('Child namespace failed to start')
        client,selected,alternate=spaces
        for local,peer,space,a,b,v6a,v6b in (
            ('ctrl0','client0',client,'10.78.0.1/24','10.78.0.20/24',selection['control6']['address']+'/64','fd12:3456:789a:1::20/64'),
            ('eth0','wan0',selected,'192.168.1.2/24','192.168.1.1/24','2001:db8:1::2/64','2001:db8:1::1/64'),
            ('eth1','wan1',alternate,'192.168.2.2/24','192.168.2.1/24','2001:db8:2::2/64','2001:db8:2::1/64')):
            ip('link','add',local,'type','veth','peer','name',peer);ip('link','set',peer,'netns',str(space.pid))
            ip('address','add',a,'dev',local);ip('-6','address','add',v6a,'dev',local,'nodad');ip('link','set',local,'up')
            remote(space,['/usr/sbin/ip','address','add',b,'dev',peer]);remote(space,['/usr/sbin/ip','-6','address','add',v6b,'dev',peer,'nodad'])
            remote(space,['/usr/sbin/ip','link','set',peer,'up']);remote(space,['/usr/sbin/ip','link','set','lo','up'])
        ip('link','set','lo','up')
        ip('-6','address','add',selection['control6']['linklocal']+'/64','dev','ctrl0','nodad')
        remote(selected,['/usr/sbin/ip','-6','address','add','fe80::1/64','dev','wan0','nodad'])
        for space in (selected,alternate):
            remote(space,['/usr/sbin/ip','address','add',TARGET4+'/32','dev','lo'])
            remote(space,['/usr/sbin/ip','-6','address','add',TARGET6+'/128','dev','lo','nodad'])
        remote(client,['/usr/sbin/ip','route','add','default','via','10.78.0.1'])
        remote(client,['/usr/sbin/ip','-6','route','add','default','via',selection['control6']['address']])
        ip('route','add','default','via','192.168.2.1','dev','eth1');ip('-6','route','add','default','via','2001:db8:2::1','dev','eth1')
        # These files refer to this freshly created network namespace only.
        Path('/proc/sys/net/ipv6/conf/all/forwarding').write_text('1\n')
        for dev in ('ctrl0','eth0'):Path('/proc/sys/net/ipv4/conf/'+dev+'/forwarding').write_text('1\n')
        platform=share.Platform();platform.add_routes(selection);platform.routes_check(selection)
        nft(share.nft_add(selection)['nftables'])
        start('selected',selected);start('alternate',alternate)
        backend=start('backend');start('frontend');start('control')
        # Ordinary share before privacy. The unused alternate uplink is live.
        request(TARGET4,443,'selected');request(TARGET6,443,'selected')
        request(TARGET4,443,'selected',client);request(TARGET6,443,'selected',client)
        state={'version':1,'mode':'proxy','uid':60002,'phase':'starting','selection':selection}
        install(state);egress.check_objects(raw_firewall(),state)
        purge(share.MARK)
        for space in (None,client):
            for target in (TARGET4,TARGET6):
                request(target,443,'private-tcp',space)
                request(target,53,'private-dns',space,udp=True)
                request(target,53,'private-dns',space)
                request(target,443,None,space,udp=True)
        for target in (TARGET4,TARGET6):request(target,443,'selected',uid=60002)
        request('10.78.0.1',443,'control',client);request('127.0.0.1',2222,'shell')
        # A control client cannot bypass redirect guards by directly reaching the
        # privileged listener port, and no upstream peer can reach it either.
        request('10.78.0.1',19081,None,client);request('192.168.1.2',19081,None,selected)
        print('PASS: Pi/client IPv4+IPv6 TCP and DNS are intercepted; UDP and direct backend ingress are blocked',flush=True)
        backend.terminate();backend.wait(timeout=3)
        request(TARGET4,443,None);request(TARGET6,443,None,client)
        print('PASS: backend loss blocks application traffic without direct fallback',flush=True)
        remove(state);blocked={**state,'phase':'blocked'};install(blocked)
        request(TARGET4,443,None,uid=60002);request(TARGET6,443,None,uid=60002)
        request('10.78.0.1',443,'control',client);request('127.0.0.1',2222,'shell')
        remove(blocked);purge(egress.MARK)
        request(TARGET4,443,'selected');request(TARGET6,443,'selected',client)
        print('PASS: blocked mode also closes transport egress; explicit removal restores selected share and control access',flush=True)
        # Test IPv4-only Tor transport with the same deterministic backends.
        backend=start('backend')
        tor={**state,'mode':'tor','uid':60002}
        install(tor)
        for phase in ('starting','recovering','blocked','active'):
            remove(tor)
            tor={**tor,'phase':phase}
            install(tor);purge(egress.MARK)
            for space in (None,client):
                request(TARGET4,443,'private-tcp' if phase=='active' else None,space)
                request(TARGET4,53,'private-dns' if phase=='active' else None,space,udp=True)
            request('127.0.0.1',19050,'probe-socks',uid=0)
            request('127.0.0.1',19050,'probe-socks' if phase=='active' else None)
            request(TARGET4,443,None if phase=='blocked' else 'selected',uid=60002)
            request('10.78.0.1',443,'control',client);request('127.0.0.1',2222,'shell')
        print('PASS: Tor startup/recovery gates Pi/client TCP and DNS, permits only privileged SOCKS probe and Tor bootstrap; local access stays usable',flush=True)
        request(TARGET6,443,None);request(TARGET6,443,None,client)
        request(TARGET6,443,None,uid=60002)
        request(TARGET4,53,None,uid=65534)
        remove(tor)
        print('PASS: Tor mode blocks external application IPv6 and DNS-over-TCP transport',flush=True)
        # Uplink loss still cannot select the usable eth1 main default.
        install(state);ip('link','set','eth0','down')
        request(TARGET4,443,None,uid=60002);request(TARGET6,443,None,uid=60002)
        print('PASS: loss of selected uplink cannot fall back to the live alternate',flush=True)
    finally:
        for process in reversed(children):
            if process.poll() is None:process.terminate()
        for process in reversed(children):
            try:process.wait(timeout=3)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=3)


def main():
    assert os.geteuid()==0 and os.readlink('/proc/self/ns/net')!=os.readlink('/proc/1/ns/net'), 'Fresh isolated root namespace required'
    if len(sys.argv)>1 and sys.argv[1]=='--serve':server(sys.argv[2]);return
    if len(sys.argv)>1 and sys.argv[1]=='--probe':probe(sys.argv[2],int(sys.argv[3]),bool(int(sys.argv[4])),int(sys.argv[5]));return
    packets(roundtrip())


if __name__=='__main__':main()
