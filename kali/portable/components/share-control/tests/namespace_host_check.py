#!/usr/bin/env python3
"""Native isolated proof: sudo unshare -n python3 namespace_host_check.py.

Refuses the init namespace and any pre-existing non-loopback link. Uses only
namespace-local veths, fake DNS endpoints and documentation addresses. No host
interface, host firewall, named netns, runtime service or real Internet is used.
"""
import importlib.util
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import time
from types import SimpleNamespace
import uuid

ROOT = Path(__file__).resolve().parents[4]
SPEC = importlib.util.spec_from_file_location('native_host_share', ROOT / 'portable/python/host_share.py')
share = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(share)

def command(*args, check=True):
    result = subprocess.run(args, check=False, text=True, capture_output=True, timeout=8)
    if check and result.returncode: raise AssertionError(str(args) + '\n' + result.stderr)
    return result
def ip(*args): return command(share.IP, *args)
def remote(process, *args, check=True):
    return command('/usr/bin/nsenter', '-t', str(process.pid), '-n', '--', *args, check=check)

def main():
    assert os.geteuid() == 0
    assert os.readlink('/proc/self/ns/net') != os.readlink('/proc/1/ns/net'), 'Refusing init namespace'
    assert [row['ifname'] for row in json.loads(ip('-j', 'link', 'show').stdout)] == ['lo'], 'Namespace is not empty'
    assert not [item for item in json.loads(command(share.NFT, '-j', 'list', 'ruleset').stdout)['nftables'] if 'metainfo' not in item]
    Path('/proc/sys/net/ipv4/conf/all/forwarding').write_text('0\n')
    children, servers = [], []
    profile = SimpleNamespace(platform='kali-host', configured=True, protected_interfaces=(), identity='a' * 64)
    def diagnostic(args, input_text=None):
        result = share.run(args, input_text)
        if result.returncode: raise AssertionError(result.stderr)
        return result
    backend = share.HostShare(profile, runner=diagnostic)
    try:
        for _ in range(3):
            child = subprocess.Popen(['/usr/bin/unshare', '-n', '/usr/bin/sleep', '120'])
            children.append(child)
            for _ in range(100):
                if os.readlink('/proc/' + str(child.pid) + '/ns/net') != os.readlink('/proc/self/ns/net'): break
                time.sleep(.01)
            else: raise AssertionError('Child namespace did not start')
        selected, alternate, client = children
        bindings = {}
        for name, peer, process, address, peer_address in (
                ('hswan0', 'peer0', selected, '192.0.2.2', '192.0.2.1'),
                ('hsalt0', 'peer1', alternate, '203.0.113.2', '203.0.113.1'),
                ('hsclient0', 'peer2', client, '10.42.0.1', '10.42.0.2')):
            ip('link', 'add', name, 'type', 'veth', 'peer', 'name', peer)
            ip('link', 'set', peer, 'netns', str(process.pid))
            ip('address', 'add', address + '/24', 'dev', name)
            ip('link', 'set', name, 'up')
            remote(process, share.IP, 'address', 'add', peer_address + '/24', 'dev', peer)
            remote(process, share.IP, 'link', 'set', peer, 'up')
            remote(process, share.IP, 'link', 'set', 'lo', 'up')
            index = json.loads(ip('-j', 'link', 'show', name).stdout)[0]['ifindex']
            bindings[name] = dict(name=name, ifindex=index, address=address, network=address.rsplit('.', 1)[0] + '.0/24',
                                  device_path='sys/devices/namespace/' + name, mac='02:00:00:00:00:01', wireless=False)
            Path('/proc/sys/net/ipv4/conf/' + name + '/forwarding').write_text('0\n')
        ip('link', 'set', 'lo', 'up')
        ip('route', 'add', 'default', 'via', '203.0.113.1', 'dev', 'hsalt0')
        remote(client, share.IP, 'route', 'add', 'default', 'via', '10.42.0.1')
        for process in (selected, alternate): remote(process, share.IP, 'address', 'add', '198.18.0.1/32', 'dev', 'lo')
        before = ip('-j', '-4', 'route', 'show', 'table', 'main').stdout
        # Independent table must survive every transaction unchanged.
        backend.nft([{'add': {'table': {'family': 'inet', 'name': 'namespace_sentinel', 'comment': 'untouched'}}}])
        server_code = '''import socket,threading,time,sys
label=sys.argv[1].encode()
def serve_udp(port):
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('198.18.0.1' if port==4242 else '0.0.0.0',port))
 while True:
  data,address=s.recvfrom(4096);s.sendto(label,address)
def serve_tcp():
 s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',53));s.listen()
 while True:
  c,a=s.accept();c.recv(4096);c.sendall(label);c.close()
for port in (53,4242):threading.Thread(target=serve_udp,args=(port,),daemon=True).start()
threading.Thread(target=serve_tcp,daemon=True).start()
time.sleep(.1);print('READY',flush=True);time.sleep(110)
'''
        for process, label in ((selected, 'selected'), (alternate, 'alternate')):
            server = subprocess.Popen(['/usr/bin/nsenter', '-t', str(process.pid), '-n', '--', '/usr/bin/python3', '-c', server_code, label], stdout=subprocess.PIPE, text=True)
            servers.append(server)
            assert select.select([server.stdout], [], [], 5)[0] and server.stdout.readline().strip() == 'READY'
        udp_probe = "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2);s.sendto(b'probe',('198.18.0.1',4242));assert s.recvfrom(32)[0]==b'selected'"
        dns_probe = "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2);s.sendto(b'probe',('198.18.0.99',53));assert s.recvfrom(32)==(b'selected',('198.18.0.99',53))"
        tcp_probe = "import socket;s=socket.create_connection(('198.18.0.99',53),2);s.sendall(b'probe');assert s.recv(32)==b'selected'"
        for with_client in (False, True):
            selection = dict(mode='lan', uplink=bindings['hswan0'], clients=[bindings['hsclient0']] if with_client else [],
                             gateway='192.0.2.1', dns=['192.0.2.1'])
            state = dict(selection=selection, run_id=str(uuid.uuid4()), forwarding={'hswan0': '0', 'hsclient0': '0'} if with_client else {})
            objects = [{'add': item} for item in share.nft_objects(state)]
            backend.nft(objects, check=True)
            backend.nft(objects)
            for row in share.routes(state): backend.command([share.IP, '-4', 'route', 'add', *share.route_args(row)])
            rule = ['priority', str(share.PRIORITY), 'fwmark', hex(share.MARK) + '/' + hex(share.MARK),
                    'lookup', str(share.TABLE), 'protocol', str(share.PROTOCOL)]
            backend.command([share.IP, '-4', 'rule', 'add', *rule])
            try:
                actual = backend.objects(state)
            except share.Error:
                print('ROUTES', backend.ip('-4', 'route', 'show', 'table', 'all'), 'EXPECTED ROUTES', share.routes(state), flush=True)
                print('RULES', backend.ip('-4', 'rule', 'show'), flush=True)
                observed = backend.canonical_nft([backend.clean_object(item) for item in backend.firewall()
                    if next(iter(item.values())).get('table', next(iter(item.values())).get('name')) == share.NFT_TABLE])
                expected = backend.canonical_nft(share.nft_objects(state))
                for wanted, found in zip(expected, observed):
                    if wanted != found: print('EXPECTED', wanted, 'ACTUAL', found, flush=True)
                raise
            assert actual[0] == backend.canonical_nft(share.nft_objects(state))
            assert len(actual[1]) == len(share.routes(state)) and len(actual[2]) == 1
            for name in state['forwarding']: backend.forwarding(name, '1')
            assert Path('/proc/sys/net/ipv4/conf/all/forwarding').read_text().strip() == '0'
            command('/usr/bin/python3', '-c', udp_probe)
            command('/usr/bin/python3', '-c', dns_probe)
            command('/usr/bin/python3', '-c', tcp_probe)
            if with_client:
                remote(client, '/usr/bin/python3', '-c', udp_probe)
                remote(client, '/usr/bin/python3', '-c', dns_probe)
                remote(client, '/usr/bin/python3', '-c', tcp_probe)
            else:
                assert remote(client, '/usr/bin/python3', '-c', udp_probe, check=False).returncode != 0
            # Removing only the usable owned default must never select the alternate.
            usable = next(row for row in share.routes(state) if row.get('gateway'))
            backend.command([share.IP, '-4', 'route', 'del', *share.route_args(usable)])
            assert command('/usr/bin/python3', '-c', udp_probe, check=False).returncode != 0
            backend.command([share.IP, '-4', 'route', 'add', *share.route_args(usable)])
            # Clean only verified objects, in the same ordering as production.
            backend.objects(state)
            for name, previous in state['forwarding'].items(): backend.forwarding(name, previous)
            backend.command([share.IP, '-4', 'rule', 'del', *rule])
            for row in reversed(share.routes(state)): backend.command([share.IP, '-4', 'route', 'del', *share.route_args(row)])
            backend.nft([{'delete': {'table': {'family': 'inet', 'name': share.NFT_TABLE}}}])
            backend.objects()
            assert ip('-j', '-4', 'route', 'show', 'table', 'main').stdout == before
            print('PASS: native ' + ('explicit-client' if with_client else 'host-only') + ' routing, TCP/UDP DNS, no fallback, ownership and cleanup', flush=True)
        print('PASS: all operations stayed in disposable network namespaces', flush=True)
    finally:
        for process in servers + children:
            process.terminate()
        for process in servers + children:
            try: process.wait(timeout=3)
            except subprocess.TimeoutExpired: process.kill(); process.wait()

if __name__ == '__main__': main()
