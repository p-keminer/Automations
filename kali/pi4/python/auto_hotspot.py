#!/usr/bin/python3
"""Runtime-only USB welcome AP. The protected ctrl0 AP is never repurposed."""
from __future__ import annotations
import argparse
from contextlib import contextmanager
import fcntl
import getpass
import hashlib
import html
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import sys
import time
import warnings

BASE = Path('/run/automations-hotspot')
WEB = Path('/run/automations-hotspot-www')
NS = 'auto-hotspot'
UNIT = 'automations-hotspot.service'
WORKER = '/usr/local/libexec/automations-support/hotspot.py'
TEMPLATES = Path('/usr/local/share/automations/hotspot/templates')
STATE = BASE/'state.json'
CHANNEL = 6


class Error(RuntimeError): pass


def require(value, message):
    if not value: raise Error(message)


def trusted(path, *, directory=False):
    path=Path(path)
    for p in (path,*path.parents):
        s=p.lstat()
        require(not stat.S_ISLNK(s.st_mode) and s.st_uid==0 and not s.st_mode&0o022,
                'Unsafe AP file ownership, permissions or path.')
    require(path.is_dir() if directory else path.is_file() and path.stat().st_nlink==1,
            'Unexpected AP file type.')
    return path


def support():
    p=(Path(__file__).resolve().parents[2] / 'common/python/adapter_selection.py') if Path(__file__).name=='auto_hotspot.py' else trusted('/usr/local/libexec/automations-support/adapter_selection.py')
    spec=importlib.util.spec_from_file_location('_hotspot_support',p)
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    return m


def modules():
    s=support()
    return (s,s.load_peer('auto_wifi.py','/usr/local/libexec/automations/wifi','_hotspot_wifi'),
            s.load_peer('auto_share.py','/usr/local/libexec/automations/share','_hotspot_share'))


def portal():
    return support().load_peer('portal_templates.py',
        '/usr/local/libexec/automations-support/portal_templates.py', '_hotspot_portal')


def run(args, *, text=None, accepted=(0,), timeout=25):
    try:
        p=subprocess.run(args,input=text,text=True,capture_output=True,timeout=timeout,
            env={**os.environ,'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
    except (OSError,subprocess.TimeoutExpired):
        raise Error('An AP system command is unavailable or timed out.') from None
    label=Path(args[0]).name
    if label=='ip':
        command=args[4:] if len(args)>4 and args[1:3]==['netns','exec'] else args
        label+=' '+Path(command[0]).name+' '+ ' '.join(command[1:3]) if command is not args else ' '+' '.join(args[1:3])
    require(p.returncode in accepted,label+' failed; no configuration or password was disclosed.')
    return p.stdout


def inside(*args, **kw): return run(['/usr/sbin/ip','netns','exec',NS,*args],**kw)


def write_private(path, value):
    path=Path(path)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,'w',encoding='utf-8') as f:
        s=os.fstat(f.fileno())
        require(s.st_uid==0 and s.st_nlink==1 and stat.S_ISREG(s.st_mode) and stat.S_IMODE(s.st_mode)==0o600,'Unsafe AP state file.')
        f.write(value)


def save(value): write_private(STATE,json.dumps(value,ensure_ascii=True)+'\n')


def load():
    if not STATE.exists(): return None
    p=trusted(STATE)
    require(p.stat().st_size<=65536 and stat.S_IMODE(p.stat().st_mode)==0o600,'Unsafe AP state.')
    s=json.loads(p.read_text())
    require(s.get('version')==1 and s.get('boot_id')==Path('/proc/sys/kernel/random/boot_id').read_text().strip(), 'Invalid AP boot identity.')
    require(isinstance(s.get('adapter'),list) and len(s['adapter'])==6 and s['adapter'][0]!='ctrl0'
        and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}',s['adapter'][0])
        and re.fullmatch(r'phy[0-9]+',s['adapter'][2]) and re.fullmatch(r'[0-9a-f]{4}:[0-9a-f]{4}',s['adapter'][5]),'Invalid external AP identity.')
    validate_ssid(s['ssid'])
    require(s.get('security') in ('open','WPA2-PSK') and s.get('phase') in ('starting','active')
        and isinstance(s.get('steps'),list) and all(isinstance(x,str) for x in s['steps'])
        and ('radio_index' not in s or type(s['radio_index']) is int and s['radio_index']>0)
        and len(s['steps'])==len(set(s['steps'])) and set(s['steps']) <= {'namespace','radio','veth','route'}
        and type(s.get('original_managed')) is bool and type(s.get('original_autoconnect')) is bool
        and (s.get('original_connection') is None or re.fullmatch(r'[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}',s['original_connection'])),'Invalid AP state.')
    if 'template' in s:
        require(isinstance(s['template'],str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',s['template'])
            and re.fullmatch(r'[0-9a-f]{64}',s.get('template_sha256','')),'Invalid AP portal identity.')
        portal().validate_manifest(s.get('portal_files'))
    return s


@contextmanager
def locked():
    fd=os.open('/run/automations-hotspot.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    try:
        info=os.fstat(fd)
        require(info.st_uid==0 and info.st_nlink==1 and stat.S_IMODE(info.st_mode)==0o600 and stat.S_ISREG(info.st_mode),'Unsafe AP lock.')
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise Error('Another AP operation is running.') from None
        yield
    finally:os.close(fd)


def validate_ssid(ssid):
    require(isinstance(ssid,str) and 1<=len(ssid.encode('utf-8'))<=32 and all(ord(c)>=32 and ord(c)!=127 for c in ssid),'SSID must contain 1–32 UTF-8 bytes without control characters.')


def password_psk(password,ssid):
    if not password:return None
    require(password.isascii() and all(32<=ord(c)<=126 for c in password) and 8<=len(password)<=63,
        'WPA2 passwords require 8–63 printable ASCII characters. Leave the password empty for an open AP.')
    return hashlib.pbkdf2_hmac('sha1',password.encode(),ssid.encode(),4096,32).hex()


def hostapd_config(name,ssid,psk):
    validate_ssid(ssid)
    require(name!='ctrl0' and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}',name),'Invalid external interface.')
    require(psk is None or re.fullmatch(r'[0-9a-f]{64}',psk),'Invalid derived AP key.')
    text=(f'interface={name}\ndriver=nl80211\nssid2={ssid.encode().hex()}\ncountry_code=DE\nieee80211d=1\n'
        f'hw_mode=g\nchannel={CHANNEL}\nwmm_enabled=1\nieee80211n=1\nauth_algs=1\nap_isolate=1\n'
        f'ctrl_interface={BASE}/control\nignore_broadcast_ssid=0\nwps_state=0\n')
    return text+('wpa=0\n' if psk is None else f'wpa=2\nwpa_key_mgmt=WPA-PSK\nrsn_pairwise=CCMP\nwpa_psk={psk}\n')


def render(template,ssid):
    validate_ssid(ssid)
    require(len(template.encode())<=2*1024*1024 and '\0' not in template,'The portal HTML must be UTF-8, at most 2 MiB, without NUL bytes.')
    return template.replace('{{SSID}}',html.escape(ssid,quote=True))


def namespace_firewall(name,guest):
    # No host interfaces, admin sockets, IPv6, or private LAN destinations are reachable.
    return f'''table inet welcome {{
chain input {{ type filter hook input priority 0; policy drop;
iifname "lo" accept
ct state invalid drop
ct state established,related accept
iifname "{name}" udp sport 68 udp dport 67 accept
iifname "{name}" ip saddr {guest['network']} ip daddr {guest['address']} udp dport 53 accept
iifname "{name}" ip saddr {guest['network']} ip daddr {guest['address']} tcp dport {{53,80,443}} accept
}}
chain forward {{ type filter hook forward priority 0; policy drop;
ct state invalid drop
iifname "ap-uplink" oifname "{name}" ip daddr {guest['network']} ct state established,related accept
iifname "{name}" ip saddr {guest['network']} ip daddr {{0.0.0.0/8,10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.168.0.0/16,224.0.0.0/4,240.0.0.0/4}} drop
iifname "{name}" oifname "ap-uplink" ip saddr {guest['network']} accept
}}
chain output {{ type filter hook output priority 0; policy accept; }}
}}\n'''


def nginx_config(guest):
    redirects='\n'.join(f'location = {path} {{ return 302 http://{guest["address"]}/; }}'
                        for path in sorted(portal().CAPTIVE_PATHS))
    return f'''user www-data;
worker_processes 1;
pid {BASE}/nginx.pid;
error_log stderr crit;
events {{ worker_connections 128; }}
http {{
include /etc/nginx/mime.types;
access_log off;
server_tokens off;
client_max_body_size 1k;
client_header_timeout 5s;
client_body_timeout 5s;
send_timeout 10s;
keepalive_timeout 5s;
server {{
listen {guest['address']}:80 default_server;
listen {guest['address']}:443 ssl default_server;
ssl_certificate /etc/pi4/tls/server.crt;
ssl_certificate_key /etc/pi4/tls/server.key;
ssl_protocols TLSv1.2 TLSv1.3;
ssl_session_tickets off;
if ($host != {guest['address']}) {{ return 302 http://{guest['address']}/; }}
root {WEB};
default_type application/octet-stream;
index index.html;
autoindex off;
disable_symlinks on;
add_header Cache-Control "no-store" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "no-referrer" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'" always;
location ~ /\\. {{ deny all; }}
{redirects}
location / {{ limit_except GET HEAD {{ deny all; }} try_files $uri $uri/ /index.html; }}
}}
}}\n'''


def sharing_selection(share):
    p=share.Platform()
    require(not p.path('run/automations-anonymity/state.json').exists(),'Turn Tor off before starting, renaming or stopping the additional AP.')
    state=p.load()
    return state['selection'] if state else None


def shared_change(share,selection):
    with share.Platform().lock():
        sources=selection.get('sources') if selection else None
        if sources is not None and not share.Platform().guest_role():
            sources=[x for x in sources if x!=share.GUEST['interface']]
        print(share.Platform().change(selection['mode'],selection['interface'],sources) if selection else share.Platform().change('off'),flush=True)


def request(ssid,interface,template=None):
    pages=portal()
    try:
        selected=pages.select(template,TEMPLATES)
        source=pages.snapshot(selected,TEMPLATES)
    except ValueError as exc:
        raise Error(str(exc)) from None
    files=pages.render(source,ssid)
    helper,wifi,share=modules(); p=wifi.Platform()
    active=load()
    devices=p.devices(); candidates=wifi.external_adapters(devices)
    if active:
        old=wifi.Adapter(*active['adapter']);candidates[old.name]=old
    require(candidates,'No external USB Wi-Fi interface is available.')
    if interface:
        require(interface in candidates,'The requested AP interface is not eligible; ctrl0 is protected.')
    else:
        try:
            interface=helper.choose([(a.name,'USB '+a.usb_id+(', active welcome AP' if active and a.name==active['adapter'][0] else '')) for a in candidates.values()],
                'Several external adapters exist; use --interface NAME in non-interactive commands.')
        except ValueError as exc:raise Error(str(exc)) from None
    require(sys.stdin.isatty() and sys.stdout.isatty(),'An interactive terminal is required for the hidden AP password prompt.')
    with warnings.catch_warnings():
        warnings.simplefilter('error',getpass.GetPassWarning)
        try:password=getpass.getpass('AP password (empty = open network): ')
        except (getpass.GetPassWarning,EOFError):raise Error('A hidden password prompt is unavailable or was cancelled; no AP was changed.') from None
    psk=password_psk(password,ssid);password=None
    previous=sharing_selection(share)
    if previous:require(previous['interface']!=interface,'The selected adapter is the active Internet uplink; choose another interface.')
    with locked():
        require(load()==active,'The AP changed during selection; retry.')
        if previous:shared_change(share,None)
        try:
            if active:
                run(['/usr/bin/systemctl','stop',UNIT],timeout=55)
                require(load() is None,'The old AP could not be cleaned up; run --off.')
            with p.locked():
                adapter=wifi.select_adapter(p.devices(),interface)
                p.guard(adapter,exclusive=True); original=p.read_state(adapter)
                require(original.mode=='managed' and original.managed,'Use auto wifi --managed on the selected adapter first.')
                require('\n\t\t * AP\n' in p.run(['iw','phy',adapter.phy,'info']) or '* AP\n' in p.run(['iw','phy',adapter.phy,'info']),'This adapter does not report AP support.')
                require(not Path('/run/netns/'+NS).exists() and not Path('/sys/class/net/'+helper.GUEST['interface']).exists(),'The reserved AP namespace or link already exists.')
                existing=json.loads(run(['/usr/sbin/ip','-j','-4','route','show','table','all']))
                for row in existing:
                    dst=row.get('dst')
                    if dst and dst!='default':
                        require(not ipaddress.ip_network(dst,strict=False).overlaps(ipaddress.ip_network(helper.GUEST['network']))
                            and not ipaddress.ip_network(dst,strict=False).overlaps(ipaddress.ip_network(helper.GUEST['transit'])),'The reserved AP subnet conflicts with an existing route.')
                BASE.mkdir(mode=0o700,exist_ok=False);trusted(BASE,directory=True)
                save({'version':1,'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                    'adapter':list(adapter),'ssid':ssid,'security':'WPA2-PSK' if psk else 'open','steps':[],
                    'original_managed':original.managed,'original_autoconnect':original.autoconnect,
                    'original_connection':original.connection,'phase':'starting',
                    'template':selected,'template_sha256':pages.digest(source),'portal_files':pages.manifest(files)})
                write_private(BASE/'hostapd.conf',hostapd_config(interface,ssid,psk));psk=None
            run(['/usr/bin/systemctl','start',UNIT],timeout=65)
            require(load() and load()['phase']=='active','The welcome AP did not become ready.')
        except BaseException:
            run(['/usr/bin/systemctl','stop',UNIT],accepted=(0,5),timeout=55)
            if load():cleanup(rollback=True)
            if previous:shared_change(share,previous)
            raise
        if previous:shared_change(share,previous)
        status()


def notify():
    address=os.environ.get('NOTIFY_SOCKET')
    require(bool(address),'The AP worker must run in its system service.')
    if address.startswith('@'):address='\0'+address[1:]
    with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as sock:sock.sendto(b'READY=1',address)


def wait_radio(name, children, stopped):
    deadline=time.monotonic()+25
    while True:
        require(not stopped() and all(p.poll() is None for p in children),'An AP service exited during startup.')
        response=inside('/usr/sbin/hostapd_cli','-p',str(BASE/'control'),'-i',name,'status',accepted=(0,1,255))
        if 'state=ENABLED' in response:
            return {k:v for k,v in (x.split('=',1) for x in response.splitlines() if '=' in x) if k in ('bssid[0]','channel')}
        require(time.monotonic()<deadline,'The AP radio did not become ready.')
        time.sleep(.2)


def namespace_link(name):
    links=json.loads(inside('/usr/sbin/ip','-j','link','show'))
    require(isinstance(links,list),'AP interface information is unavailable.')
    return next((row for row in links if isinstance(row,dict) and row.get('ifname')==name),None)


def radio_present(s):
    name,index,phy,phy_path,device_path,usb_id=s['adapter']
    # Process/control-socket liveness survives a USB disconnect on some drivers.
    # Query the kernel in the AP namespace, not its stale hostapd control state.
    # iw's ENODEV is exit237 on this platform; other errors still propagate.
    info=inside('/usr/sbin/iw','dev',name,'info',accepted=(0,237))
    fields={row[0]:row[1] for line in info.splitlines() if len(row:=line.strip().split(None,1))==2}
    return (fields.get('Interface')==name and fields.get('wiphy')==phy[3:]
        and fields.get('ifindex')==str(s.get('radio_index',index)) and fields.get('type')=='AP')


def watch_radio(s, children, stopped):
    next_check=0
    while not stopped():
        require(all(p.poll() is None for p in children),'An AP service exited; the AP is stopping.')
        now=time.monotonic()
        if now>=next_check:
            require(radio_present(s),'The AP adapter disappeared or changed; the AP is stopping.')
            next_check=now+1
        time.sleep(.3)


def worker():
    helper,wifi,share=modules();g=helper.GUEST
    s=load();require(s is not None,'No AP request is available.')
    pages=portal()
    source=pages.snapshot(s['template'],TEMPLATES)
    require(pages.digest(source)==s['template_sha256'],'The selected portal template changed before AP activation; retry.')
    files=pages.render(source,s['ssid'])
    require(pages.manifest(files)==s['portal_files'],'The portal snapshot changed before AP activation.')
    children=[]; stop=False
    def terminated(signum,frame):
        nonlocal stop
        stop=True
    signal.signal(signal.SIGTERM,terminated);signal.signal(signal.SIGINT,terminated)
    try:
        with share.Platform().lock(), wifi.Platform().locked():
            require(sharing_selection(share) is None,'Stop sharing before changing the AP topology.')
            p=wifi.Platform();adapter=wifi.Adapter(*s['adapter']);p.guard(adapter,exclusive=True)
            p.off(adapter)
            p.nm_set(adapter,'managed',False)
            run(['/usr/sbin/ip','link','set',adapter.name,'down'])
            s['steps'].append('namespace');save(s)
            run(['/usr/sbin/ip','netns','add',NS])
            s['steps'].append('radio');save(s)
            run(['/usr/sbin/iw','phy',adapter.phy,'set','netns','name',NS])
            link=namespace_link(adapter.name)
            require(link and type(link.get('ifindex')) is int and link['ifindex']>0,'The moved AP interface is unavailable.')
            s['radio_index']=link['ifindex'];save(s)
            inside('/usr/sbin/sysctl','-q','-w','net.ipv6.conf.all.disable_ipv6=1','net.ipv6.conf.default.disable_ipv6=1')
            inside('/usr/sbin/ip','link','set','lo','up')
            inside('/usr/sbin/ip','address','add',g['address']+'/24','dev',adapter.name)
            s['steps'].append('veth');save(s)
            run(['/usr/sbin/ip','link','add',g['interface'],'type','veth','peer','name','ap-uplink','netns',NS])
            s['veth_index']=int(Path('/sys/class/net/'+g['interface']+'/ifindex').read_text());save(s)
            run(['/usr/sbin/sysctl','-q','-w','net.ipv6.conf.'+g['interface']+'.disable_ipv6=1'])
            run(['/usr/sbin/ip','address','add',g['host']+'/30','dev',g['interface']])
            run(['/usr/sbin/ip','link','set',g['interface'],'up'])
            inside('/usr/sbin/ip','address','add',g['peer']+'/30','dev','ap-uplink')
            inside('/usr/sbin/ip','link','set','ap-uplink','up')
            inside('/usr/sbin/ip','route','add','default','via',g['host'],'dev','ap-uplink')
            s['steps'].append('route');save(s)
            run(['/usr/sbin/ip','route','add',g['network'],'via',g['peer'],'dev',g['interface'],'proto','static'])
            inside('/usr/sbin/sysctl','-q','-w','net.ipv4.ip_forward=1')
            inside('/usr/sbin/nft','-f','-',text=namespace_firewall(adapter.name,g))
            pages.write_runtime(WEB,files)
            write_private(BASE/'nginx.conf',nginx_config(g))
            dns=(f'interface={adapter.name}\nbind-interfaces\nexcept-interface=lo\nno-resolv\nno-hosts\n'
                f'dhcp-range=10.79.0.20,10.79.0.200,255.255.255.0,1h\ndhcp-option=3,{g["address"]}\ndhcp-option=6,{g["address"]}\n'
                'dhcp-authoritative\nleasefile-ro\nserver=10.78.0.1#1053\ndomain-needed\nbogus-priv\n')
            for host in ('pi4',*pages.CAPTIVE_HOSTS):dns+=f'address=/{host}/{g["address"]}\nlocal=/{host}/\n'
            write_private(BASE/'dnsmasq.conf',dns)
            inside('/usr/sbin/dnsmasq','--test','--conf-file='+str(BASE/'dnsmasq.conf'))
            inside('/usr/sbin/nginx','-t','-c',str(BASE/'nginx.conf'),'-p',str(BASE)+'/')
            commands=[['/usr/sbin/hostapd',str(BASE/'hostapd.conf')],
                ['/usr/sbin/dnsmasq','--keep-in-foreground','--pid-file=','--user=nobody','--group=nogroup','--conf-file='+str(BASE/'dnsmasq.conf')],
                ['/usr/sbin/nginx','-c',str(BASE/'nginx.conf'),'-p',str(BASE)+'/', '-g','daemon off;']]
            for cmd in commands:
                children.append(subprocess.Popen(['/usr/sbin/ip','netns','exec',NS,*cmd],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
            s['radio_status']=wait_radio(adapter.name,children,lambda:stop)
            # A connection alone is not enough: verify the welcome response in the namespace.
            probe=('import hashlib,urllib.request; r=urllib.request.urlopen("http://10.79.0.1/",timeout=3); '
                'assert r.status==200 and hashlib.sha256(r.read()).hexdigest()=='+repr(s['portal_files']['index.html']))
            inside('/usr/bin/python3','-c',probe)
            s['phase']='active';s['started_monotonic']=time.monotonic();save(s)
        notify()
        watch_radio(s,children,lambda:stop)
    except Exception:
        print('AP resource stages: '+', '.join(s['steps']),file=sys.stderr,flush=True)
        raise
    finally:
        for p in children:
            if p.poll() is None:p.terminate()
        for p in children:
            try:p.wait(timeout=3)
            except subprocess.TimeoutExpired:p.kill();p.wait(timeout=3)


def cleanup(*,rollback=False):
    helper,wifi,share=modules();g=helper.GUEST;s=load()
    if s is None:return
    adapter=wifi.Adapter(*s['adapter']); p=wifi.Platform()
    with p.locked():
        if Path('/run/netns/'+NS).exists():
            # Only the recorded USB radio may be returned to the initial namespace.
            # A removed radio is absent here; iw reports ENODEV as exit237,
            # not exit1. Inspect netlink first rather than masking iw errors.
            link=namespace_link(adapter.name)
            if link is not None:
                require(link.get('ifindex')==s.get('radio_index',adapter.index),'The AP interface identity changed; refusing cleanup.')
                info=inside('/usr/sbin/iw','dev',adapter.name,'info')
                require('wiphy '+adapter.phy[3:] in info,'The AP radio identity changed; refusing cleanup.')
                inside('/usr/sbin/ip','link','set',adapter.name,'down')
                inside('/usr/sbin/ip','address','flush','dev',adapter.name)
                inside('/usr/sbin/iw','dev',adapter.name,'set','type','managed')
                inside('/usr/sbin/iw','phy',adapter.phy,'set','netns','1')
        link=Path('/sys/class/net/'+g['interface'])
        if link.exists():
            require(s.get('veth_index')==int((link/'ifindex').read_text()),'The AP transit link changed; refusing cleanup.')
            run(['/usr/sbin/ip','link','delete',g['interface']])
        # Keep the namespace alive until its veth pair is explicitly removed.
        # Removing the namespace first also destroys the peer asynchronously.
        if Path('/run/netns/'+NS).exists():
            run(['/usr/sbin/ip','netns','delete',NS])
        current=p.devices()
        if adapter.name in current:
            require(current[adapter.name].usb_id==adapter.usb_id and current[adapter.name].device_path==adapter.device_path,'A replacement USB adapter will not be changed.')
            run(['/usr/bin/nmcli','device','set',adapter.name,'managed','yes' if s['original_managed'] else 'no'])
            run(['/usr/bin/nmcli','device','set',adapter.name,'autoconnect','no'])
            if rollback and s.get('original_connection'):
                run(['/usr/bin/nmcli','connection','up','uuid',s['original_connection'],'ifname',adapter.name],timeout=35)
                run(['/usr/bin/nmcli','device','set',adapter.name,'autoconnect','yes' if s['original_autoconnect'] else 'no'])
        if WEB.exists():
            if 'portal_files' in s:
                portal().remove_runtime(WEB,s['portal_files'])
            else:
                trusted(WEB,directory=True)
                require({x.name for x in WEB.iterdir()}=={'index.html'},'Unexpected welcome files; cleanup stopped.')
                trusted(WEB/'index.html').unlink();WEB.rmdir()
        allowed={'state.json','hostapd.conf','nginx.conf','nginx.pid','dnsmasq.conf','control'}
        require(all(x.name in allowed for x in BASE.iterdir()),'Unexpected AP runtime files; cleanup stopped.')
        for x in BASE.iterdir():
            if x.is_dir():
                require(x.name=='control' and not list(x.iterdir()),'AP control socket is still in use.')
                x.rmdir()
            else:x.unlink()
        BASE.rmdir()


def service_ready(s):
    if not(s and s.get('phase')=='active' and Path('/run/netns/'+NS).exists() and
        run(['/usr/bin/systemctl','is-active',UNIT],accepted=(0,3,4)).strip()=='active'):return False
    try:return radio_present(s)
    except (Error,OSError,ValueError):return False


def status():
    helper,_,share=modules();s=load()
    active=service_ready(s)
    print('Additional AP: '+('up' if active else 'off' if not s else 'starting or degraded'))
    print('Control WLAN: ctrl0 is separate and protected')
    print('Lifetime: runtime only; always off after reboot')
    print('Web files: '+str(WEB)+' (generated runtime directory; present while AP is running)')
    print('Template directory: '+str(TEMPLATES))
    print('Welcome template: '+(s.get('template','legacy welcome.html') if s else 'not selected; choose with --template NAME'))
    if not s:return 0
    print('Interface: '+s['adapter'][0]);print('SSID: '+json.dumps(s['ssid'],ensure_ascii=True))
    print('Security: '+s['security']);print('Client isolation: enabled');print('Channel: '+str(CHANNEL))
    print('Uptime: '+str(max(0,int(time.monotonic()-s.get('started_monotonic',time.monotonic()))))+' seconds')
    stations=inside('/usr/sbin/hostapd_cli','-p',str(BASE/'control'),'-i',s['adapter'][0],'all_sta',accepted=(0,1)) if active else ''
    print('Active clients: '+(str(sum(bool(re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',x)) for x in stations.splitlines())) if active else 'unavailable'))
    print('Web: http://10.79.0.1/ ; https://pi4/ (requires trust in the Pi4 CA)')
    print('Local services: HTTP/HTTPS, DHCP and DNS only; no SSH or Guacamole')
    selection=share.Platform().load()
    print('Internet: '+(selection['selection']['interface']+' (selected share uplink; no fallback)' if selection and selection.get('ready') and share.guest_enabled(selection['selection']) else 'off; use auto share --wifi/--lan --from '+s['adapter'][0]))
    print('Guest IPv6: disabled; no IPv6 bypass')
    return 0


def main(argv=None):
    args=list(sys.argv[1:] if argv is None else argv)
    if args in (['--internal-worker'],['--internal-cleanup']):
        require(os.geteuid()==0 and '/'+UNIT in Path('/proc/self/cgroup').read_text(),'The internal AP worker requires its fixed root service.')
        if args==['--internal-worker']:worker()
        else:
            s=load()
            cleanup(rollback=bool(s and (s.get('phase')!='active' or os.environ.get('SERVICE_RESULT','success')!='success')))
        return 0
    p=argparse.ArgumentParser(prog='auto share ap',description=__doc__)
    p.add_argument('ssid',nargs='?',help='Start or rename the additional AP; a hidden password prompt follows (empty = open)')
    p.add_argument('--interface',metavar='IFACE',help='Choose an external USB adapter; otherwise ask when several exist')
    p.add_argument('--template',metavar='NAME',help='Portal directory name; otherwise ask and list available templates')
    group=p.add_mutually_exclusive_group();group.add_argument('--off',action='store_true');group.add_argument('--status',action='store_true')
    a=p.parse_args(args)
    if a.ssid is not None and (a.off or a.status):p.error('SSID cannot be combined with --off or --status')
    if (a.interface or a.template is not None) and a.ssid is None:p.error('--interface/--template require an SSID')
    require(os.geteuid()==0,'Use sudo auto share ap; AP state and service inspection require root.')
    if a.ssid is not None:validate_ssid(a.ssid);request(a.ssid,a.interface,a.template)
    elif a.off:
        with locked():
            _,_,share=modules();previous=sharing_selection(share)
            if previous:shared_change(share,None)
            run(['/usr/bin/systemctl','stop',UNIT],accepted=(0,5),timeout=55)
            if load():cleanup()
            if previous:shared_change(share,previous)
            print('Additional AP stopped. ctrl0 and its services were not changed.')
    else:return status()
    return 0


if __name__=='__main__':
    try:raise SystemExit(main())
    except (RuntimeError,OSError,ValueError,KeyError) as exc:
        print('ERROR: '+(str(exc) if isinstance(exc,Error) else 'Cannot manage the AP safely; private configuration was not disclosed.'),file=sys.stderr)
        raise SystemExit(1)
    except KeyboardInterrupt:
        print('AP operation cancelled.',file=sys.stderr);raise SystemExit(130)
