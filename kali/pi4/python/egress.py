"""Shared, runtime-only Tor/proxy egress guard for the managed Pi4 platform.

No daemon launch, source downloads or automatic uplink selection happens here.
Only the fixed caller lifecycle may open a transport UID through an already
selected share uplink. Tor recovery keeps application traffic closed until its
caller has verified a new working Tor path. Only explicit --off removes the guard.
"""
from __future__ import annotations

from contextlib import contextmanager
import ast
import importlib.machinery
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import pwd
import stat
import sys
import tempfile


# Fixed, data-only optional role contract. Do not execute another helper during
# firewall inspection. The cross-component contract test checks this against CLI.
GUEST={'interface':'autoap0','network':'10.79.0.0/24','address':'10.79.0.1',
       'host':'169.254.95.1','peer':'169.254.95.2','transit':'169.254.95.0/30'}

TABLE = 'auto_privacy'
STATE = 'run/automations-anonymity/state.json'
MARK = 0x414E4F4E
SUPPORT = '/usr/local/libexec/automations-support/egress.py'
MODES = {
    'tor': {'user': 'auto-tor', 'service': 'automations-tor.service', 'tcp_port': 19040, 'dns_port': 19053,
            'ipv6_tcp': False, 'dns_tcp': False},
    'proxy': {'user': 'auto-proxy', 'service': 'automations-proxy.service', 'tcp_port': 19081, 'dns_port': 19053,
              'ipv6_tcp': True, 'dns_tcp': True},
}


class Error(RuntimeError):
    pass


class Busy(Error):
    """A legitimate sharing operation owns the lock; no operation was entered."""


def require(condition, message):
    if not condition:
        raise Error(message)


def trusted(root, relative, directory=False, owner=0):
    path = Path(root)
    for part in Path(relative).parts:
        require(part not in ('..', '/'), 'Unsafe anonymity path.')
        path /= part
        info = path.lstat()
        require(not stat.S_ISLNK(info.st_mode) and info.st_uid == owner and not info.st_mode & 0o022,
                'Unsafe anonymity file ownership, permissions or link.')
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
            'Unexpected anonymity file type.')
    return path


def load_state(root=Path('/'), owner=0):
    path = Path(root)/STATE
    if not path.exists() and not path.is_symlink():
        return None
    try:
        trusted(root, str(Path(STATE).parent), True, owner)
        require(stat.S_IMODE(path.parent.stat().st_mode) == 0o700, 'Unsafe anonymity state directory.')
        path = trusted(root, STATE, owner=owner)
        require(stat.S_IMODE(path.stat().st_mode) == 0o600 and path.stat().st_size <= 65536,
                'Unsafe anonymity state file.')
        value = json.loads(path.read_text(encoding='utf-8'))
        validate_state(value)
        return value
    except (OSError, ValueError, TypeError, KeyError):
        raise Error('Cannot read the protected anonymity state.') from None


def validate_state(value):
    require(isinstance(value, dict) and set(value) == {'version', 'mode', 'uid', 'selection', 'phase'}
            and value['version'] == 1 and value['mode'] in MODES
            and type(value['uid']) is int and 0 < value['uid'] < 2**32-1 and value['uid'] != 65534
            and value['phase'] in ('starting', 'active', 'blocked', 'recovering')
            and (value['phase'] != 'recovering' or value['mode'] == 'tor'), 'Unrecognized anonymity state.')
    selection = value['selection']
    require(isinstance(selection, dict),'Invalid selected uplink.')
    if 'guest' in selection:
        require(selection['guest']==GUEST,'Invalid additional AP routing role.')
    if 'sources' in selection:
        sources=selection['sources']
        require(isinstance(sources,list) and len(sources)<=2
            and all(isinstance(x,str) and x in ('ctrl0',GUEST['interface']) for x in sources)
            and len(set(sources))==len(sources)
            and (GUEST['interface'] not in sources or selection.get('guest')==GUEST),'Invalid sharing sources.')
    require(isinstance(selection, dict) and selection.get('mode') in ('lan', 'wifi'), 'Invalid selected uplink.')
    # The share module performs the full configuration validation. Here also
    # reject malformed addresses before any state-derived nft construction.
    import re
    require(isinstance(selection.get('interface'), str)
            and re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}', selection['interface'])
            and selection['interface'] not in ('lo', 'ctrl0'), 'Invalid selected interface.')
    address = ipaddress.IPv4Address(selection['address'])
    require(not address.is_loopback and not address.is_multicast and not address.is_unspecified
            and address not in ipaddress.IPv4Network('10.78.0.0/24'), 'Invalid selected IPv4 source.')
    require('ipv6' in selection and 'control6' in selection, 'Incomplete selected uplink.')
    if selection['ipv6']:
        require(isinstance(selection['ipv6'].get('addresses'), list) and 1 <= len(selection['ipv6']['addresses']) <= 16,
                'Invalid selected IPv6 sources.')
        for item in selection['ipv6']['addresses']:
            require(ipaddress.IPv6Address(item) in ipaddress.IPv6Network('2000::/3'), 'Invalid selected IPv6 source.')
        control = selection['control6']
        network = ipaddress.IPv6Network(control['network'])
        require(network.prefixlen == 64 and network.subnet_of(ipaddress.IPv6Network('fd00::/8'))
                and ipaddress.IPv6Address(control['address']) in network, 'Invalid control IPv6 prefix.')


def match(left, right):
    return {'match': {'op': '==', 'left': left, 'right': right}}


def dnat_status():
    # Status is a bitmask, not an enum. Additional confirmed/seen-reply bits
    # must not turn a genuine DNAT connection into an unmatched packet.
    return {'match':{'op':'in','left':{'ct':{'key':'status'}},'right':'dnat'}}


def meta(key, right):
    return match({'meta': {'key': key}}, right)


def payload(protocol, field, right):
    return match({'payload': {'protocol': protocol, 'field': field}}, right)


def prefix(value):
    network = ipaddress.ip_network(value)
    return {'prefix': {'addr': str(network.network_address), 'len': network.prefixlen}}


ACCEPT, DROP, RETURN = {'accept': None}, {'drop': None}, {'return': None}
MARK_FLOW = {'mangle': {'key': {'ct': {'key': 'mark'}}, 'value': MARK}}


def rule(chain, expr, comment, table=TABLE):
    return {'family': 'inet', 'table': table, 'chain': chain, 'expr': expr, 'comment': 'auto-privacy:'+comment}


def local_exceptions():
    return [
        [meta('oifname', 'lo'), ACCEPT],
        [meta('oifname', 'ctrl0'), payload('ip', 'daddr', prefix('10.78.0.0/24')), ACCEPT],
        [meta('oifname', 'ctrl0'), payload('ip6', 'daddr', prefix('fd00::/8')), ACCEPT],
        [meta('oifname', 'ctrl0'), payload('ip6', 'daddr', prefix('fe80::/10')), ACCEPT],
        [meta('oifname', 'ctrl0'), payload('udp', 'sport', 67), payload('udp', 'dport', 68), ACCEPT],
        [payload('udp', 'sport', 68), payload('udp', 'dport', 67), ACCEPT],
        [payload('ip6', 'hoplimit', 255), payload('icmpv6', 'type', {'set': [133,134,135,136]}), ACCEPT],
        [payload('ip6', 'hoplimit', 1), payload('icmpv6', 'type', {'set': [130,131,132,143]}), ACCEPT],
        [meta('nfproto', 'ipv6'), payload('udp', 'sport', 546), payload('udp', 'dport', 547), ACCEPT],
    ]


def control_enabled(selected):
    return 'ctrl0' in selected.get('sources',['ctrl0'])


def guest_enabled(selected):
    return bool(selected.get('guest')) and GUEST['interface'] in selected.get('sources',[GUEST['interface']])


def input_rules(state):
    config, selected = MODES[state['mode']], state['selection']
    families = [('ip', '10.78.0.0/24', '10.78.0.1')]
    if config['ipv6_tcp'] and selected['ipv6']:
        families.append(('ip6', selected['control6']['network'], selected['control6']['address']))
    result = [rule('input', [meta('iifname','ctrl0'), payload(family,'saddr',prefix(network)),
                payload(family,'daddr',address), payload('tcp','dport',config['tcp_port']),
                dnat_status(), ACCEPT], 'input-'+family+'-'+state['mode'], 'pi4')
            for family, network, address in families if control_enabled(selected)]
    if 'sources' in selected:
        for name,enabled in (('ctrl0',control_enabled(selected)),(GUEST['interface'],guest_enabled(selected))):
            if not enabled:
                result.insert(0,rule('input',[meta('iifname',name),payload('tcp','dport',config['tcp_port']),DROP],
                    'excluded-'+name,'pi4'))
    if guest_enabled(selected):
        result.append(rule('input',[meta('iifname',GUEST['interface']),payload('ip','saddr',prefix(GUEST['network'])),
            payload('ip','daddr','10.78.0.1'),payload('tcp','dport',config['tcp_port']),dnat_status(),ACCEPT],
            'input-guest-'+state['mode'],'pi4'))
    return result


def local_redirect_expressions(state):
    config=MODES[state['mode']]
    targets=[('ip','127.0.0.1','tcp',config['tcp_port'])]
    if config['ipv6_tcp'] and state['selection']['ipv6']:targets.append(('ip6','::1','tcp',config['tcp_port']))
    for family,address in (('ip','127.0.0.1'),('ip6','::1')):
        for protocol in (('udp','tcp') if config['dns_tcp'] else ('udp',)):
            targets.append((family,address,protocol,config['dns_port']))
    return [[payload(family,'daddr',address),payload(protocol,'dport',port),
             dnat_status(),match({'ct':{'key':'mark'}},MARK),ACCEPT]
            for family,address,protocol,port in targets]


def extension_rules(state):
    # OUTPUT still has its original oif during DNAT. Keep only our exact local
    # DNAT flows out of Share's external source rules, which would overwrite the
    # private conntrack mark. No external destination can match this admission.
    return input_rules(state)+[rule('egress',expr,'share-local-dnat-'+str(i),'auto_share')
                              for i,expr in enumerate(local_redirect_expressions(state))]


def objects(state):
    validate_state(state)
    selected, config = state['selection'], MODES[state['mode']]
    result = [('table', {'family':'inet', 'name':TABLE})]
    for name, kind, hook, priority, policy in (
        ('egress','filter','output',5,'drop'), ('forward','filter','forward',-30,'drop'),
        ('local_nat','nat','output',-110,'accept'), ('client_nat','nat','prerouting',-110,'accept')):
        result.append(('chain', {'family':'inet','table':TABLE,'name':name,'type':kind,'hook':hook,
                                'prio':priority,'policy':policy}))
    if state['mode'] == 'tor':
        result.append(('chain', {'family':'inet','table':TABLE,'name':'recovery_input',
            'type':'filter','hook':'input','prio':-30,'policy':'accept'}))
        if state['phase'] != 'active':
            # Before the ordinary loopback/control exceptions: DNAT and old
            # established transports must not bypass the recovery gate. Only
            # the privileged fixed HTTPS probe may use Tor's SOCKS listener.
            result.append(('rule', rule('egress', [meta('skuid',0),payload('ip','daddr','127.0.0.1'),
                payload('tcp','dport',19050), ACCEPT], 'recovery-probe')))
            for chain in ('egress', 'recovery_input'):
                for protocol in ('tcp','udp'):
                    ports = [19040,19053] if chain == 'recovery_input' else [19040,19050,19053]
                    result.append(('rule', rule(chain, [payload(protocol,'dport',{'set':ports}),DROP],
                        'recovery-close-'+chain+'-'+protocol)))
    for index, expression in enumerate(local_exceptions()):
        result.append(('rule', rule('egress', expression, 'local-'+str(index))))
    if guest_enabled(selected):
        for label,target in (('clients',prefix(GUEST['network'])),('resolver',GUEST['peer'])):
            result.append(('rule',rule('egress',[meta('oifname',GUEST['interface']),payload('ip','daddr',target),
                match({'ct':{'key':'state'}},{'set':['established','related']}),ACCEPT],'guest-reply-'+label)))
    for index,expression in enumerate(local_redirect_expressions(state)):
        result.append(('rule',rule('egress',expression,'local-dnat-'+str(index))))
    for family,address in (('ip','10.78.0.1'),('ip6','::1')):
        for protocol in ('udp','tcp'):
            result.append(('rule',rule('egress',[payload(family,'daddr',address),payload(protocol,'dport',1053),
                dnat_status(),match({'ct':{'key':'mark'}},0x4155544F),ACCEPT],
                'share-frontend-'+family+'-'+protocol)))
    if state['phase'] != 'blocked':
        result.append(('rule',rule('egress',[meta('skuid',state['uid']),payload('tcp','dport',53),DROP],
                                   'transport-no-direct-dns')))
        families = [('ip', [selected['address']])]
        if config['ipv6_tcp'] and selected['ipv6']:
            families.append(('ip6', selected['ipv6']['addresses']))
        for family, addresses in families:
            result.append(('rule', rule('egress', [meta('skuid',state['uid']),
                meta('oifname',selected['interface']), meta('nfproto','ipv6' if family=='ip6' else 'ipv4'),
                meta('l4proto','tcp'), match({'ct':{'key':'state'}},{'set':['established','related']}),
                ACCEPT], 'transport-existing-'+family)))
            result.append(('rule', rule('egress', [meta('skuid',state['uid']),
                meta('oifname',selected['interface']), payload(family,'saddr',{'set':addresses}),
                meta('l4proto','tcp'), ACCEPT], 'transport-'+family)))
    # Transport connects straight to its relay/first proxy; no recursive redirect.
    result.append(('rule', rule('local_nat', [meta('skuid',state['uid']), RETURN], 'transport-bypass')))
    # Keep the existing selected-share DNS front-end (local pi4 name + RA). Its
    # external queries, and local application's queries, go only to this backend.
    for family, loopback in (('ip','127.0.0.1'), ('ip6','::1')):
        protocols = ('udp','tcp') if config['dns_tcp'] else ('udp',)
        for protocol in protocols:
            result.append(('rule', rule('local_nat', [meta('skuid',65534),meta('nfproto','ipv4' if family=='ip' else 'ipv6'),
                payload(protocol,'dport',53), MARK_FLOW,
                {'dnat':{'family':family,'addr':loopback,'port':config['dns_port']}}], 'dns-'+family+'-'+protocol)))
        if not config['dns_tcp']:
            result.append(('rule', rule('local_nat', [meta('skuid',65534),meta('nfproto','ipv4' if family=='ip' else 'ipv6'),
                payload('tcp','dport',53), DROP], 'dns-tcp-block-'+family)))
    for protocol in ('udp','tcp'):
        result.append(('rule',rule('local_nat',[payload(protocol,'dport',53),RETURN],
                                   'dns-front-end-'+protocol)))
    # Preserve loopback and the control subnet; everything else is either TCP
    # redirected here or denied by the filter hooks (including existing flows).
    for family, subnet in (('ip','127.0.0.0/8'),('ip','10.78.0.0/24'),('ip6','::1/128'),
                          ('ip6','fe80::/10'),('ip6','ff00::/8')):
        result.append(('rule', rule('local_nat',[payload(family,'daddr',prefix(subnet)),RETURN], 'keep-'+subnet)))
    if selected['ipv6']:
        result.append(('rule',rule('local_nat',[payload('ip6','daddr',prefix(selected['control6']['network'])),RETURN],'keep-control6')))
    if guest_enabled(selected):
        for subnet in (GUEST['network'],GUEST['transit']):
            result.append(('rule',rule('local_nat',[payload('ip','daddr',prefix(subnet)),RETURN],'keep-guest-'+subnet)))
    families = [('ip','10.78.0.0/24','10.78.0.1','127.0.0.1')]
    if config['ipv6_tcp'] and selected['ipv6']:
        families.append(('ip6',selected['control6']['network'],selected['control6']['address'],'::1'))
    # DNS to the control front-end is handled by auto_share's later NAT chain.
    result.append(('rule',rule('client_nat',[payload('tcp','dport',53),RETURN],'client-dns')))
    if guest_enabled(selected):
        result.append(('rule',rule('client_nat',[meta('iifname',GUEST['interface']),payload('ip','saddr',prefix(GUEST['network'])),
            meta('l4proto','tcp'),MARK_FLOW,{'dnat':{'family':'ip','addr':'10.78.0.1','port':config['tcp_port']}}],'client-tcp-guest')))
    for family, network, address, loopback in families:
        result.append(('rule',rule('client_nat',[payload(family,'daddr',prefix(network)),RETURN],'client-local-'+family)))
        if control_enabled(selected):
            result.append(('rule',rule('client_nat',[meta('iifname','ctrl0'),payload(family,'saddr',prefix(network)),
                meta('l4proto','tcp'),MARK_FLOW,{'dnat':{'family':family,'addr':address,'port':config['tcp_port']}}], 'client-tcp-'+family)))
        result.append(('rule',rule('local_nat',[meta('nfproto','ipv4' if family=='ip' else 'ipv6'),
            meta('l4proto','tcp'),MARK_FLOW,{'dnat':{'family':family,'addr':loopback,'port':config['tcp_port']}}],'local-tcp-'+family)))
    result += [('rule', item) for item in extension_rules(state)]
    return result


def normalize(value):
    """Only native nft spelling changes; never discard match conditions."""
    value = json.loads(json.dumps(value))
    if not isinstance(value,dict): return value
    for key in ('handle','index','position'): value.pop(key,None)
    for item in value.get('expr',[]):
        expression = item.get('match',{})
        right = expression.get('right')
        if expression.get('left') == {'payload':{'protocol':'icmpv6','field':'type'}}:
            names = {'nd-router-solicit':133,'nd-router-advert':134,'nd-neighbor-solicit':135,'nd-neighbor-advert':136,
                     'mld-listener-query':130,'mld-listener-report':131,'mld-listener-done':132,'mld2-listener-report':143}
            if isinstance(right,str): expression['right']=names.get(right,right)
            elif isinstance(right,dict) and 'set' in right: expression['right']={'set':[names.get(x,x) for x in right['set']]}
        right = expression.get('right')
        if isinstance(right,dict) and set(right)=={'prefix'}:
            network=right['prefix']
            if set(network)=={'addr','len'}:
                address=ipaddress.ip_address(network['addr'])
                if network['len']==address.max_prefixlen: expression['right']=str(address)
        if isinstance(right,dict) and 'set' in right:
            right['set'] = sorted(right['set'],key=str)
            if len(right['set']) == 1: expression['right'] = right['set'][0]
            if expression.get('op') == 'in': expression['op']='=='
    protocols = {x.get('match',{}).get('left',{}).get('payload',{}).get('protocol') for x in value.get('expr',[])}
    implied = 'ipv6' if protocols & {'ip6','icmpv6'} else 'ipv4' if protocols & {'ip','icmp'} else None
    if implied and 'expr' in value: value['expr']=[x for x in value['expr'] if x != meta('nfproto',implied)]
    return value


def relevant(data):
    require(isinstance(data,dict) and isinstance(data.get('nftables'),list),'Invalid anonymity firewall response.')
    result=[]
    for row in data['nftables']:
        for kind,value in row.items():
            if not isinstance(value,dict): continue
            if value.get('family')=='inet' and (value.get('table')==TABLE or
                    kind=='table' and value.get('name')==TABLE or
                    kind=='rule' and value.get('table') in ('pi4','auto_share') and value.get('comment','').startswith('auto-privacy:')):
                result.append((kind,value))
    return result


def check_objects(data,state,allow_absent=False):
    actual = relevant(data)
    if not actual and allow_absent: return []
    expected = objects(state) if state else []
    # Object order is meaningful inside each chain. Cross-table insertion order
    # differs because the exact pi4 INPUT admissions are inserted at its front.
    def key(pair):
        kind,value=pair
        return (value.get('table',value.get('name','')),value.get('chain',''),kind)
    need_actual=sorted(actual,key=key)
    need_expected=sorted(expected,key=key)
    require([(k,normalize(v)) for k,v in need_actual] == [(k,normalize(v)) for k,v in need_expected],
            'Anonymity firewall objects are missing, changed or out of order; refusing unsafe cleanup.')
    return actual


def firewall_view(data,root=Path('/'),owner=0):
    """Validate the extension; hide only its exact admissions from core guards."""
    state=load_state(root,owner)
    check_objects(data,state)
    if state:
        share_path = trusted(root,'run/automations-share/state.json',owner=owner)
        require(share_path.stat().st_size <= 65536, 'Sharing state is too large.')
        share_state = json.loads(share_path.read_text(encoding='utf-8'))
        require(share_state.get('version') == 2 and share_state.get('selection') == state['selection'],
                'Anonymity and sharing select different uplinks.')
    admissions = extension_rules(state) if state else []
    return {'nftables':[row for row in data['nftables'] if not ('rule' in row and any(
        normalize(row['rule'])==normalize(expected) for expected in admissions))]}


def load_share():
    path=trusted(Path('/'),'usr/local/libexec/automations/share')
    loader=importlib.machinery.SourceFileLoader('_automations_share_runtime',str(path))
    spec=importlib.util.spec_from_loader(loader.name,loader)
    module=importlib.util.module_from_spec(spec)
    sys.modules[loader.name]=module
    loader.exec_module(module)
    return module


class Runtime:
    Busy = Busy

    def __init__(self,share=None,platform=None,account_lookup=pwd.getpwnam):
        self.share = share or load_share()
        self.platform = platform or self.share.Platform()
        self.root,self.owner=self.platform.root,self.platform.owner
        self.account_lookup=account_lookup
        self.mode=None
        self.held=False

    def raw_firewall(self):
        return json.loads(self.platform.run(['/usr/sbin/nft','--json','list','ruleset']))

    def state(self):
        return load_state(self.root,self.owner)

    def save(self,state,expected):
        validate_state(state)
        parent=Path(self.root)/Path(STATE).parent
        trusted(self.root,'run',True,self.owner)
        if not parent.exists(): parent.mkdir(mode=0o700)
        trusted(self.root,str(Path(STATE).parent),True,self.owner)
        require(stat.S_IMODE(parent.stat().st_mode)==0o700,'Unsafe anonymity state directory.')
        require(self.state()==expected,'Concurrent anonymity state change; refusing overwrite.')
        fd,temp=tempfile.mkstemp(prefix='.state-',dir=parent)
        try:
            with os.fdopen(fd,'w',encoding='utf-8') as stream:
                os.fchmod(stream.fileno(),0o600)
                stream.write(json.dumps(state,sort_keys=True)+'\n')
                stream.flush(); os.fsync(stream.fileno())
            require(self.state()==expected,'Concurrent anonymity state change; refusing overwrite.')
            os.replace(temp,Path(self.root)/STATE)
        finally: Path(temp).unlink(missing_ok=True)

    def batch(self,old,new,allow_absent=False):
        data=self.raw_firewall()
        actual=check_objects(data,old,allow_absent)
        commands=[]
        if actual:
            for kind,value in actual:
                if kind=='rule' and value.get('table')!=TABLE:
                    require(type(value.get('handle')) is int and value['handle']>0,'Missing anonymity rule handle.')
                    commands.append({'delete':{'rule':{k:value[k] for k in ('family','table','chain','handle')}}})
            commands.append({'delete':{'table':{'family':'inet','name':TABLE}}})
        if new:
            commands += [{'add':{kind:value}} for kind,value in objects(new) if not(kind=='rule' and value['table']!=TABLE)]
            # Insert before the core policy drop. The exact extension is
            # validated and removed from the view used by the core guards.
            for item in reversed(extension_rules(new)):
                commands.append({'insert':{'rule':item}})
        batch={'nftables':commands}
        self.platform.run(['/usr/sbin/nft','--check','--json','-f','-'],json.dumps(batch))
        self.platform.nft(batch)

    def assert_operation(self):
        require(self.held and self.mode in MODES,'Anonymity mutation requires its serialized operation context.')

    @contextmanager
    def operation(self,mode):
        require(mode in MODES,'Unknown anonymity mode.')
        require(not self.held,'Nested anonymity operation is not supported.')
        entered=False
        try:
            with self.platform.lock():
                entered=True
                self.platform.validate()
                current=self.state()
                require(not current or current['mode']==mode,'Tor and proxy are mutually exclusive; turn the active mode off first.')
                self.held,self.mode=True,mode
                try:
                    yield self
                except BaseException as original:
                    if self.state() is not None:
                        try: self.block()
                        except BaseException:
                            raise Error('Anonymity operation failed and its guard could not be verified; inspect the protected state before retrying.') from original
                    raise
                finally:
                    self.held,self.mode=False,None
        except self.share.Busy as error:
            # Only lock acquisition may turn contention into a deferred tick.
            # Once entered, preserve the ordinary error/guard lifecycle.
            raise (Error if entered else Busy)(str(error)) from None
        except Busy as error:
            if entered:
                raise Error(str(error)) from None
            raise
        except self.share.Error as error:
            raise Error(str(error)) from None

    def activate(self,uid,tcp_port,dns_port):
        self.assert_operation()
        require(type(getattr(self.share,'PRIVACY_API',None)) is int and self.share.PRIVACY_API==1,
                'Update the selected share-control component before enabling anonymity.')
        require(getattr(self.share,'PRIVACY_DNS_API',None)==1,
                'Update share-control for reloadable privacy DNS before enabling anonymity.')
        ssh_path=Path(self.root)/'usr/local/libexec/automations/ssh'
        if ssh_path.exists() or ssh_path.is_symlink():
            ssh_path=trusted(self.root,'usr/local/libexec/automations/ssh',owner=self.owner)
            require(ssh_path.stat().st_size<=262144,'The installed SSH component is too large.')
            try:
                tree=ast.parse(ssh_path.read_text(encoding='utf-8'))
                markers=[node.value.value for node in tree.body if isinstance(node,ast.Assign)
                    and len(node.targets)==1 and isinstance(node.targets[0],ast.Name)
                    and node.targets[0].id=='PRIVACY_API' and isinstance(node.value,ast.Constant)
                    and type(node.value.value) is int]
            except (OSError,SyntaxError,ValueError):markers=[]
            require(markers==[1], 'Update the selected ssh-control component before enabling anonymity.')
        config=MODES[self.mode]
        require((tcp_port,dns_port)==(config['tcp_port'],config['dns_port']), 'Unexpected anonymity listener ports.')
        require(type(uid) is int and 0<uid<2**32-1 and uid!=65534
                and self.account_lookup(config['user']).pw_uid==uid,'Anonymity service UID is not its dedicated account.')
        previous=self.state()
        if previous:
            require(previous['uid']==uid,'Anonymity service identity changed; turn it off before retrying.')
            raise Error('Anonymity is already configured; turn it off before starting it again.')
        share=self.platform.load()
        require(share and self.platform.healthy(share), 'Enable a healthy explicit auto share uplink before anonymity.')
        state={'version':1,'mode':self.mode,'uid':uid,'selection':share['selection'],'phase':'starting'}
        check_objects(self.raw_firewall(),None)
        self.save(state,None)
        self.batch(state,state,allow_absent=True)
        # First-packet NAT cannot retrofit old DNS/direct TCP connections.
        # Local control/Guacamole traffic is not marked by auto_share.
        self.platform.run(['/usr/sbin/conntrack','-D','--mark',str(self.share.MARK)],accepted=(0,1))
        if self.mode=='tor':
            self.platform.resolver_mode(True)

    def ready(self):
        self.assert_operation()
        state=self.state()
        require(state and state['mode']==self.mode and state['phase'] in ('starting','recovering'),
                'No matching anonymity activation is pending.')
        check_objects(self.raw_firewall(),state)
        share=self.platform.load()
        require(share and share['selection']==state['selection'] and self.platform.healthy(share),
                'The selected share uplink changed during anonymity activation.')
        self.transition(state,{**state,'phase':'active'})

    def transition(self,old,new,allow_absent=False):
        """Keep the old verified firewall if publishing its new state fails."""
        self.batch(old,new,allow_absent)
        try:
            self.save(new,old)
        except BaseException:
            self.batch(new,old)
            raise

    def recover(self):
        """Permit Tor bootstrap only; never release normal Pi/client traffic."""
        self.assert_operation()
        state=self.state()
        require(self.mode=='tor' and state and state['mode']=='tor',
                'Automatic recovery requires an existing Tor guard.')
        require(self.account_lookup(MODES['tor']['user']).pw_uid==state['uid'],
                'The Tor service identity changed; recovery refused.')
        check_objects(self.raw_firewall(),state)
        self.platform.resolver_mode(True)
        share=self.platform.load()
        require(share and share['selection']==state['selection'] and self.platform.healthy(share),
                'The selected share uplink is unavailable or changed; Tor recovery will retry.')
        if state['phase']!='recovering':
            self.transition(state,{**state,'phase':'recovering'})
            self.platform.run(['/usr/sbin/conntrack','-D','--mark',str(MARK)],accepted=(0,1))

    def block(self):
        self.assert_operation()
        state=self.state()
        if not state:
            check_objects(self.raw_firewall(),None)
            return
        require(state['mode']==self.mode,'Another anonymity mode owns the guard.')
        blocked={**state,'phase':'blocked'}
        self.transition(state,blocked,allow_absent=state['phase']=='starting')

    def deactivate(self):
        self.assert_operation()
        state=self.state()
        if not state:
            check_objects(self.raw_firewall(),None)
            return
        require(state['mode']==self.mode and state['phase']=='blocked','Block anonymity before stopping and removing it.')
        raw=self.platform.run(['/usr/bin/systemctl','show',MODES[self.mode]['service'],
                               '--property=MainPID,ActiveState'])
        values=dict(line.split('=',1) for line in raw.splitlines() if '=' in line)
        require(values.get('MainPID')=='0' and values.get('ActiveState') in ('inactive','failed'),
                'Stop the anonymity service before removing its guard.')
        # Stale local DNAT flows must not survive the explicit return to share.
        self.platform.run(['/usr/sbin/conntrack','-D','--mark',str(MARK)],accepted=(0,1))
        if self.mode=='tor':
            self.platform.resolver_mode(False)
        self.batch(state,None)
        require(self.state()==state,'Concurrent anonymity state change; refusing removal.')
        try:
            (Path(self.root)/STATE).unlink()
        except OSError:
            # Removal failed after our atomic rule deletion. Restore the exact
            # closed guard, never leave a misleading blocked record with no guard.
            self.batch(state,state,allow_absent=True)
            raise

    def status(self):
        state=self.state()
        if not state:
            check_objects(self.raw_firewall(),None)
            share=self.platform.load()
            selected=share['selection'] if share else None
            return {'mode':'off','phase':'off','ready':False,'interface':selected['interface'] if selected else None,
                    'selection':selected,'uid':None,
                    'tcp_port':None,'dns_port':None,'error':None}
        error=None
        try:
            check_objects(self.raw_firewall(),state)
            share=self.platform.load()
            require(share and share['selection']==state['selection'] and self.platform.healthy(share),
                    'The selected share uplink is unavailable or changed.')
        except (Error,self.share.Error,OSError,ValueError):
            error='The anonymity guard or selected uplink could not be verified.'
        config=MODES[state['mode']]
        return {'mode':state['mode'],'phase':'degraded' if error else state['phase'],
                'ready':not error and state['phase']=='active','interface':state['selection']['interface'],
                'selection':state['selection'],'uid':state['uid'],'tcp_port':config['tcp_port'],
                'dns_port':config['dns_port'],'error':error}
