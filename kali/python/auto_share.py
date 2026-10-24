#!/usr/bin/env python3
"""Runtime-only, single-uplink sharing for the managed Pi4 control network."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import importlib.util
import pwd
import socket
import struct
import ipaddress
import json
import os
from pathlib import Path
import grp
import re
import stat
import subprocess
import sys
import tempfile
import time


def selection_support():
    path = Path(__file__).with_name("adapter_selection.py") if Path(__file__).name == "auto_share.py" else Path("/usr/local/libexec/automations-support/adapter_selection.py")
    if Path(__file__).name != "auto_share.py":
        for entry in (path, *path.parents):
            info = entry.lstat()
            if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError("Unsafe Automations selection helper.")
    spec = importlib.util.spec_from_file_location("_share_selection_common", path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


# Data-only role contract: help and firewall inspection do not execute helpers.
# Its equality with the shared selector and privacy contracts is tested.
GUEST = {"interface":"autoap0","network":"10.79.0.0/24","address":"10.79.0.1",
         "host":"169.254.95.1","peer":"169.254.95.2","transit":"169.254.95.0/30"}

CTRL = "ctrl0"
PRIVACY_API = 1
PRIVACY_DNS_API = 1
ADDRESS = "10.78.0.1"
SUBNET = "10.78.0.0/24"
TABLE = 17855
PRIORITY = 17855
LOCAL_PRIORITY = 17856
LINK_PRIORITY = 17854
GATE = "auto_share_gate"
DNS_UID = 65534
MARK = 0x4155544F
DNS_PORT = 1053
SERVICE = "auto-share-dns.service"
UNIT = "run/systemd/system/" + SERVICE
STATE = "run/automations-share/state.json"
DNS_SERVERS = "run/auto-share-dns.servers"
REFRESH_STATE = "run/automations-share/refresh.json"
WATCH_STATE = "run/automations-share/watch.json"
WATCH_SERVICE = "automations-share-watch.service"
WATCH_TIMER = "automations-share-watch.timer"
WATCH_SERVICE_TEXT = """[Unit]
Description=Inspect and refresh the selected Pi4 sharing uplink
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 -I /usr/local/libexec/automations/share --internal-watch
TimeoutStartSec=0
User=root
Group=root
UMask=0077
NoNewPrivileges=yes
ProtectHome=yes
PrivateTmp=yes
RestrictSUIDSGID=yes
"""
WATCH_TIMER_TEXT = """[Unit]
Description=Watch the active Pi4 sharing selection

[Timer]
OnActiveSec=30s
OnUnitInactiveSec=30s
AccuracySec=1s
Unit=automations-share-watch.service
"""
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
CONFIGS = {
    "etc/NetworkManager/conf.d/90-pi4-control.conf": "[device-pi4-control]\nmatch-device=interface-name:ctrl0;driver:brcmfmac\nmanaged=0",
    "etc/systemd/network/10-pi4-control.link": "[Match]\nDriver=brcmfmac\n[Link]\nName=ctrl0",
    "etc/systemd/network/20-pi4-control.network": "[Match]\nName=ctrl0\n[Link]\nRequiredForOnline=no\n[Network]\nAddress=10.78.0.1/24\nDHCP=no\nLinkLocalAddressing=no\nIPv6AcceptRA=no\nConfigureWithoutCarrier=yes",
    "etc/dnsmasq.d/pi4-control.conf": "interface=ctrl0\nexcept-interface=lo\nbind-dynamic\nno-resolv\nno-hosts\nlocal=/pi4/\nhost-record=pi4,10.78.0.1\ndhcp-range=10.78.0.20,10.78.0.99,255.255.255.0,12h\ndhcp-option=3,10.78.0.1\ndhcp-option=6,10.78.0.1\ndhcp-authoritative",
}


class Error(RuntimeError):
    pass


class Busy(Error):
    pass


LOCK_OWNER_LABELS = {
    "automations-share-watch.service": "Share watcher",
    "automations-tor-recovery.service": "Tor recovery check",
    "automations-tor-rotation.service": "Tor rotation worker",
}


def _lock_proc_text(path, maximum):
    """Read bounded kernel diagnostics; never inspect a command line or secrets."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        data = bytearray()
        while len(data) <= maximum:
            block = os.read(fd, min(65536, maximum + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        if len(data) > maximum:
            raise ValueError("Oversized lock diagnostic.")
        return data.decode("ascii")
    finally:
        os.close(fd)


def _sharing_lock_pid(info, proc_root):
    owners = set()
    for line in _lock_proc_text(proc_root / "locks", 1024 * 1024).splitlines():
        fields = line.split()
        if (len(fields) != 8 or not re.fullmatch(r"[0-9]+:", fields[0])
                or fields[1:3] != ["FLOCK", "ADVISORY"] or fields[3] not in ("READ", "WRITE")
                or not re.fullmatch(r"[1-9][0-9]*", fields[4]) or fields[6:] != ["0", "EOF"]):
            continue
        device = fields[5].split(":")
        if (len(device) != 3 or not all(re.fullmatch(r"[0-9a-fA-F]+", x) for x in device[:2])
                or not re.fullmatch(r"[1-9][0-9]*", device[2])):
            continue
        if (int(device[0], 16), int(device[1], 16), int(device[2])) == (os.major(info.st_dev), os.minor(info.st_dev), info.st_ino):
            owners.add(int(fields[4]))
    return next(iter(owners)) if len(owners) == 1 else None


def _lock_process_start(proc_root, pid):
    text = _lock_proc_text(proc_root / str(pid) / "stat", 8192)
    head, separator, tail = text.rpartition(") ")
    fields = tail.split()
    if (not separator or not head.startswith(str(pid) + " (") or len(fields) < 20
            or not fields[19].isdigit()):
        raise ValueError("Unrecognized process identity.")
    return fields[19]


def sharing_busy_message(fd, proc_root=Path("/proc")):
    """Describe a still-observed holder without changing or waiting for its lock."""
    prefix = "Another sharing operation is running. "
    unknown = prefix + "Owner is no longer observable or could not be determined; retry shortly."
    try:
        info = os.fstat(fd)
        pid = _sharing_lock_pid(info, proc_root)
        if pid is None:
            return unknown
        start = _lock_process_start(proc_root, pid)
        cgroup = _lock_proc_text(proc_root / str(pid) / "cgroup", 65536)
        services = set()
        for line in cgroup.splitlines():
            fields = line.split(":", 2)
            if (len(fields) == 3 and fields[0].isdigit()
                    and (fields[1] == "" or "name=systemd" in fields[1].split(","))
                    and fields[2].startswith("/")):
                services.update(part for part in fields[2].split("/") if part in LOCK_OWNER_LABELS)
        if (_sharing_lock_pid(info, proc_root) != pid or _lock_process_start(proc_root, pid) != start
                or _lock_proc_text(proc_root / str(pid) / "cgroup", 65536) != cgroup):
            return unknown
        owner = "PID " + str(pid)
        if len(services) == 1:
            service = next(iter(services))
            owner = LOCK_OWNER_LABELS[service] + " (" + service + ", PID " + str(pid) + ")"
        return prefix + "Observed owner: " + owner + ". Retry shortly."
    except (OSError, UnicodeError, ValueError):
        return unknown


def require(condition, message):
    if not condition:
        raise Error(message)


def run_command(args, input_text=None, accepted=(0,)):
    try:
        result = subprocess.run(args, input=input_text, text=True, capture_output=True,
                                timeout=20, env=ENV, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Error("A required system command is unavailable or timed out.") from None
    require(result.returncode in accepted,
            "A system command failed; its output was withheld to avoid disclosing configuration.")
    return result.stdout


def canonical(text):
    return "\n".join(line.strip() for line in text.splitlines()
                     if line.strip() and not line.lstrip().startswith("#"))


def iface_name(value):
    require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}", value),
            "Unsupported interface name.")
    return value


def ipv4(value):
    try:
        address = ipaddress.IPv4Address(value)
        require(not (address.is_unspecified or address.is_loopback or address.is_multicast or
                     address.is_link_local or address.is_reserved), "Unusable upstream IPv4 address.")
        require(address not in ipaddress.ip_network(SUBNET), "The upstream overlaps the control network.")
        return str(address)
    except (ValueError, TypeError):
        raise Error("Invalid upstream IPv4 address.") from None



def nm_dns_servers(raw, version, interface):
    """Parse native nmcli DNS arrays: separate lines or pipe-separated values."""
    message = f"Cannot read IPv{version} DNS servers from NetworkManager: invalid address list or scope."
    try:
        require(isinstance(raw, str) and len(raw) <= 8192, message)
        result = []
        for line in raw.splitlines():
            if not line.strip():
                continue
            for item in line.split("|"):
                value = item.strip()
                require(bool(value), message)
                if version == 4:
                    value = ipv4(value)
                else:
                    plain, *scope = value.split("%")
                    address = ipaddress.IPv6Address(plain)
                    require(not (address.is_loopback or address.is_unspecified or address.is_multicast), message)
                    require(scope in ([], [interface]) if address.is_link_local else not scope, message)
                    value = str(address) + ("%" + interface if address.is_link_local else "")
                if value not in result:
                    result.append(value)
                require(len(result) <= 16, message)
        return result
    except (Error, ValueError, TypeError):
        raise Error(message) from None


def match(left, right, op="=="):
    return {"match": {"op": op, "left": left, "right": right}}


def meta(key, value, op="=="):
    return match({"meta": {"key": key}}, value, op)


def payload(protocol, field, value):
    return match({"payload": {"protocol": protocol, "field": field}}, value)


PREFIX = {"prefix": {"addr": "10.78.0.0", "len": 24}}
ACCEPT = {"accept": None}
DROP = {"drop": None}
BASE_INPUT = [
    [meta("iifname", "lo"), ACCEPT],
    [match({"ct": {"key": "state"}}, {"set": ["established", "related"]}), ACCEPT],
    [meta("iifname", CTRL), payload("udp", "sport", 68), payload("udp", "dport", 67), ACCEPT],
    [meta("iifname", CTRL), payload("udp", "dport", 53), ACCEPT],
    [meta("iifname", CTRL), payload("tcp", "dport", 53), ACCEPT],
    [meta("iifname", CTRL), payload("ip", "protocol", "icmp"), ACCEPT],
    [meta("iifname", CTRL), payload("tcp", "dport", {"set": [80, 443]}), ACCEPT],
]
SSH_INPUT = [meta("iifname", CTRL), payload("tcp", "dport", 22), ACCEPT]


def rule(table, chain, expr, comment):
    return {"family": "inet", "table": table, "chain": chain, "expr": expr, "comment": comment}


def dns_rules():
    return [rule("pi4", "input", [meta("iifname", CTRL), payload("ip", "saddr", PREFIX),
                 payload("ip", "daddr", ADDRESS), payload(proto, "dport", DNS_PORT), ACCEPT],
                 "auto-share:dns-" + proto + "-v1") for proto in ("udp", "tcp")]


def control_enabled(selection):
    return CTRL in selection.get("sources", [CTRL])


def guest_enabled(selection):
    return bool(selection.get("guest")) and GUEST["interface"] in selection.get("sources", [GUEST["interface"]])


def ipv6_input_rules(selection):
    """Exact SSH-composition contract: order and comments are deliberate."""
    upstream = iface_name(selection["interface"])
    nd = payload("icmpv6", "type", {"set": [135, 136]})
    hop = payload("ip6", "hoplimit", 255)
    ll = {"prefix": {"addr": "fe80::", "len": 10}}
    result = [
        rule("pi4", "input", [meta("iifname", upstream), payload("ip6", "saddr", ll), hop,
             payload("icmpv6", "type", 134), ACCEPT], "auto-share:upstream-ra-v2"),
        rule("pi4", "input", [meta("iifname", upstream), hop, nd, ACCEPT], "auto-share:upstream-nd-v2"),
        rule("pi4", "input", [meta("iifname", upstream), payload("icmpv6", "type", {"set": [1, 2, 3, 4]}),
             ACCEPT], "auto-share:upstream-errors-v2"),
        rule("pi4", "input", [meta("iifname", upstream), payload("ip6", "saddr", ll),
             payload("ip6", "hoplimit", 1), payload("icmpv6", "type", 130), ACCEPT], "auto-share:upstream-mld-v2"),
        rule("pi4", "input", [meta("iifname", upstream), meta("nfproto", "ipv6"),
             payload("udp", "sport", 547), payload("udp", "dport", 546), ACCEPT], "auto-share:upstream-dhcp6-v2"),
        rule("pi4", "input", [meta("iifname", CTRL), hop,
             payload("icmpv6", "type", {"set": [133, 135, 136]}), ACCEPT], "auto-share:control-nd-v2"),
    ]
    if selection.get("ipv6") and control_enabled(selection):
        prefix = ipaddress.IPv6Network(selection["control6"]["network"])
        for proto in ("udp", "tcp"):
            result.append(rule("pi4", "input", [meta("iifname", CTRL),
                payload("ip6", "saddr", {"prefix": {"addr": str(prefix.network_address), "len": 64}}),
                payload("ip6", "daddr", selection["control6"]["address"]), payload(proto, "dport", DNS_PORT),
                ACCEPT], "auto-share:dns6-" + proto + "-v2"))
    return result


def input_rules(selection):
    result = (dns_rules() if control_enabled(selection) else []) + ipv6_input_rules(selection)
    if "sources" in selection:
        for name, enabled in ((CTRL, control_enabled(selection)), (GUEST["interface"], guest_enabled(selection))):
            if not enabled:
                for proto in ("tcp", "udp"):
                    result.insert(0, rule("pi4", "input", [meta("iifname", name), payload(proto,"dport",DNS_PORT), DROP],
                        "auto-share:excluded-dns-"+name+"-"+proto))
    if guest_enabled(selection):
        for source in (GUEST["peer"], {"prefix": {"addr": "10.79.0.0", "len": 24}}):
            for proto in ("tcp", "udp"):
                result.append(rule("pi4", "input", [meta("iifname", GUEST["interface"]), payload("ip", "saddr", source),
                    payload("ip", "daddr", ADDRESS), payload(proto,"dport",DNS_PORT),ACCEPT],
                    "auto-share:guest-dns-"+proto+("-peer" if isinstance(source,str) else "-client")))
    return result


def local_exceptions():
    # Only local control traffic and essential link maintenance survive a gate.
    return [
        [meta("oifname", "lo"), ACCEPT],
        [meta("oifname", CTRL), payload("ip", "daddr", PREFIX), ACCEPT],
        [meta("oifname", CTRL), payload("ip6", "daddr", {"prefix": {"addr": "fd00::", "len": 8}}), ACCEPT],
        [meta("oifname", CTRL), payload("ip6", "daddr", {"prefix": {"addr": "fe80::", "len": 10}}), ACCEPT],
        [meta("oifname", CTRL), payload("udp", "sport", 67), payload("udp", "dport", 68), ACCEPT],
        [payload("udp", "sport", 68), payload("udp", "dport", 67), ACCEPT],
        [meta("nfproto", "ipv6"), payload("ip6", "hoplimit", 255),
         payload("icmpv6", "type", {"set": [133, 134, 135, 136]}), ACCEPT],
        [meta("nfproto", "ipv6"), payload("ip6", "hoplimit", 1),
         payload("icmpv6", "type", {"set": [130, 131, 132, 143]}), ACCEPT],
        [meta("nfproto", "ipv6"), payload("udp", "sport", 546), payload("udp", "dport", 547), ACCEPT],
    ]


def gate_objects():
    result = [("table", {"family": "inet", "name": GATE})]
    for name in ("output", "forward"):
        result.append(("chain", {"family": "inet", "table": GATE, "name": name,
                     "type": "filter", "hook": name, "prio": -20, "policy": "drop"}))
    result += [("rule", rule(GATE, "output", expr, "auto-share:gate-" + str(index)))
               for index, expr in enumerate(local_exceptions())]
    return result


def nft_objects(selection):
    """Scoped IPv4/IPv6 egress for this Pi and its control clients."""
    upstream = selection["interface"]
    established = match({"ct": {"key": "state"}}, {"set": ["established", "related"]})
    set_mark = {"mangle": {"key": {"ct": {"key": "mark"}}, "value": MARK}}
    result = [("table", {"family": "inet", "name": "auto_share"}),
              ("chain", {"family": "inet", "table": "pi4", "name": "auto_share_forward"})]
    for name, kind, hook, priority in (("guard", "filter", "forward", -10),
            ("egress", "filter", "output", 10), ("dns", "nat", "prerouting", -100),
            ("local_dns", "nat", "output", -100), ("nat", "nat", "postrouting", 100)):
        result.append(("chain", {"family": "inet", "table": "auto_share", "name": name,
                     "type": kind, "hook": hook, "prio": priority, "policy": "accept"}))
    result += [("rule", item) for item in input_rules(selection)]
    result.append(("rule", rule("pi4", "forward", [{"jump": {"target": "auto_share_forward"}}],
                               "auto-share:forward-v2")))
    families = [("ip", PREFIX, ADDRESS)] if control_enabled(selection) else []
    if selection.get("ipv6") and control_enabled(selection):
        net = ipaddress.IPv6Network(selection["control6"]["network"])
        families.append(("ip6", {"prefix": {"addr": str(net.network_address), "len": 64}}, selection["control6"]["address"]))
    for family, prefix, address in families:
        result.append(("rule", rule("pi4", "auto_share_forward", [
            meta("iifname", CTRL), meta("oifname", upstream), payload(family, "saddr", prefix),
            match({"ct": {"key": "state"}}, {"set": ["new", "established", "related"]}), set_mark, ACCEPT],
            "auto-share:out-" + family + "-v2")))
        result.append(("rule", rule("pi4", "auto_share_forward", [
            meta("iifname", upstream), meta("oifname", CTRL), payload(family, "daddr", prefix),
            established, match({"ct": {"key": "mark"}}, MARK), ACCEPT], "auto-share:return-" + family + "-v2")))
        result.append(("rule", rule("auto_share", "nat", [meta("iifname", CTRL), meta("oifname", upstream),
            payload(family, "saddr", prefix), {"masquerade": None}], "auto-share:nat-" + family + "-v2")))
        for proto in ("udp", "tcp"):
            result.append(("rule", rule("auto_share", "dns", [meta("iifname", CTRL),
                payload(family, "saddr", prefix), payload(proto, "dport", 53), set_mark,
                {"dnat": {"family": family, "addr": address, "port": DNS_PORT}}],
                "auto-share:redirect-" + family + "-" + proto + "-v2")))
    if guest_enabled(selection):
        prefix = {"prefix": {"addr": "10.79.0.0", "len": 24}}
        name = GUEST["interface"]
        result += [("rule", rule("pi4","auto_share_forward",[meta("iifname",name),meta("oifname",upstream),payload("ip","saddr",prefix),set_mark,ACCEPT],"auto-share:guest-out")),
            ("rule",rule("pi4","auto_share_forward",[meta("iifname",upstream),meta("oifname",name),payload("ip","daddr",prefix),established,match({"ct":{"key":"mark"}},MARK),ACCEPT],"auto-share:guest-return")),
            ("rule",rule("auto_share","nat",[meta("iifname",name),meta("oifname",upstream),payload("ip","saddr",prefix),{"masquerade":None}],"auto-share:guest-nat"))]
        for incoming,outgoing in ((name,upstream),(upstream,name)):
            result.append(("rule",rule("auto_share","guard",[meta("iifname",incoming),meta("oifname",outgoing),{"return":None}],"auto-share:guest-pair-"+incoming)))
        for proto in ("tcp","udp"):
            result.append(("rule",rule("auto_share","dns",[meta("iifname",name),payload("ip","saddr",prefix),payload(proto,"dport",53),set_mark,
                {"dnat":{"family":"ip","addr":ADDRESS,"port":DNS_PORT}}],"auto-share:guest-redirect-"+proto)))
    # Do not accept unrelated forwards, even if global IPv6 forwarding is needed.
    for incoming, outgoing in (((CTRL, upstream), (upstream, CTRL)) if control_enabled(selection) else []):
        result.append(("rule", rule("auto_share", "guard", [meta("iifname", incoming),
            meta("oifname", outgoing), {"return": None}], "auto-share:pair-" + incoming)))
    result.append(("rule", rule("auto_share", "guard", [DROP], "auto-share:no-other-forward-v2")))
    for index, expr in enumerate(local_exceptions()):
        result.append(("rule", rule("auto_share", "egress", expr, "auto-share:local-" + str(index))))
    if guest_enabled(selection):
        for label,target in (("clients",{"prefix":{"addr":"10.79.0.0","len":24}}),("resolver",GUEST["peer"])):
            result.append(("rule",rule("auto_share","egress",[meta("oifname",GUEST["interface"]),payload("ip","daddr",target),established,ACCEPT],"auto-share:guest-reply-"+label)))
    if selection.get("ipv6"):
        net = ipaddress.IPv6Network(selection["control6"]["network"])
        result.append(("rule", rule("auto_share", "egress", [meta("oifname", CTRL),
            payload("ip6", "daddr", {"prefix": {"addr": str(net.network_address), "len": 64}}), ACCEPT],
            "auto-share:control6-local-v2")))
    for family, addresses in (("ip", [selection["address"]]),
            ("ip6", selection["ipv6"]["addresses"] if selection.get("ipv6") else [])):
        if addresses:
            result.append(("rule", rule("auto_share", "egress", [meta("oifname", upstream),
                payload(family, "saddr", {"set": addresses}), set_mark, ACCEPT], "auto-share:pi-out-" + family + "-v2")))
    link_dns = [x.split("%", 1)[0] for x in selection["dns"] if ":" in x and ipaddress.IPv6Address(x.split("%", 1)[0]).is_link_local]
    result.append(("rule", rule("auto_share", "egress", [meta("oifname", upstream),
        match({"ct": {"key": "mark"}}, MARK), established, ACCEPT], "auto-share:existing-selected-flow-v1")))
    if link_dns:
        for proto in ("udp", "tcp"):
            result.append(("rule", rule("auto_share", "egress", [meta("oifname", upstream), meta("skuid", DNS_UID),
                payload("ip6", "saddr", {"prefix": {"addr": "fe80::", "len": 10}}),
                payload("ip6", "daddr", {"set": link_dns}), payload(proto, "dport", 53), set_mark, ACCEPT],
                "auto-share:resolver-linklocal-" + proto + "-v2")))
    result.append(("rule", rule("auto_share", "egress", [DROP], "auto-share:pi-no-fallback-v2")))
    # The fixed unprivileged dnsmasq UID is exempt from interception, but only its
    # exact configured upstream servers are permitted. No recursive resolver loop.
    for family, target in (("ip", ADDRESS), ("ip6", "::1")):
        servers = [x.split("%", 1)[0] for x in selection["dns"] if (":" in x) == (family == "ip6")]
        for proto in ("udp", "tcp"):
            if servers:
                result.append(("rule", rule("auto_share", "local_dns", [meta("skuid", DNS_UID),
                    meta("oifname", upstream), payload(family, "daddr", {"set": servers}),
                    payload(proto, "dport", 53), {"return": None}], "auto-share:resolver-" + family + "-" + proto)))
            result.append(("rule", rule("auto_share", "local_dns", [meta("skuid", DNS_UID),
                meta("nfproto", "ipv6" if family == "ip6" else "ipv4"), payload(proto, "dport", 53), DROP],
                "auto-share:resolver-deny-" + family + "-" + proto)))
            result.append(("rule", rule("auto_share", "local_dns", [meta("nfproto", "ipv6" if family == "ip6" else "ipv4"),
                payload(proto, "dport", 53), set_mark, {"dnat": {"family": family, "addr": target, "port": DNS_PORT}}],
                "auto-share:pi-dns-" + family + "-" + proto)))
    return result


def nft_add(selection):
    objects = nft_objects(selection)
    commands = [{"add": {kind: value}} for kind, value in objects
                if not (kind == "rule" and value["table"] == "pi4" and value["chain"] == "input")]
    commands += [{"insert": {"rule": value}} for value in reversed(input_rules(selection))]
    return {"nftables": commands}


def normalize(value):
    """Normalize only harmless native nft JSON spelling differences."""
    value = json.loads(json.dumps(value))
    if isinstance(value, dict):
        for key in ("handle", "index", "position"):
            value.pop(key, None)
        for statement in value.get("expr", []):
            expression = statement.get("match", {})
            right = expression.get("right")
            if expression.get("left") == {"payload": {"protocol": "icmpv6", "field": "type"}}:
                types = {"destination-unreachable": 1, "packet-too-big": 2, "time-exceeded": 3,
                         "parameter-problem": 4, "mld-listener-query": 130, "nd-router-solicit": 133,
                         "nd-router-advert": 134, "nd-neighbor-solicit": 135, "nd-neighbor-advert": 136,
                         "mld-listener-report": 131, "mld-listener-done": 132, "mld2-listener-report": 143}
                if isinstance(right, str): expression["right"] = types.get(right, right)
                elif isinstance(right, dict) and "set" in right:
                    expression["right"] = {"set": [types.get(x, x) for x in right["set"]]}
            if expression.get("left") == {"ct": {"key": "state"}} and isinstance(right, list):
                expression["right"] = {"set": right}
            if isinstance(expression.get("right"), dict) and "set" in expression["right"]:
                expression["right"]["set"] = sorted(expression["right"]["set"], key=str)
                if expression.get("op") == "in":
                    expression["op"] = "=="
                if len(expression["right"]["set"]) == 1:
                    expression["right"] = expression["right"]["set"][0]
        # Native nft removes explicit nfproto checks already implied by a payload.
        protocols = {x.get("match", {}).get("left", {}).get("payload", {}).get("protocol") for x in value.get("expr", [])}
        implied = "ipv6" if protocols & {"ip6", "icmpv6"} else "ipv4" if protocols & {"ip", "icmp"} else None
        if implied and "expr" in value:
            value["expr"] = [x for x in value.get("expr", []) if x != meta("nfproto", implied)]
    return value


def firewall_check(data, selection=None):
    """Refuse unknown Pi4 rules or modifications of owned objects before deleting anything."""
    require(isinstance(data, dict) and isinstance(data.get("nftables"), list), "Invalid firewall response.")
    relevant = []
    for item in data["nftables"]:
        for kind, value in item.items():
            if not isinstance(value, dict):
                continue
            if value.get("family") == "inet" and (value.get("table") in ("pi4", "auto_share") or
                    kind == "table" and value.get("name") in ("pi4", "auto_share")):
                relevant.append((kind, value))
    owned = nft_objects(selection) if selection else []
    remaining = list(relevant)
    for kind, expected in owned:
        found = [(i, actual) for i, (actual_kind, actual) in enumerate(remaining)
                 if kind == actual_kind and normalize(actual) == normalize(expected)]
        require(len(found) == 1, "Sharing firewall objects are missing or changed; refusing unsafe cleanup.")
        remaining.pop(found[0][0])
    expected_chains = [{"family": "inet", "table": "pi4", "name": name, "type": "filter",
                        "hook": name, "prio": 0, "policy": policy}
                       for name, policy in (("input", "drop"), ("forward", "drop"), ("output", "accept"))]
    tables = [normalize(value) for kind, value in remaining if kind == "table"]
    chains = [normalize(value) for kind, value in remaining if kind == "chain"]
    require(tables == [{"family": "inet", "name": "pi4"}] and
            sorted(chains, key=lambda x: x.get("name", "")) == sorted(expected_chains, key=lambda x: x["name"]),
            "Unrecognized managed firewall tables or chains.")
    rules = [value for kind, value in remaining if kind == "rule"]
    require(all(value.get("chain") == "input" and not value.get("comment") for value in rules),
            "Unrecognized managed firewall rule.")
    expressions = [normalize(value)["expr"] for value in rules]
    base = [normalize({"expr": expr})["expr"] for expr in BASE_INPUT]
    require(expressions in (base, base + [SSH_INPUT]), "The live firewall is not the supported Pi4 configuration.")
    require(len(remaining) == len(tables) + len(chains) + len(rules), "Unrecognized firewall object.")
    # Input rule order is part of the SSH composition contract.
    if selection:
        inputs = [value for kind, value in relevant if kind == "rule" and value.get("table") == "pi4" and value.get("chain") == "input"]
        require([normalize(item) for item in inputs[:len(input_rules(selection))]] == [normalize(item) for item in input_rules(selection)],
                "Unexpected sharing DNS rule order.")
    return relevant


def nft_delete(data, selection):
    objects = firewall_check(data, selection)
    commands = []
    for kind, value in objects:
        if kind == "rule" and value.get("table") == "pi4" and value.get("chain") in ("input", "forward") and value.get("comment", "").startswith("auto-share:"):
            require(type(value.get("handle")) is int and value["handle"] > 0, "Missing owned rule handle.")
            commands.append({"delete": {"rule": {key: value[key] for key in ("family", "table", "chain", "handle")}}})
    commands += [{"flush": {"chain": {"family": "inet", "table": "pi4", "name": "auto_share_forward"}}},
                 {"delete": {"chain": {"family": "inet", "table": "pi4", "name": "auto_share_forward"}}},
                 {"delete": {"table": {"family": "inet", "name": "auto_share"}}}]
    return {"nftables": commands}


def servers_text(selection, tor=False):
    validate_selection(selection)
    if tor:
        # Dnsmasq may reuse upstream records across HUP. Keep an explicit
        # loopback binding and use bind-dynamic below so check_servers refreshes
        # the cached interface index when switching from a physical uplink.
        # The privacy guard still forbids direct resolver egress.
        return "server=127.0.0.1#19053@lo\n"
    return "".join("server=" + address + "@" + selection["interface"] +
                   ("@" + selection["address"] if ":" not in address else "") + "\n"
                   for address in selection["dns"])


def unit_text(selection, inline=False):
    args = ["/usr/sbin/dnsmasq", "--keep-in-foreground", "--conf-file=/dev/null", "--pid-file=",
            "--user=nobody", "--group=nogroup", "--port=1053", "--listen-address=10.78.0.1,127.0.0.1,::1",
            "--bind-dynamic", "--no-resolv", "--no-hosts", "--no-poll", "--local=/pi4/", "--host-record=pi4,10.78.0.1"]
    if selection.get("ipv6") and control_enabled(selection):
        control = selection["control6"]
        # RA checks interface names, not listen-address entries (AF_LOCAL in
        # dnsmasq iface_check). Explicitly admit only the control interface.
        args += ["--interface=ctrl0", "--listen-address=" + control["address"], "--enable-ra", "--no-dhcpv4-interface=ctrl0",
                 "--dhcp-range=" + str(ipaddress.IPv6Network(control["network"]).network_address) + ",ra-only,64,120s",
                 "--dhcp-option=option6:dns-server,[" + control["address"] + "]", "--ra-param=ctrl0,10,30"]
    else:
        args.append("--no-dhcp-interface=ctrl0")
    args += ["--" + line for line in servers_text(selection).splitlines()] if inline else ["--servers-file=/" + DNS_SERVERS]
    return ("[Unit]\nDescription=Automations selected-uplink DNS and IPv6 RA\n"
            "After=network.target\n[Service]\nType=simple\nExecStart=" + " ".join(args) +
            "\nRestart=no\nNoNewPrivileges=yes\nProtectHome=yes\nProtectSystem=strict\n"
            "PrivateTmp=yes\nRestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK\n")


def validate_selection(selection):
    required={"mode", "interface", "address", "network", "gateway", "dns", "ipv6", "control6"}
    require(isinstance(selection, dict) and required <= set(selection) <= required | {"guest", "sources"}, "Invalid stored upstream selection.")
    if "sources" in selection:
        sources = selection["sources"]
        require(isinstance(sources, list) and len(sources) <= 2
                and all(isinstance(x,str) and x in (CTRL,GUEST["interface"]) for x in sources)
                and len(set(sources)) == len(sources)
                and (GUEST["interface"] not in sources or selection.get("guest") == GUEST), "Invalid sharing source selection.")
    if "guest" in selection:
        require(selection["guest"] == GUEST, "Invalid additional AP routing role.")
        require(not ipaddress.ip_network(selection["network"]).overlaps(ipaddress.ip_network(GUEST["network"]))
            and not ipaddress.ip_network(selection["network"]).overlaps(ipaddress.ip_network(GUEST["transit"])),"The upstream conflicts with the additional AP subnet.")
    require(selection["mode"] in ("wifi", "lan"), "Invalid sharing mode.")
    require(iface_name(selection["interface"]) != CTRL, "The control interface cannot be an upstream.")
    address, gateway = ipv4(selection["address"]), ipv4(selection["gateway"])
    try:
        network = ipaddress.IPv4Network(selection["network"])
        require(not network.overlaps(ipaddress.ip_network(SUBNET)) and
                ipaddress.ip_address(address) in network and ipaddress.ip_address(gateway) in network,
                "Unsupported upstream subnet or gateway.")
        control = selection["control6"]
        require(set(control) == {"network", "address", "linklocal"}, "Invalid control IPv6 state.")
        prefix = ipaddress.IPv6Network(control["network"])
        require(prefix.prefixlen == 64 and prefix.subnet_of(ipaddress.IPv6Network("fd00::/8")) and
                ipaddress.IPv6Address(control["address"]) == prefix.network_address + 1 and
                ipaddress.IPv6Address(control["linklocal"]).is_link_local, "Invalid control IPv6 prefix.")
        v6 = selection["ipv6"]
        if v6 is not None:
            require(set(v6) == {"addresses", "address", "network", "gateway"} and
                    1 <= len(v6["addresses"]) <= 16 and len(set(v6["addresses"])) == len(v6["addresses"]), "Invalid upstream IPv6 state.")
            net6 = ipaddress.IPv6Network(v6["network"])
            for candidate in v6["addresses"]:
                require(ipaddress.IPv6Address(candidate) in ipaddress.IPv6Network("2000::/3"), "Upstream IPv6 is not global unicast.")
            require(v6["address"] in v6["addresses"] and ipaddress.IPv6Address(v6["address"]) in net6 and
                    (ipaddress.IPv6Address(v6["gateway"]).is_link_local or ipaddress.IPv6Address(v6["gateway"]) in net6),
                    "Invalid upstream IPv6 gateway/source.")
        require(isinstance(selection["dns"], list) and 1 <= len(selection["dns"]) <= 16 and
                len(set(selection["dns"])) == len(selection["dns"]), "The upstream requires DNS servers.")
        for server in selection["dns"]:
            if ":" not in server:
                ipv4(server)
            else:
                plain, *scope = server.split("%")
                value = ipaddress.IPv6Address(plain)
                require(v6 is not None and not (value.is_loopback or value.is_unspecified or value.is_multicast) and
                        (scope == [selection["interface"]] if value.is_link_local else not scope), "Invalid upstream IPv6 DNS server.")
    except (ValueError, TypeError, KeyError):
        raise Error("Invalid upstream or control addressing.") from None
    return selection


def operational_state(record):
    # IFF_UP is administrative; an unplugged/disconnected device may still have it.
    value = record.get("operstate")
    return value.lower() if isinstance(value, str) and value in {
        "UNKNOWN", "NOTPRESENT", "DOWN", "LOWERLAYERDOWN", "TESTING", "DORMANT", "UP"
    } else "unknown"


class Platform:
    """Dependency injection is for offline tests; production offers no filesystem override."""
    def __init__(self, root=Path("/"), runner=run_command, owner=0):
        self.root, self.run, self.owner = Path(root), runner, owner

    def path(self, relative):
        return self.root / relative

    def trusted(self, relative, directory=False):
        path = self.root
        for part in Path(relative).parts:
            path /= part
            info = path.lstat()
            require(not stat.S_ISLNK(info.st_mode) and info.st_uid == self.owner and not info.st_mode & 0o022,
                    "Unsafe managed file ownership, permissions or link.")
        require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
                "Unexpected managed file type.")
        return path

    def read(self, relative):
        path = self.trusted(relative)
        require(path.stat().st_size <= 65536, "Managed file is too large.")
        return path.read_text(encoding="utf-8")

    def write(self, relative, text, expected=None, mode=0o600):
        require(mode in (0o600, 0o644), "Unexpected runtime file permissions.")
        path = self.path(relative)
        self.trusted(str(Path(relative).parent), directory=True)
        old = self.read(relative) if path.exists() or path.is_symlink() else None
        require(old == expected, "Concurrent or unrecognized runtime file found; refusing overwrite.")
        fd, temporary = tempfile.mkstemp(prefix=".auto-share-", dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                os.fchmod(stream.fileno(), mode)
                stream.write(text)
                stream.flush()
                os.fsync(stream.fileno())
            current = self.read(relative) if path.exists() or path.is_symlink() else None
            require(current == old, "Concurrent runtime file edit detected.")
            os.replace(temporary, path)
        finally:
            Path(temporary).unlink(missing_ok=True)

    @contextmanager
    def lock(self):
        self.trusted("run", directory=True)
        fd = os.open(self.path("run/automations-share.lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == self.owner and info.st_nlink == 1 and
                    stat.S_IMODE(info.st_mode) == 0o600, "Unsafe sharing lock.")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Busy(sharing_busy_message(fd)) from None
            if self.path(REFRESH_STATE).exists() or self.path(REFRESH_STATE).is_symlink():
                self.refresh_support().resume(self)
            yield
        finally:
            os.close(fd)

    def validate(self, ready=True):
        # os-release is commonly a distribution-maintained symlink.
        require(re.search(r'(?m)^ID=(?:kali|"kali")$', self.path("etc/os-release").read_text()),
                "This command requires the managed Kali Pi4 image.")
        for relative, expected in CONFIGS.items():
            require(canonical(self.read(relative)) == expected, "Unrecognized control-network configuration.")
        if not ready:
            return
        control = self.ip("-j", "address", "show", "dev", CTRL)
        require(len(control) == 1 and "UP" in control[0].get("flags", []) and
                any(x.get("family") == "inet" and x.get("local") == ADDRESS and x.get("prefixlen") == 24
                    for x in control[0].get("addr_info", [])), "The control network is not ready.")

    def ip(self, *args):
        try:
            result = json.loads(self.run(["/usr/sbin/ip", *args]))
            require(isinstance(result, list), "Invalid iproute2 response.")
            return result
        except (ValueError, TypeError):
            raise Error("Invalid iproute2 response.") from None

    def firewall(self):
        try:
            data = json.loads(self.run(["/usr/sbin/nft", "--json", "list", "ruleset"]))
            if self.path("run/automations-anonymity/state.json").exists() or any(
                    item.get("table", {}).get("name") == "auto_privacy" or
                    item.get("rule", {}).get("comment", "").startswith("auto-privacy:")
                    for item in data.get("nftables", [])):
                helper = self.trusted("usr/local/libexec/automations-support/egress.py")
                spec = importlib.util.spec_from_file_location("_automations_share_privacy", helper)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                try:
                    data = module.firewall_view(data, self.root, self.owner)
                except module.Error as error:
                    raise Error(str(error)) from None
            return data
        except ValueError:
            raise Error("Invalid firewall response.") from None

    def nft(self, batch):
        self.run(["/usr/sbin/nft", "--json", "-f", "-"], json.dumps(batch))

    def refresh_support(self):
        path = (Path(__file__).with_name("share_refresh.py") if Path(__file__).name == "auto_share.py"
                else self.trusted("usr/local/libexec/automations-support/share_refresh.py"))
        spec = importlib.util.spec_from_file_location("_automations_share_refresh", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.share = sys.modules.get(__name__)
        # importlib fixture loaders need not register their module in sys.modules.
        if module.share is None:
            import types
            module.share = types.SimpleNamespace(**globals())
        return module

    def interfaces(self):
        records = self.ip("-j", "address", "show")
        result = []
        for item in records:
            name = item.get("ifname", "")
            if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}", name) or name in ("lo", CTRL):
                continue
            device = self.path("sys/class/net/" + name + "/device")
            if not device.exists():
                continue  # Exclude bridges, VPNs and other virtual interfaces.
            wireless = self.path("sys/class/net/" + name + "/phy80211").exists()
            usb = any((parent / "idVendor").exists() and (parent / "idProduct").exists()
                      for parent in (device.resolve(), *device.resolve().parents))
            if wireless and not usb:
                continue  # Never repurpose an internal radio as the external uplink.
            if not wireless and self.path("sys/class/net/" + name + "/type").read_text().strip() != "1":
                continue
            result.append({"name": name, "mode": "wifi" if wireless else "lan", "up": "UP" in item.get("flags", []),
                           "operstate": operational_state(item),
                           "addresses": [x for x in item.get("addr_info", []) if x.get("family") == "inet"]})
        return result

    def select(self, mode, interface=None):
        candidates = [x for x in self.interfaces() if x["mode"] == mode and (interface is None or x["name"] == interface)]
        require(candidates, "No matching external interface is present.")
        if len(candidates) > 1:
            helper = Path(__file__).with_name("adapter_selection.py") if Path(__file__).name == "auto_share.py" else self.trusted("usr/local/libexec/automations-support/adapter_selection.py")
            spec = importlib.util.spec_from_file_location("_share_selection", helper)
            module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
            try:
                name = module.choose([(x["name"], x["mode"] + ", " + x.get("operstate","unknown") +
                    (", SSID " + self.wifi_ssid(x["name"]) if mode == "wifi" else "")) for x in candidates],
                                     "Several interfaces match; specify --to NAME.")
            except ValueError as exc:
                raise Error(str(exc)) from None
            candidates = [x for x in candidates if x["name"] == name]
        item = candidates[0]
        require(item["up"], "The selected interface is down; connect it first.")
        name = item["name"]
        state = self.run(["/usr/bin/nmcli", "-g", "GENERAL.STATE", "device", "show", name]).strip()
        require(state.split(" ", 1)[0] == "100", "NetworkManager has no active connection on this interface.")
        routes = [r for r in self.ip("-j", "-4", "route", "show", "default", "dev", name)
                  if r.get("gateway") and r.get("type", "unicast") == "unicast"]
        require(routes, "An IPv4 address and gateway are required; IPv6-only uplinks are not supported (no NAT64/DNS64).")
        routes.sort(key=lambda r: int(r.get("metric", 0)))
        require(len(routes) == 1 or routes[0].get("metric", 0) != routes[1].get("metric", 0),
                "The selected interface has ambiguous default routes.")
        gateway = ipv4(routes[0]["gateway"])
        addresses = [x for x in item["addresses"] if ipaddress.ip_address(gateway) in
                     ipaddress.ip_interface(f"{x['local']}/{x['prefixlen']}").network]
        require(len(addresses) == 1, "Cannot determine one upstream source address.")
        address = addresses[0]
        dns = nm_dns_servers(self.run(["/usr/bin/nmcli", "--escape", "no", "-g", "IP4.DNS", "device", "show", name]), 4, name)
        v6, dns6 = self.discover_ipv6(name)
        selected = {"mode": mode, "interface": name, "address": address["local"],
            "network": str(ipaddress.ip_interface(f"{address['local']}/{address['prefixlen']}").network),
            "gateway": gateway, "dns": dns + dns6,
            "ipv6": v6, "control6": self.control_ipv6()}
        if self.guest_role(): selected["guest"] = dict(GUEST)
        return validate_selection(selected)

    def source_selection(self, answer=None):
        options = [(CTRL, "control WLAN, SSID " + self.control_ssid())]
        mapping = {CTRL: CTRL}
        if self.guest_role():
            state = json.loads(self.read("run/automations-hotspot/state.json"))
            name = iface_name(state["adapter"][0])
            require(name not in (CTRL, GUEST["interface"]), "Invalid additional AP interface.")
            options.append((name,"additional AP, SSID " + json.dumps(state["ssid"],ensure_ascii=True)))
            mapping[name] = GUEST["interface"]
        try:
            names = selection_support().choose_many(options,
                "Non-interactive sharing requires --from NAME[,NAME...].", answer=answer)
        except ValueError as exc:
            raise Error(str(exc)) from None
        return [mapping[name] for name in names]

    @staticmethod
    def with_sources(selection, sources):
        return validate_selection({**selection, "sources": list(sources)}) if sources is not None else selection

    def guest_role(self):
        relative="run/automations-hotspot/state.json"
        if not self.path(relative).exists(): return None
        value=json.loads(self.read(relative))
        if value.get("phase") != "active": return None
        require(value.get("version")==1 and value.get("boot_id")==self.path("proc/sys/kernel/random/boot_id").read_text().strip(),"Unrecognized additional AP state.")
        link=self.path("sys/class/net/"+GUEST["interface"])
        require(link.exists() and int((link/"ifindex").read_text())==value.get("veth_index"),"Additional AP transit link is missing or changed.")
        return GUEST

    def control_ipv6(self):
        identity = self.read("etc/machine-id").strip()
        require(re.fullmatch(r"[0-9a-f]{32}", identity), "Missing valid machine identity for the private IPv6 prefix.")
        digest = hashlib.sha256(("automations-share-ipv6:" + identity).encode()).digest()
        network = ipaddress.IPv6Network((int.from_bytes(b"\xfd" + digest[:5] + b"\x00\x01" + b"\0" * 8, "big"), 64))
        linklocal = ipaddress.IPv6Address(int(ipaddress.IPv6Address("fe80::")) | int.from_bytes(digest[5:13], "big"))
        return {"network": str(network), "address": str(network.network_address + 1), "linklocal": str(linklocal)}

    def discover_ipv6(self, name):
        rows = self.ip("-j", "-6", "address", "show", "dev", name)
        require(len(rows) <= 1, "Cannot inspect the selected IPv6 interface.")
        candidates = [x for row in rows for x in row.get("addr_info", []) if x.get("family") == "inet6" and
            x.get("scope") == "global" and not ({"tentative", "dadfailed", "deprecated"} & set(x.get("flags", []))) and
            not any(x.get(flag) for flag in ("tentative", "dadfailed", "deprecated")) and
            x.get("preferred_life_time", 1) != 0 and ipaddress.IPv6Address(x["local"]) in ipaddress.IPv6Network("2000::/3")]
        routes = [r for r in self.ip("-j", "-6", "route", "show", "default", "dev", name)
                  if r.get("gateway") and r.get("type", "unicast") == "unicast" and "dead" not in r.get("flags", [])]
        if not candidates or not routes:
            return None, []
        routes.sort(key=lambda x: int(x.get("metric", 0)))
        require(len(routes) == 1 or routes[0].get("metric", 0) != routes[1].get("metric", 0), "Ambiguous IPv6 default routes.")
        candidates.sort(key=lambda x: (bool(x.get("temporary")) or "temporary" in x.get("flags", []), x["local"]))
        source = candidates[0]
        dns = nm_dns_servers(self.run(["/usr/bin/nmcli", "--escape", "no", "-g", "IP6.DNS", "device", "show", name]), 6, name)
        return {"address": source["local"], "addresses": sorted({x["local"] for x in candidates}),
                "network": str(ipaddress.IPv6Interface(str(source["local"]) + "/" + str(source["prefixlen"])).network),
                "gateway": routes[0]["gateway"]}, dns

    def solicit_router(self, name):
        index = socket.if_nametoindex(name)
        rows = self.ip("-j", "-6", "address", "show", "dev", name)
        sources = [x["local"] for row in rows for x in row.get("addr_info", []) if x.get("family") == "inet6" and
                   x.get("scope") == "link" and not x.get("tentative") and "tentative" not in x.get("flags", [])]
        require(sources, "IPv6 discovery needs a ready upstream link-local address.")
        with socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6) as sock:
            sock.settimeout(2)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, index)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
            sock.bind((sources[0], 0, 0, index))
            sock.sendto(struct.pack("!BBHI", 133, 0, 0, 0), ("ff02::2", 0, 0, index))

    def probe_ipv6(self, selected):
        # Native NetworkManager remains the upstream RA/address owner. The probe
        # only requests an advertisement; it does not install an upstream address.
        self.solicit_router(selected["interface"])
        for attempt in range(20):
            updated = self.with_sources(self.select(selected["mode"], selected["interface"]), selected.get("sources"))
            require(all(updated[key] == selected[key] for key in ("mode", "interface", "address", "network", "gateway")),
                    "The upstream changed during IPv6 discovery; retry the command.")
            if updated["ipv6"]:
                return updated
            if attempt != 19:
                time.sleep(0.25)
        return updated  # A completed probe with no usable IPv6 is an explicit blocked state.

    def gate_present(self):
        data = self.firewall()
        actual = [(kind, value) for entry in data.get("nftables", []) for kind, value in entry.items()
                  if isinstance(value, dict) and value.get("family") == "inet" and
                  (value.get("table") == GATE or kind == "table" and value.get("name") == GATE)]
        expected = gate_objects()
        require(not actual or [(k, normalize(v)) for k,v in actual] == [(k, normalize(v)) for k,v in expected],
                "The temporary egress guard is not owned by this command.")
        return bool(actual)

    def gate(self, enabled):
        actual = self.gate_present()
        expected = gate_objects()
        if enabled and not actual:
            self.nft({"nftables": [{"add": {k:v}} for k,v in expected]})
        elif not enabled and actual:
            self.nft({"nftables": [{"delete": {"table": {"family": "inet", "name": GATE}}}]})

    def admission(self, selection, enabled):
        expected = ipv6_input_rules({**selection, "ipv6": None})
        data = self.firewall()
        actual = [item["rule"] for item in data.get("nftables", []) if "rule" in item and
                  item["rule"].get("table") == "pi4" and item["rule"].get("chain") == "input" and
                  item["rule"].get("comment") in {rule["comment"] for rule in expected}]
        require(not actual or [normalize(x) for x in actual] == [normalize(x) for x in expected], "Changed IPv6 admission rules.")
        if enabled:
            require(not actual, "IPv6 admission rules already exist.")
            self.nft({"nftables": [{"insert": {"rule": x}} for x in reversed(expected)]})
        elif actual:
            self.nft({"nftables": [{"delete": {"rule": {key:x[key] for key in ("family", "table", "chain", "handle")}}} for x in actual]})

    def ipv6_settings(self):
        base = self.path("proc/sys/net/ipv6/conf")
        result = {}
        for folder in sorted(base.iterdir()):
            require(folder.name in ("all", "default") or iface_name(folder.name), "Unexpected IPv6 sysctl interface.")
            value = (folder / "forwarding").read_text().strip()
            require(value in ("0", "1"), "Unexpected IPv6 forwarding value.")
            result[folder.name] = value
        require({"all", "default", CTRL} <= result.keys(), "IPv6 forwarding controls are unavailable.")
        return result

    def write_ipv6_forwarding(self, name, value):
        self.path("proc/sys/net/ipv6/conf/" + name + "/forwarding").write_text(value + "\n")

    def ipv6_forwarding(self, state, enabled):
        original = state["ipv6_forwarding"]
        current = self.ipv6_settings()
        require({"all", "default", CTRL} <= current.keys(), "Required IPv6 forwarding controls disappeared.")
        desired = {**original, "all": "1", CTRL: "1", state["selection"]["interface"]: "1"}
        if enabled:
            require(current == original, "IPv6 forwarding changed before activation.")
        else:
            # An unplugged uplink has no sysctl file to restore. Other/new devices
            # retain their observed values when the global switch fans out.
            require(all(current[name] in ({original[name], desired[name]} | ({"1"} if name != "default" else set())) for name in current.keys() & original.keys()),
                    "IPv6 forwarding was edited externally.")
        target = {name: (desired[name] if enabled else original[name]) if name in original else value
                  for name,value in current.items()}
        self.write_ipv6_forwarding("all", target["all"])
        for name, value in target.items():
            if name != "all": self.write_ipv6_forwarding(name, value)

    def ipv6_addresses(self, state, enabled):
        selected = state["selection"]
        if enabled and not selected["ipv6"]:
            return
        expected = [selected["control6"]["linklocal"] + "/64", selected["control6"]["address"] + "/64"]
        rows = self.ip("-j", "-6", "address", "show", "dev", CTRL)
        current = {x["local"] + "/" + str(x["prefixlen"]) for row in rows for x in row.get("addr_info", []) if x.get("family") == "inet6"}
        if enabled:
            require(not current.intersection(expected), "The private control IPv6 address is already present; it was not adopted.")
        for address in expected if enabled else list(state.get("owned_addresses", [])):
            if enabled:
                self.run(["/usr/sbin/ip", "-6", "address", "add", address, "dev", CTRL])
                state.setdefault("owned_addresses", []).append(address)
                self.save(state)
            elif address in current:
                self.run(["/usr/sbin/ip", "-6", "address", "del", address, "dev", CTRL])
                state["owned_addresses"].remove(address)
                self.save(state)
        if enabled:
            for attempt in range(30):
                rows = self.ip("-j", "-6", "address", "show", "dev", CTRL)
                entries = [x for row in rows for x in row.get("addr_info", []) if x.get("local") in {a.split("/")[0] for a in expected}]
                require(not any(x.get("dadfailed") or "dadfailed" in x.get("flags", []) for x in entries), "Control IPv6 address collision.")
                if len(entries) == 2 and not any(x.get("tentative") or "tentative" in x.get("flags", []) for x in entries):
                    return
                time.sleep(0.1)
            raise Error("Control IPv6 duplicate-address detection did not complete.")

    def withdraw_ra(self, selection):
        if not selection["ipv6"]:
            return
        index = socket.if_nametoindex(CTRL)
        control = selection["control6"]
        packet = struct.pack("!BBHBBHII", 134, 0, 0, 64, 0, 0, 0, 0)
        packet += struct.pack("!BBBBIII16s", 3, 4, 64, 0xc0, 0, 0, 0, ipaddress.IPv6Network(control["network"]).network_address.packed)
        packet += struct.pack("!BBHI16s", 25, 3, 0, 0, ipaddress.IPv6Address(control["address"]).packed)
        with socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6) as sock:
            sock.settimeout(2)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, index)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
            sock.bind((control["linklocal"], 0, 0, index))
            sock.sendto(packet, ("ff02::1", 0, 0, index))

    @staticmethod
    def validate_snapshot(state):
        try:
            require(set(state) == {"version", "selection", "forwarding", "ipv6_forwarding", "owned_addresses", "ready", "steps"} and state["version"] == 2,
                    "Unrecognized sharing state; stop the old component before updating.")
            validate_selection(state["selection"])
            require(type(state["ready"]) is bool, "Invalid sharing readiness state.")
            allowed_addresses = {state["selection"]["control6"][key] + "/64" for key in ("address", "linklocal")}
            require(isinstance(state["owned_addresses"], list) and len(state["owned_addresses"]) == len(set(state["owned_addresses"])) and
                    set(state["owned_addresses"]) <= allowed_addresses,
                    "Invalid control IPv6 ownership state.")
            require(set(state["forwarding"]) == {CTRL, state["selection"]["interface"], *([GUEST["interface"]] if state["selection"].get("guest") else [])} and
                    all(value in ("0", "1") for value in state["forwarding"].values()) and
                    isinstance(state["steps"], list) and len(state["steps"]) == len(set(state["steps"])) and
                    set(state["steps"]) <= {"gate", "admission", "addresses", "routes", "unit", "firewall", "forwarding"}, "Invalid sharing state.")
            require(isinstance(state["ipv6_forwarding"], dict) and {"all", "default", CTRL, state["selection"]["interface"]} <= state["ipv6_forwarding"].keys() and all(
                (name in ("all", "default") or iface_name(name)) and value in ("0", "1")
                for name,value in state["ipv6_forwarding"].items()), "Invalid IPv6 forwarding snapshot.")
            return state
        except (ValueError, TypeError, KeyError):
            raise Error("Invalid sharing state; no network changes made.") from None

    def load(self):
        if not self.path(STATE).exists() and not self.path(STATE).is_symlink():
            return None
        try:
            return self.validate_snapshot(json.loads(self.read(STATE)))
        except (ValueError, TypeError, KeyError):
            raise Error("Invalid sharing state; no network changes made.") from None

    def save(self, state):
        folder = self.path("run/automations-share")
        folder.mkdir(mode=0o700, exist_ok=True)
        self.trusted("run/automations-share", directory=True)
        require(stat.S_IMODE(folder.stat().st_mode) == 0o700, "Unsafe sharing state directory.")
        previous = self.read(STATE) if self.path(STATE).exists() else None
        self.write(STATE, json.dumps(state, sort_keys=True) + "\n", previous)

    def forwarding(self, interface, value=None):
        path = self.path("proc/sys/net/ipv4/conf/" + iface_name(interface) + "/forwarding")
        if not path.exists() and value is not None:
            return  # A removed adapter has no per-interface setting to restore.
        current = path.read_text().strip()
        require(current in ("0", "1"), "Invalid per-interface forwarding state.")
        if value is not None:
            path.write_text(value + "\n")
        return current

    def route_state(self, family=4):
        routes = [r for r in self.ip("-j", "-" + str(family), "route", "show", "table", "all") if str(r.get("table")) == str(TABLE)]
        return routes, self.ip("-j", "-" + str(family), "rule", "show")

    def route_plan(self, selection, family):
        base = ["/usr/sbin/ip", "-" + str(family)]
        routes = [(base + ["route", "add", "unreachable", "default", "table", str(TABLE), "proto", "static", "metric", "32760"],
                   {"type": "unreachable", "dst": "default", "table": TABLE, "protocol": "static", "metric": 32760})]
        connected = [(SUBNET, CTRL, ADDRESS)] if family == 4 else []
        default = None
        if family == 4:
            if selection.get("guest"): connected.append((GUEST["transit"],GUEST["interface"],GUEST["host"]))
            connected.append((selection["network"], selection["interface"], selection["address"]))
            default = selection
        elif selection["ipv6"]:
            connected += [(selection["control6"]["network"], CTRL, selection["control6"]["address"]),
                          (selection["ipv6"]["network"], selection["interface"], selection["ipv6"]["address"]),
                          ("fe80::/64", selection["interface"], None)]
            default = selection["ipv6"]
        for subnet, name, source in connected:
            row = {"dst": subnet, "dev": name, "table": TABLE, "protocol": "static", "metric": 10}
            command = base + ["route", "add", subnet, "dev", name]
            if source:
                command += ["src", source]
                row["prefsrc"] = source
            if family == 4:
                row["scope"] = "link"
            routes.append((command + ["table", str(TABLE), "proto", "static", "metric", "10"], row))
        if default:
            routes.append((base + ["route", "add", "default", "via", default["gateway"], "dev", selection["interface"],
                "src", default["address"], "table", str(TABLE), "proto", "static", "metric", "10"],
                {"dst": "default", "gateway": default["gateway"], "dev": selection["interface"],
                 "prefsrc": default["address"], "table": TABLE, "protocol": "static", "metric": 10}))
        if family == 4 and selection.get("guest"):
            routes.append((base+["route","add",GUEST["network"],"via",GUEST["peer"],"dev",GUEST["interface"],"table",str(TABLE),"proto","static","metric","10"],
                {"dst":GUEST["network"],"gateway":GUEST["peer"],"dev":GUEST["interface"],"table":TABLE,"protocol":"static","metric":10}))
        rules = []
        links = [(LINK_PRIORITY, "255.255.255.255/32")] if family == 4 else [(LINK_PRIORITY-1, "fe80::/10"), (LINK_PRIORITY, "ff00::/8")]
        for priority, target in links:
            rules.append((base + ["rule", "add", "priority", str(priority), "to", target, "lookup", "main"],
                {"priority": priority, "src": "all", "dst": target, "table": "main"}))
        for priority, name in ((PRIORITY, CTRL), (LOCAL_PRIORITY, "lo")):
            rules.append((base + ["rule", "add", "priority", str(priority), "iif", name, "lookup", str(TABLE)],
                {"priority": priority, "src": "all", "iif": name, "table": TABLE}))
        if family == 4 and selection.get("guest"):
            rules.append((base+["rule","add","priority",str(LOCAL_PRIORITY+1),"iif",GUEST["interface"],"lookup",str(TABLE)],
                {"priority":LOCAL_PRIORITY+1,"src":"all","iif":GUEST["interface"],"table":TABLE}))
        return routes, rules

    @staticmethod
    def normalize_route(row, family):
        row = dict(row)
        require(not row.get("flags"), "Unexpected route flags.")
        row.pop("flags", None)
        if family == 6:
            require(row.get("pref", "medium") == "medium", "Unexpected IPv6 route preference.")
            row.pop("pref", None)
            if row.get("type") == "unreachable" and row.get("dev") == "lo":
                row.pop("dev")
        if "table" in row and str(row["table"]) == str(TABLE): row["table"] = TABLE
        return row

    @staticmethod
    def normalize_rule(row):
        row = dict(row)
        row.pop("protocol", None)
        if "dst" in row:
            target = row["dst"]
            if "dstlen" in row:
                require("/" not in target and type(row["dstlen"]) is int, "Unexpected policy rule prefix.")
                target += "/" + str(row.pop("dstlen"))
            row["dst"] = str(ipaddress.ip_network(target, strict=False))
        if str(row.get("table")) == str(TABLE): row["table"] = TABLE
        return row

    def routes_check(self, selection=None, cleanup_state=None):
        all_routes, all_own = [], []
        cleaning = (cleanup_state is not None and cleanup_state["selection"] == selection and
                    cleanup_state["ready"] is False)
        uplink_down = False
        if cleaning:
            rows = [row for row in self.ip("-j", "address", "show") if row.get("ifname") == selection["interface"]]
            require(len(rows) <= 1, "Cannot verify the uplink during routing cleanup.")
            uplink_down = (not rows or "UP" not in rows[0].get("flags", []) or
                           rows[0].get("operstate") in ("DOWN", "LOWERLAYERDOWN", "NOTPRESENT"))
        removed_control_source = False
        # Recovery for an interrupted older cleanup that removed its addresses
        # before its routes: Linux then drops this route's preferred source.
        # This exception never applies to live health/status validation.
        if (cleanup_state is not None and cleanup_state["selection"] == selection and
                cleanup_state["ready"] is False and cleanup_state["owned_addresses"] == [] and
                selection["ipv6"] is not None):
            rows = self.ip("-j", "-6", "address", "show", "dev", CTRL)
            require(len(rows) <= 1 and all(row.get("ifname") == CTRL for row in rows),
                    "Cannot verify removed control IPv6 source during cleanup.")
            removed_control_source = not any(x.get("local") == selection["control6"]["address"]
                for row in rows for x in row.get("addr_info", []) if x.get("family") == "inet6")
        standard = [(0, "local"), (32766, "main"), (32767, "default")]
        for family in (4, 6):
            routes, rules = self.route_state(family)
            expected_routes, expected_rules = self.route_plan(selection, family) if selection else ([], [])
            expected_routes = [self.normalize_route(row, family) for _,row in expected_routes]
            # Carrier/address loss may erase prefsrc from our external routes,
            # and Linux does not restore it when the same address reconnects.
            # Only cleanup admits that exact omission; all other fields stay exact.
            if cleaning:
                expected_routes += [{key: value for key, value in row.items() if key != "prefsrc"}
                    for row in expected_routes if row.get("dev") == selection["interface"] and "prefsrc" in row]
            if removed_control_source and family == 6:
                expected_routes += [{key: value for key, value in row.items() if key != "prefsrc"}
                    for row in expected_routes if row.get("dev") == CTRL and
                    row.get("dst") == selection["control6"]["network"] and
                    row.get("prefsrc") == selection["control6"]["address"]]
            expected_rules = [self.normalize_rule(row) for _,row in expected_rules]
            own = []
            for entry in rules:
                normal = self.normalize_rule(entry)
                comparison = normal
                if (cleaning and family == 4 and selection.get("guest") and
                        "iif_detached" in normal and normal["iif_detached"] is None and
                        normal.get("iif") == GUEST["interface"] and
                        not any(row.get("ifname") == GUEST["interface"]
                                for row in self.ip("-j", "address", "show"))):
                    # Linux retains an iif rule after the owned AP veth vanishes,
                    # adding this flag. Admit only its otherwise exact reserved
                    # identity during cleanup; never treat it as healthy.
                    comparison = {key: value for key, value in normal.items() if key != "iif_detached"}
                    require(sum(row.get("priority") == normal.get("priority") for row in rules) == 1,
                            "Ambiguous detached AP policy rule; refusing cleanup.")
                if (entry.get("priority"), entry.get("table")) in standard:
                    require(set(normal) == {"priority", "src", "table"} and normal["src"] == "all", "Unexpected standard policy rule.")
                else:
                    require(comparison in expected_rules, "Unrecognized IPv" + str(family) + " policy rule.")
                    own.append(normal)
            actual = []
            for row in routes:
                if (cleaning and uplink_down and row.get("dev") == selection["interface"] and
                        row.get("flags") == ["linkdown"]):
                    row = {**row, "flags": []}
                actual.append(self.normalize_route(row, family))
            require(all(row in expected_routes for row in actual) and len(actual) == len({json.dumps(x,sort_keys=True) for x in actual}) and
                    len(own) == len({json.dumps(x,sort_keys=True) for x in own}), "Changed or duplicate reserved routing objects.")
            all_routes += [(family, row) for row in actual]
            all_own += [(family, row) for row in own]
        return all_routes, all_own

    def add_routes(self, selection):
        for family in (4, 6):
            routes, rules = self.route_plan(selection, family)
            for command, _ in routes + rules:
                self.run(command)

    def remove_routes(self, selection, cleanup_state=None):
        actual_routes, actual_rules = self.routes_check(selection, cleanup_state)
        for family, row in actual_rules:
            command = ["/usr/sbin/ip", "-" + str(family), "rule", "del", "priority", str(row["priority"])]
            if "iif_detached" not in row:
                command += ["iif", row["iif"]] if "iif" in row else ["to", row["dst"]]
            self.run(command + ["lookup", str(row["table"])])
        for family in {family for family,_ in actual_routes}:
            self.run(["/usr/sbin/ip", "-" + str(family), "route", "flush", "table", str(TABLE)])

    def service(self):
        return dict(line.split("=", 1) for line in self.run(["/usr/bin/systemctl", "show", SERVICE,
                    "--property=LoadState,ActiveState,MainPID,FragmentPath,DropInPaths"]).splitlines() if "=" in line)

    def service_check(self, selection, allow_missing=False, starting=False, server_config=True, unit_config=True):
        values = self.service()
        if allow_missing and values.get("LoadState") == "not-found" and not self.path(UNIT).exists():
            return False
        require((not unit_config or self.read(UNIT) == unit_text(selection)) and values.get("FragmentPath") == "/" + UNIT and
                not values.get("DropInPaths"), "The sharing DNS service was changed externally.")
        if server_config:
            self.servers_check(selection)
        if values.get("ActiveState") != "active" or int(values.get("MainPID", "0")) <= 1:
            return False
        try:
            process = self.path("proc/" + values["MainPID"] + "/status").read_text()
        except FileNotFoundError:
            if starting:
                return False
            raise
        expected_uid = re.search(r"(?m)^Uid:\s+" + str(DNS_UID) + r"\s+" + str(DNS_UID) + r"\s", process)
        if starting and not expected_uid:
            # Type=simple may report active before dnsmasq drops privileges.
            # The caller has a fixed deadline; no forwarding is enabled yet.
            return False
        require(expected_uid, "DNS helper did not drop to its expected UID.")
        expected = {ADDRESS, "127.0.0.1", "::1"}
        if selection["ipv6"] and control_enabled(selection):
            expected.add(selection["control6"]["address"])
            expected.add(selection["control6"]["linklocal"] + "%" + CTRL)
        for protocol in ("-ltnp", "-lunp"):
            listeners = self.run(["/usr/bin/ss", "-H", protocol])
            found = [line for line in listeners.splitlines() if len(line.split()) >= 4 and
                     line.split()[3].rsplit(":", 1)[-1] == str(DNS_PORT)]
            addresses = set()
            for line in found:
                address = line.split()[3].rsplit(":", 1)[0]
                if address.startswith("["):
                    # Native ss prints a TCP zone outside the IPv6 brackets.
                    bracketed = re.fullmatch(r"\[([^\[\]]+)\](%[A-Za-z0-9_.-]+)?", address)
                    if not bracketed:
                        return False
                    address = bracketed[1] + (bracketed[2] or "")
                # UDP socket diagnostics can omit the bound link-local zone.
                # Normalize only our exact control LL; TCP still proves ctrl0.
                if (protocol == "-lunp" and selection["ipv6"] and control_enabled(selection) and
                        address == selection["control6"]["linklocal"]):
                    address += "%" + CTRL
                addresses.add(address)
            if addresses != expected or len(found) != len(expected) or any(f"pid={values['MainPID']}," not in line for line in found):
                return False
        return True

    def servers_check(self, selection):
        privacy = self.path("run/automations-anonymity/state.json")
        tor = False
        if privacy.exists() or privacy.is_symlink():
            module = self.refresh_support().privacy_module(self)
            state = module.load_state(self.root, self.owner)
            require(state["selection"] == selection, "Resolver and privacy select different uplinks.")
            tor = state["mode"] == "tor"
        require(self.read(DNS_SERVERS) == servers_text(selection, tor=tor) and
                stat.S_IMODE(self.path(DNS_SERVERS).stat().st_mode) == 0o644,
                "The sharing DNS server file was changed externally.")

    def resolver_mode(self, tor):
        """Called only inside the serialized privacy lifecycle, behind its guard."""
        state = self.load()
        require(state and state["ready"], "A completed sharing resolver is required.")
        selection = state["selection"]
        previous = self.read(DNS_SERVERS)
        require(previous in (servers_text(selection), servers_text(selection, tor=True)) and
                stat.S_IMODE(self.path(DNS_SERVERS).stat().st_mode) == 0o644 and
                self.service_check(selection, server_config=False), "The sharing resolver was changed externally.")
        desired = servers_text(selection, tor=tor)
        if previous != desired:
            self.write(DNS_SERVERS, desired, previous, mode=0o644)
        pid = self.service().get("MainPID")
        self.run(["/usr/bin/systemctl", "kill", "--kill-whom=main", "--signal=HUP", SERVICE])
        require(self.service_check(selection, server_config=False) and self.service().get("MainPID") == pid,
                "The sharing resolver changed during privacy DNS reload.")

    def preflight(self, selection):
        self.validate()
        validate_selection(selection)
        firewall_check(self.firewall())
        self.routes_check()
        require(pwd.getpwnam("nobody").pw_uid == DNS_UID and grp.getgrnam("nogroup").gr_gid == DNS_UID,
                "The standard nobody/nogroup identity is unavailable.")
        require(self.path("proc/sys/net/ipv6/conf/lo/disable_ipv6").read_text().strip() == "0" and
                self.path("proc/sys/net/ipv6/conf/ctrl0/disable_ipv6").read_text().strip() == "0",
                "IPv6 loopback/control support is disabled; no configuration was changed.")
        require(self.service().get("LoadState") == "not-found" and not self.path(UNIT).exists() and
                not self.path(UNIT).is_symlink(), "The sharing DNS service name is already in use.")
        require(not self.path(DNS_SERVERS).exists() and not self.path(DNS_SERVERS).is_symlink(),
                "The sharing DNS server file is already in use.")
        self.trusted("run/systemd/system", directory=True)
        # Required for scoped NAT cleanup; fail before activation if absent.
        self.run(["/usr/sbin/conntrack", "--version"])
        # Check daemon syntax without binding sockets or changing the main dnsmasq.
        command = unit_text(selection, inline=True).split("ExecStart=", 1)[1].splitlines()[0].split()
        self.run(command + ["--test"])
        for protocol in ("-ltn", "-lun"):
            listeners = self.run(["/usr/bin/ss", "-H", protocol])
            require(not any(len(line.split()) >= 4 and line.split()[3].rsplit(":", 1)[-1] == str(DNS_PORT)
                            for line in listeners.splitlines()), "The private sharing DNS port is already in use.")

    def enable(self, selection, held_gate=False):
        self.preflight(selection)
        state = {"version": 2, "selection": selection, "ready": False,
                 "forwarding": {name: self.forwarding(name) for name in (CTRL, selection["interface"], *([GUEST["interface"]] if selection.get("guest") else []))},
                 "ipv6_forwarding": self.ipv6_settings(), "owned_addresses": [], "steps": []}
        self.save(state)
        try:
            for step in ("gate", "admission", "addresses", "routes", "unit", "firewall", "forwarding"):
                state["steps"].append(step)
                self.save(state)
                if step == "gate":
                    self.gate(True)
                elif step == "admission":
                    self.admission(selection, True)
                    selection = self.with_sources(self.probe_ipv6(selection), selection.get("sources"))
                    state["selection"] = selection
                    self.save(state)
                elif step == "addresses":
                    self.ipv6_addresses(state, True)
                    self.admission(selection, False)
                    state["steps"].remove("admission")
                    self.save(state)
                elif step == "routes":
                    self.add_routes(selection)
                elif step == "unit":
                    self.write(DNS_SERVERS, servers_text(selection), mode=0o644)
                    command = unit_text(selection).split("ExecStart=", 1)[1].splitlines()[0].split()
                    self.run(command + ["--test"])
                    self.write(UNIT, unit_text(selection))
                    self.run(["/usr/bin/systemctl", "daemon-reload"])
                    self.run(["/usr/bin/systemctl", "start", SERVICE])
                    for attempt in range(20):
                        if self.service_check(selection, starting=True): break
                        if attempt == 19: raise Error("The sharing DNS service did not reach its expected UID and dedicated sockets within the startup timeout.")
                        time.sleep(0.1)
                elif step == "firewall":
                    firewall_check(self.firewall())
                    batch = nft_add(selection)
                    self.run(["/usr/sbin/nft", "--check", "--json", "-f", "-"], json.dumps(batch))
                    self.nft(batch)
                    firewall_check(self.firewall(), selection)
                else:
                    for name in state["forwarding"]: self.forwarding(name, "1")
                    if selection["ipv6"]: self.ipv6_forwarding(state, True)
            state["ready"] = True
            self.save(state)
            self.gate(False)
            return state
        except BaseException as original:
            try:
                self.disable(state, keep_gate=held_gate)
            except BaseException:
                raise Error("Sharing activation failed and cleanup is incomplete. Run sudo auto share --off; the guard/state were retained.") from original
            raise

    def disable(self, state, keep_gate=False):
        selection = state["selection"]
        self.gate(True)  # Keep local management, block all external traffic during restoration.
        if state["ready"] and (selection["ipv6"] or state["owned_addresses"]):
            current = self.ipv6_settings()
            expected = {**state["ipv6_forwarding"], "all": "1", CTRL: "1", selection["interface"]: "1"}
            require(all(current[name] == expected[name] for name in current.keys() & expected.keys()),
                    "IPv6 forwarding changed externally; refusing to overwrite it.")
        state["ready"] = False
        self.save(state)
        if "unit" in state["steps"] and (self.path(UNIT).exists() or self.path(UNIT).is_symlink()):
            require(self.read(UNIT) == unit_text(selection), "The sharing DNS unit changed; refusing removal.")
            values = self.service()
            require(not values.get("DropInPaths") and values.get("FragmentPath") in ("", "/" + UNIT),
                    "Unexpected sharing DNS service overrides.")
            self.run(["/usr/bin/systemctl", "stop", SERVICE])
            if selection["ipv6"]:
                try:
                    self.withdraw_ra(selection)
                except OSError:
                    print("Warning: IPv6 router withdrawal could not be sent; forwarding is still being disabled.", file=sys.stderr)
            self.path(UNIT).unlink()
            self.run(["/usr/bin/systemctl", "daemon-reload"])
        if "unit" in state["steps"] and (self.path(DNS_SERVERS).exists() or self.path(DNS_SERVERS).is_symlink()):
            self.servers_check(selection)
            self.path(DNS_SERVERS).unlink()
        if "firewall" in state["steps"]:
            data = self.firewall()
            if any(x.get("table", {}).get("name") == "auto_share" for x in data.get("nftables", [])):
                self.nft(nft_delete(data, selection))
            else:
                firewall_check(data)
        if "admission" in state["steps"]:
            self.admission(selection, False)
        if "forwarding" in state["steps"]:
            for name, previous in state["forwarding"].items(): self.forwarding(name, previous)
            if selection["ipv6"] or state["owned_addresses"]: self.ipv6_forwarding(state, False)
        if "firewall" in state["steps"]:
            self.run(["/usr/sbin/conntrack", "-D", "--mark", str(MARK)], accepted=(0, 1))
        # Validate/remove routes while their own preferred source still exists.
        if "routes" in state["steps"]:
            self.remove_routes(selection, state)
        if "addresses" in state["steps"]:
            self.ipv6_addresses(state, False)
        if not keep_gate:
            self.gate(False)
            self.path(STATE).unlink(missing_ok=True)

    def healthy(self, state):
        require(state["ready"] and state["steps"] == ["gate", "addresses", "routes", "unit", "firewall", "forwarding"],
                "A previous sharing operation is incomplete; run --off.")
        selected = state["selection"]
        firewall_check(self.firewall(), selected)
        routes, rules = self.routes_check(selected)
        expected = [self.route_plan(selected, family) for family in (4, 6)]
        live = self.with_sources(self.select(selected["mode"], selected["interface"]), selected.get("sources"))
        current = self.ipv6_settings()
        desired = {**state["ipv6_forwarding"], "all": "1", CTRL: "1", selected["interface"]: "1"}
        return (not self.gate_present() and len(routes) == sum(len(x[0]) for x in expected) and len(rules) == sum(len(x[1]) for x in expected) and
                self.service_check(selected) and all(self.forwarding(name) == "1" for name in state["forwarding"]) and
                (not (selected["ipv6"] or state["owned_addresses"]) or
                 {"all", "default", CTRL, selected["interface"]} <= current.keys() and
                 all(current[name] == desired[name] for name in current.keys() & desired.keys())) and live == selected)

    def watch_definition(self):
        definitions = ((WATCH_SERVICE, WATCH_SERVICE_TEXT), (WATCH_TIMER, WATCH_TIMER_TEXT))
        if not any(self.path("etc/systemd/system/" + name).exists() or
                   self.path("etc/systemd/system/" + name).is_symlink() for name, _ in definitions):
            return False
        for name, expected in definitions:
            relative = "etc/systemd/system/" + name
            require(self.read(relative) == expected, "Unrecognized sharing watcher definition.")
            fields = dict(line.split("=", 1) for line in self.run([
                "/usr/bin/systemctl", "show", name,
                "--property=FragmentPath,DropInPaths,NeedDaemonReload"]).splitlines() if "=" in line)
            require(fields.get("FragmentPath") == "/" + relative and not fields.get("DropInPaths") and
                    fields.get("NeedDaemonReload") == "no", "The loaded sharing watcher definition differs.")
        return True

    def watch_start(self):
        if self.watch_definition():
            self.run(["/usr/bin/systemctl", "start", WATCH_TIMER])

    def watch_stop(self):
        if self.watch_definition():
            # The shared lock prevents racing a refresh. Never kill its worker
            # in the middle of a network transaction; stop future ticks only.
            self.run(["/usr/bin/systemctl", "stop", WATCH_TIMER])

    def watch_record(self):
        path = self.path(WATCH_STATE)
        if not path.exists() and not path.is_symlink():
            return None
        require(stat.S_IMODE(path.lstat().st_mode) == 0o600 and
                stat.S_IMODE(path.parent.lstat().st_mode) == 0o700, "Unsafe sharing watcher state.")
        value = json.loads(self.read(WATCH_STATE))
        require(isinstance(value, dict) and set(value) == {"version", "status", "reason", "selection", "changes", "candidate"} and
                type(value["version"]) is int and value["version"] == 2 and
                value["status"] in ("active", "degraded", "deferred") and
                value["reason"] in ("verified", "refreshed", "unavailable", "unrecognized", "pending", "refresh-failed") and
                isinstance(value["selection"], str) and re.fullmatch(r"[0-9a-f]{64}", value["selection"]) and
                (value["candidate"] is None or isinstance(value["candidate"], str) and re.fullmatch(r"[0-9a-f]{64}", value["candidate"])) and
                isinstance(value["changes"], list) and len(value["changes"]) == len(set(value["changes"])) and
                all(name in ("address", "network", "gateway", "dns", "ipv6") for name in value["changes"]),
                "Invalid sharing watcher state.")
        return value

    def watch_publish(self, state, status, reason, changes=(), candidate=None):
        previous = self.watch_record()
        digest = hashlib.sha256(json.dumps(state["selection"], sort_keys=True).encode()).hexdigest()
        record = {"version": 2, "status": status, "reason": reason, "selection": digest, "changes": list(changes), "candidate": candidate}
        if previous == record or (status == "active" and reason == "verified" and previous and
                                  previous["status"] == "active" and previous["selection"] == digest):
            return
        expected = self.read(WATCH_STATE) if previous else None
        self.write(WATCH_STATE, json.dumps(record, sort_keys=True) + "\n", expected)
        messages = {"verified": "selected uplink verified", "refreshed": "selected uplink refreshed",
                    "unavailable": "selected uplink unavailable; no fallback",
                    "unrecognized": "managed state differs; no automatic overwrite",
                    "pending": "uplink change observed; waiting for a second consistent observation",
                    "refresh-failed": "refresh failed; inspect sharing before retrying"}
        print("Share watcher: " + status + "; " + messages[reason] +
              (" (" + ", ".join(changes) + ")" if changes else "") + ".", flush=True)

    def watch_once(self):
        """One serialized metadata check, with no Internet request or fallback."""
        state = self.load()
        if state is None:
            return "off"
        selected = state["selection"]
        try:
            current = self.with_sources(self.select(selected["mode"], selected["interface"]), selected.get("sources"))
        except (Error, OSError, ValueError, KeyError, TypeError):
            self.watch_publish(state, "degraded", "unavailable")
            return "unavailable"
        fixed = ("mode", "interface", "control6", "sources", "guest")
        if any(current.get(key) != selected.get(key) for key in fixed):
            self.watch_publish(state, "degraded", "unrecognized")
            return "unrecognized"
        changes = [key for key in ("address", "network", "gateway", "dns", "ipv6") if current[key] != selected[key]]
        if not changes:
            try:
                healthy = self.healthy(state)
            except (Error, OSError, ValueError, KeyError, TypeError):
                healthy = False
            if healthy:
                self.watch_publish(state, "active", "verified")
                return "active"
        digest = hashlib.sha256(json.dumps(current, sort_keys=True).encode()).hexdigest()
        previous = self.watch_record()
        selected_digest = hashlib.sha256(json.dumps(selected, sort_keys=True).encode()).hexdigest()
        if not (previous and previous["reason"] == "pending" and previous["candidate"] == digest and previous["selection"] == selected_digest):
            self.watch_publish(state, "deferred", "pending", changes, digest)
            return "pending"
        try:
            self.refresh_support().refresh(self, state, current)
            refreshed = self.load()
            require(refreshed and self.healthy(refreshed), "The refreshed sharing selection is not healthy.")
        except Busy:
            return "pending"  # The existing activation owns its lifecycle; retry a later tick.
        except (RuntimeError, OSError, ValueError, KeyError, TypeError):
            self.watch_publish(self.load() or state, "degraded", "refresh-failed", changes)
            return "failed"
        self.watch_publish(refreshed, "active", "refreshed", changes)
        return "refreshed"

    def change(self, mode, interface=None, sources=None):
        privacy = self.path("run/automations-anonymity/state.json")
        require(not privacy.exists() and not privacy.is_symlink(),
                "Turn Tor or proxy off before changing the selected share uplink.")
        self.validate(ready=mode != "off")
        require(not any(item.get("table", {}).get("name") == "auto_privacy"
                        for item in self.firewall().get("nftables", [])),
                "An anonymity guard remains; turn its mode off before changing sharing.")
        state = self.load()
        if mode == "off":
            self.watch_stop()
            if state:
                self.disable(state)
            else:
                firewall_check(self.firewall())
                self.routes_check()
                self.gate(False)
            return "Sharing is off. Normal Pi routing is restored; control access and upstream connections remain."
        selected = self.with_sources(self.select(mode, interface), sources)
        if state and state["selection"] == selected:
            try:
                self.routes_check(selected)
            except Error:
                # Reconnect can leave known kernel-degraded owned routes. Verify
                # their narrow cleanup forms before rebuilding; never call them healthy.
                self.routes_check(selected, {**state, "ready": False})
            else:
                if self.healthy(state):
                    self.watch_start()
                    return "Sharing is already active through " + selected["interface"] + "."
        previous = state["selection"] if state else None
        if state: self.disable(state, keep_gate=True)
        try:
            self.enable(selected, held_gate=bool(previous))
        except BaseException as original:
            if previous:
                try:
                    restored = self.with_sources(self.select(previous["mode"], previous["interface"]), previous.get("sources"))
                    require(all(restored[key] == previous[key] for key in ("address", "gateway", "network")), "Previous uplink changed.")
                    self.enable(restored, held_gate=True)
                except BaseException:
                    raise Error("The new upstream failed; the previous selection could not be restored. External traffic remains blocked; run --off.") from original
            raise
        labels = ([CTRL] if control_enabled(selected) else []) + (["additional AP"] if guest_enabled(selected) else [])
        self.watch_start()
        return "Pi" + (" and " + ", ".join(labels) if labels else " only") + " use " + selected["interface"] + "; no fallback (until reboot)."

    def control_ssid(self):
        try:
            ssid = re.search(r"(?m)^ssid2=([0-9a-fA-F]+)$", self.read("etc/hostapd/hostapd.conf"))
            return json.dumps(bytes.fromhex(ssid[1]).decode("utf-8"),ensure_ascii=True) if ssid else "unavailable"
        except (Error,OSError,ValueError): return "unavailable"

    def wifi_ssid(self, name):
        try:
            identifier = self.run(["/usr/bin/nmcli", "-g", "GENERAL.CON-UUID", "device", "show", name]).strip()
            if not re.fullmatch(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", identifier):
                return "none"
            return json.dumps(self.run(["/usr/bin/nmcli", "--escape", "no", "-g", "802-11-wireless.ssid", "connection", "show", identifier]).rstrip("\n"), ensure_ascii=True)
        except (Error, OSError):
            return "unavailable"

    def status(self):
        state = self.load()
        if state:
            selected = state["selection"]
            try:
                healthy = self.healthy(state)
                status = "active" if healthy else "degraded; reapply --" + selected["mode"]
            except (Error, OSError):
                status = "degraded; inspect the selected interface or run --off"
            print("Sharing: " + status)
            print("Selected upstream: " + selected["mode"] + " / " + selected["interface"])
            print("Control WLAN Internet: " + ("enabled" if control_enabled(selected) else "off; local control access remains"))
            print("Additional AP Internet: " + ("enabled; same selected uplink; IPv4 only" if guest_enabled(selected) else "off"))
            if selected["mode"] == "wifi": print("Upstream SSID: " + self.wifi_ssid(selected["interface"]))
            print("IPv4 gateway: " + selected["gateway"])
            print("Selected DNS: " + ", ".join(selected["dns"]))
        else:
            firewall_check(self.firewall())
            self.routes_check()
            require(not self.gate_present(), "A temporary egress guard remains without state; run --off to remove the verified guard.")
            print("Sharing: off")
        controls = [item for item in self.ip("-j", "address", "show") if item.get("ifname") == CTRL]
        control = controls[0] if controls else {}
        control_state = (f"admin {'up' if 'UP' in control.get('flags', []) else 'down'}, "
                         f"operational {operational_state(control)}") if control else "absent"
        control_addresses = ", ".join(f"{item['local']}/{item['prefixlen']}" for item in control.get("addr_info", [])
                                     if item.get("family") == "inet") or "no IPv4 address"
        print(f"Control interface: ctrl0 ({control_state}, {control_addresses})")
        try:
            config = self.read("etc/hostapd/hostapd.conf")
            ssid = re.search(r"(?m)^ssid2=([0-9a-fA-F]+)$", config)
            print("Control SSID: " + (json.dumps(bytes.fromhex(ssid[1]).decode("utf-8"), ensure_ascii=True) if ssid else "unavailable"))
        except (Error, OSError, ValueError): print("Control SSID: unavailable")
        if state:
            print("Pi and selected client networks: selected uplink only; no fallback")
            if not state["ready"]:
                print("IPv6 sharing: not active; activation or cleanup is incomplete")
            else:
                print("IPv6 sharing: " + (("ULA + RA + NAT66 configured for selected control WLAN" if control_enabled(selected) else
                      "off for client networks; Pi IPv6 uses selected uplink") if selected["ipv6"] else
                      "blocked (completed discovery found no usable global address and default route)"))
        else:
            print("IPv6 sharing: off; Pi routing: normal NetworkManager policy")
        print("Lifetime: until reboot; selected uplink changes are watched while sharing is active")
        try:
            if self.watch_definition():
                active = self.run(["/usr/bin/systemctl", "show", WATCH_TIMER, "--property=ActiveState", "--value"]).strip()
                print("Automatic refresh: " + ("watching every 30s" if active == "active" else "off"))
                observed = self.watch_record()
                if observed:
                    print("Last watcher result: " + observed["status"] + " / " + observed["reason"] +
                          (" (" + ", ".join(observed["changes"]) + ")" if observed["changes"] else ""))
            else:
                print("Automatic refresh: watcher units not installed")
        except (RuntimeError, OSError, ValueError, KeyError, TypeError):
            print("Automatic refresh: watcher could not be verified; inspect its journal")
        candidates = self.interfaces()
        if self.path("run/automations-hotspot/state.json").exists():
            ap=json.loads(self.read("run/automations-hotspot/state.json"))
            print("Additional AP SSID on "+str(ap["adapter"][0])+": "+json.dumps(ap["ssid"],ensure_ascii=True))
        for item in candidates:
            if item["mode"] == "wifi": print("SSID on " + item["name"] + ": " + self.wifi_ssid(item["name"]))
            addresses = ", ".join(x["local"] for x in item["addresses"]) or "no IPv4 address"
            print(f"Interface: {item['name']} ({item['mode']}, admin {'up' if item['up'] else 'down'}, "
                  f"operational {item.get('operstate', 'unknown')}, {addresses})")
            try:
                connection = self.run(["/usr/bin/nmcli", "-g", "GENERAL.STATE", "device", "show", item["name"]]).strip()
                print("  Connection: " + ("connected" if connection.split(" ", 1)[0] == "100" else "not connected"))
            except Error:
                print("  Connection: unavailable")
        if not candidates:
            print("External interfaces: none")


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(64, f"{self.prog}: {message}\n")


def main(argv=None, platform=None, uid=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv == ["--internal-watch"]:
        platform = platform or Platform()
        try:
            require((os.geteuid() if uid is None else uid) == 0, "The sharing watcher requires root.")
            require(platform.watch_definition(), "The sharing watcher is not installed.")
            with platform.lock():
                outcome = platform.watch_once()
            return 1 if outcome == "failed" else 0
        except Busy:
            return 0  # A legitimate CLI operation owns the lock; defer this tick.
        except (RuntimeError, OSError, ValueError, KeyError, TypeError):
            print("Share watcher: inspection failed; no unverified state was overwritten.", file=sys.stderr)
            return 1
    if argv and argv[0]=="ap":
        try:
            module=selection_support().load_peer("auto_hotspot.py","/usr/local/libexec/automations-support/hotspot.py","_share_ap")
        except (OSError,ValueError):
            print("The optional hotspot-control component is not installed or is unsafe.",file=sys.stderr);return 1
        try:return module.main(argv[1:])
        except (RuntimeError,OSError,ValueError,KeyError) as error:
            print("ERROR: "+(str(error) if isinstance(error,module.Error) else "Cannot manage the additional AP safely; no private configuration was disclosed."),file=sys.stderr);return 1
        except KeyboardInterrupt:
            print("AP operation cancelled.",file=sys.stderr);return 130
    parser = Parser(prog="auto share", description="Use one connected uplink for this Pi and control-WLAN clients until reboot.")
    action = parser.add_mutually_exclusive_group()
    for name, help_text in (("wifi", "Use one connected external USB Wi-Fi adapter."),
                            ("lan", "Use one connected wired interface."), ("off", "Stop sharing and restore normal Pi routing."),
                            ("status", "Show sharing state and available interfaces (default).")):
        action.add_argument("--" + name, action="store_const", dest="action", const=name, help=help_text)
    uplink = parser.add_mutually_exclusive_group()
    uplink.add_argument("--to", dest="interface", metavar="NAME", help="Select the Internet uplink.")
    uplink.add_argument("--interface", dest="interface", metavar="NAME", help=argparse.SUPPRESS)
    parser.add_argument("--from", dest="sources", metavar="NAME[,NAME...]", help="Client networks receiving Internet; otherwise ask. The Pi always uses the selected uplink.")
    parser.epilog="Optional additional AP: auto share ap --help (hotspot-control component)."
    args = parser.parse_args(argv)
    if args.interface and args.action not in ("wifi", "lan"):
        parser.error("--to requires --wifi or --lan")
    if args.sources is not None and args.action not in ("wifi", "lan"):
        parser.error("--from requires --wifi or --lan")
    if (os.geteuid() if uid is None else uid) != 0:
        print("Use sudo auto share; reading the live firewall also requires root.", file=sys.stderr)
        return 77
    platform = platform or Platform()
    try:
        with platform.lock():
            if args.action in (None, "status"):
                platform.status()
            else:
                if args.action in ("wifi","lan"):
                    sources = platform.source_selection(args.sources)
                    print(platform.change(args.action, args.interface, sources))
                else:
                    print(platform.change(args.action, args.interface))
        return 0
    except KeyboardInterrupt:
        print("Sharing operation interrupted; check auto share --status.", file=sys.stderr)
        return 130
    except (RuntimeError, OSError, ValueError, KeyError, TypeError):
        # Error messages are deliberately bounded; no raw daemon output or profiles.
        error = sys.exc_info()[1]
        print(str(error) if isinstance(error, Error) else "Cannot inspect or change sharing safely; no configuration contents were disclosed.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
