#!/usr/bin/env python3
"""Toggle direct control-network SSH on the explicitly supported Pi4 v05 image."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import ipaddress
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time

SERVICE = "pi4-shell.service"
PRIVACY_API = 1
OFF_SERVICE = "automations-ssh-off.service"
RUNTIME = "/usr/local/libexec/automations/ssh"
SESSION_EXE = "/usr/lib/openssh/sshd-session"
CONFIG = "etc/pi4/sshd_config"
FIREWALL = "etc/nftables.conf"
UNIT = "etc/systemd/system/pi4-shell.service"
SHARE_STATE = "run/automations-share/state.json"
DIRECT_LISTENER = "ListenAddress 0.0.0.0:22\n"
DIRECT_RULE = '    iifname "ctrl0" tcp dport 22 accept\n'
CONFIG_OFF = """Port 2222
ListenAddress 127.0.0.1:2222

AddressFamily inet
HostKey /etc/pi4/ssh_host_ed25519_key
PidFile /run/pi4-shell/sshd.pid
AllowUsers kali
PermitRootLogin no
PasswordAuthentication yes
KbdInteractiveAuthentication no
PubkeyAuthentication no
UsePAM yes
PermitEmptyPasswords no
PermitTTY yes
DisableForwarding yes
PermitUserRC no
PermitUserEnvironment no
X11Forwarding no
Subsystem sftp internal-sftp
"""
UNIT_OFF = """[Unit]
Description=Pi4 separate SSH shell through Guacamole
After=network.target cloud-config.service

[Service]
Type=simple
RuntimeDirectory=pi4-shell sshd
RuntimeDirectoryMode=0755
ExecStart=/usr/sbin/sshd -D -e -f /etc/pi4/sshd_config
Restart=on-failure
RestartSec=2
# tmux owns persistent shell sessions, not the transient SSH connection.
KillMode=process
LimitCORE=0

[Install]
WantedBy=multi-user.target
"""
UNIT_ON = UNIT_OFF.replace("After=network.target cloud-config.service\n",
    "After=network.target cloud-config.service nftables.service\nRequires=nftables.service\n")
FIREWALL_OFF = """#!/usr/sbin/nft -f
flush ruleset
table inet pi4 {
  chain input {
    type filter hook input priority filter; policy drop;
    iifname "lo" accept
    ct state established,related accept
    iifname "ctrl0" udp sport 68 udp dport 67 accept
    iifname "ctrl0" udp dport 53 accept
    iifname "ctrl0" tcp dport 53 accept
    iifname "ctrl0" ip protocol icmp accept
    iifname "ctrl0" tcp dport { 80, 443 } accept
  }
  chain forward {
    type filter hook forward priority filter; policy drop;
  }
  chain output {
    type filter hook output priority filter; policy accept;
  }
}
"""


class Error(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise Error(message)


def config_text(enabled):
    return CONFIG_OFF.replace("ListenAddress 127.0.0.1:2222\n",
        "ListenAddress 127.0.0.1:2222\n" + (DIRECT_LISTENER if enabled else ""))


def firewall_text(enabled):
    return FIREWALL_OFF.replace('    iifname "ctrl0" tcp dport { 80, 443 } accept\n',
        '    iifname "ctrl0" tcp dport { 80, 443 } accept\n' + (DIRECT_RULE if enabled else ""))


def canonical(text):
    return [line.strip() for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]


def match(left, right):
    return {"match": {"op": "==", "left": left, "right": right}}


def iif(name):
    return match({"meta": {"key": "iifname"}}, name)


def port(protocol, field, value):
    return match({"payload": {"protocol": protocol, "field": field}}, value)


ALLOW = {"accept": None}
RULES = [
    [iif("lo"), ALLOW],
    [match({"ct": {"key": "state"}}, {"set": ["established", "related"]}), ALLOW],
    [iif("ctrl0"), port("udp", "sport", 68), port("udp", "dport", 67), ALLOW],
    [iif("ctrl0"), port("udp", "dport", 53), ALLOW],
    [iif("ctrl0"), port("tcp", "dport", 53), ALLOW],
    [iif("ctrl0"), port("ip", "protocol", "icmp"), ALLOW],
    [iif("ctrl0"), port("tcp", "dport", {"set": [80, 443]}), ALLOW],
]
SSH_RULE = [iif("ctrl0"), port("tcp", "dport", 22), ALLOW]
SHARE_DNS_RULES = [
    [iif("ctrl0"), match({"payload": {"protocol": "ip", "field": "saddr"}},
                         {"prefix": {"addr": "10.78.0.0", "len": 24}}),
     match({"payload": {"protocol": "ip", "field": "daddr"}}, "10.78.0.1"),
     port(protocol, "dport", 1053), ALLOW]
    for protocol in ("udp", "tcp")
]
SHARE_DNS_TAGS = ["auto-share:dns-udp-v1", "auto-share:dns-tcp-v1"]
SHARE_V6_TAGS = ["auto-share:" + tag + "-v2" for tag in (
    "upstream-ra", "upstream-nd", "upstream-errors", "upstream-mld", "upstream-dhcp6", "control-nd")]
SHARE_DNS6_TAGS = ["auto-share:dns6-" + protocol + "-v2" for protocol in ("udp", "tcp")]
SHARE_GUEST = {"interface": "autoap0", "network": "10.79.0.0/24", "address": "10.79.0.1",
               "host": "169.254.95.1", "peer": "169.254.95.2", "transit": "169.254.95.0/30"}
SHARE_GUEST_DNS_TAGS = ["auto-share:guest-dns-" + protocol + "-" + source
                        for source in ("peer", "client") for protocol in ("tcp", "udp")]
SHARE_GUEST_DNS_RULES = [
    [iif("autoap0"), port("ip", "saddr", source), port("ip", "daddr", "10.78.0.1"),
     port(protocol, "dport", 1053), ALLOW]
    for source in ("169.254.95.2", {"prefix": {"addr": "10.79.0.0", "len": 24}})
    for protocol in ("tcp", "udp")
]
ICMP6_NAMES = {"dst-unreach": 1, "destination-unreachable": 1, "packet-too-big": 2, "time-exceeded": 3,
               "param-problem": 4, "parameter-problem": 4, "mld-listener-query": 130, "nd-router-solicit": 133,
               "nd-router-advert": 134, "nd-neighbor-solicit": 135, "nd-neighbor-advert": 136}


def share_v6_rules(upstream):
    hop = port("ip6", "hoplimit", 255)
    linklocal = port("ip6", "saddr", {"prefix": {"addr": "fe80::", "len": 10}})
    return [
        [iif(upstream), linklocal, hop, port("icmpv6", "type", 134), ALLOW],
        [iif(upstream), hop, port("icmpv6", "type", {"set": [135, 136]}), ALLOW],
        [iif(upstream), port("icmpv6", "type", {"set": [1, 2, 3, 4]}), ALLOW],
        [iif(upstream), linklocal, port("ip6", "hoplimit", 1), port("icmpv6", "type", 130), ALLOW],
        [iif(upstream), match({"meta": {"key": "nfproto"}}, "ipv6"),
         port("udp", "sport", 547), port("udp", "dport", 546), ALLOW],
        [iif("ctrl0"), hop, port("icmpv6", "type", {"set": [133, 135, 136]}), ALLOW],
    ]


def live_ssh_handle(data, external_interfaces=(), missing_upstream=None):
    """Accept only the known v05 input chain; never infer safety from one rule."""
    require(isinstance(data, dict) and isinstance(data.get("nftables"), list), "Invalid nftables response.")
    chains, rules, comments = [], [], []
    for item in data["nftables"]:
        require(isinstance(item, dict), "Invalid nftables object.")
        if "chain" in item:
            chains.append(item["chain"])
        if "rule" in item:
            rule = item["rule"]
            require((rule.get("family"), rule.get("table"), rule.get("chain")) == ("inet", "pi4", "input"),
                    "Unexpected live firewall rule.")
            require(type(rule.get("handle")) is int and rule["handle"] > 0, "Missing firewall rule handle.")
            expr = json.loads(json.dumps(rule.get("expr")))
            # nft may render set membership with either == or in.
            if isinstance(expr, list):
                for statement in expr:
                    require(isinstance(statement, dict), "Invalid firewall expression.")
                    value = statement.get("match", {})
                    if value.get("left") == {"payload": {"protocol": "icmpv6", "field": "type"}}:
                        right = value.get("right")
                        if isinstance(right, str):
                            value["right"] = ICMP6_NAMES.get(right, right)
                        elif isinstance(right, dict) and isinstance(right.get("set"), list):
                            normalized = [ICMP6_NAMES.get(item, item) if isinstance(item, str) else item
                                          for item in right["set"]]
                            if all(type(item) is int for item in normalized):
                                value["right"] = {"set": sorted(normalized)}
                    # Native nft 1.1.7 emits conntrack state membership as a
                    # plain array. Normalize only the two permitted states.
                    states = value.get("right")
                    if (value.get("op") == "in" and value.get("left") == {"ct": {"key": "state"}}
                            and isinstance(states, list) and len(states) == 2
                            and all(isinstance(state, str) for state in states)
                            and set(states) == {"established", "related"}):
                        value["right"] = {"set": ["established", "related"]}
                    if value.get("op") == "in" and isinstance(value.get("right"), dict) and set(value["right"]) == {"set"}:
                        value["op"] = "=="
            rules.append((expr, rule["handle"]))
            comments.append(rule.get("comment", ""))
    require(len(chains) == 1, "Expected exactly one Pi4 input chain.")
    chain = chains[0]
    require((chain.get("family"), chain.get("table"), chain.get("name"), chain.get("type"),
             chain.get("hook"), chain.get("prio"), chain.get("policy")) ==
            ("inet", "pi4", "input", "filter", "input", 0, "drop"), "Unexpected input-chain policy or hook.")
    # Source selection prepends exact DNS denies for excluded networks. Keep
    # both their order and DROP verdict; comments alone never grant an exception.
    excluded = set()
    for interface in ("autoap0", "ctrl0"):
        tags = ["auto-share:excluded-dns-" + interface + "-" + protocol for protocol in ("udp", "tcp")]
        if comments and comments[0] == tags[0]:
            expected = [[iif(interface), port(protocol, "dport", 1053), {"drop": None}]
                        for protocol in ("udp", "tcp")]
            require(comments[:2] == tags and [expr for expr, _ in rules[:2]] == expected,
                    "Unexpected excluded sharing DNS rules; no changes made.")
            excluded.add(interface)
            rules, comments = rules[2:], comments[2:]
    # Sharing may add these two local control-network DNS exceptions.
    # Their exact addresses/port/order are required; a tag alone grants nothing.
    has_dns4 = any(comment in SHARE_DNS_TAGS for comment in comments)
    if has_dns4:
        require("ctrl0" not in excluded and comments[:2] == SHARE_DNS_TAGS and
                [expr for expr, _ in rules[:2]] == SHARE_DNS_RULES and
                not any(comment in SHARE_DNS_TAGS for comment in comments[2:]),
                "Unexpected sharing DNS rules; no changes made.")
        rules = rules[2:]
        comments = comments[2:]
    has_v6 = any(comment in SHARE_V6_TAGS + SHARE_DNS6_TAGS for comment in comments)
    if has_v6:
        require(comments[:6] == SHARE_V6_TAGS and len(rules) >= 6,
                "Unexpected sharing IPv6 rule order or comments.")
        first = rules[0][0]
        require(isinstance(first, list) and first and isinstance(first[0].get("match"), dict),
                "Invalid sharing IPv6 interface match.")
        upstream = first[0]["match"].get("right")
        require(isinstance(upstream, str) and re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}", upstream) and
                upstream not in ("lo", "ctrl0") and (upstream in external_interfaces or
                missing_upstream is not None and upstream == missing_upstream["interface"]),
                "Sharing IPv6 requires a known external interface or its protected sharing state.")
        require([expr for expr, _ in rules[:6]] == share_v6_rules(upstream),
                "Unexpected sharing IPv6 input scope.")
        rules, comments = rules[6:], comments[6:]
        if comments and comments[0] in SHARE_DNS6_TAGS:
            require(has_dns4 and comments[:2] == SHARE_DNS6_TAGS and len(rules) >= 2,
                    "Unexpected sharing IPv6 DNS order.")
            expr = rules[0][0]
            require(isinstance(expr, list) and len(expr) == 5, "Invalid sharing IPv6 DNS expression.")
            right = expr[1].get("match", {}).get("right", {})
            require(isinstance(right, dict), "Invalid sharing IPv6 DNS prefix.")
            source = right.get("prefix", {})
            require(isinstance(source, dict) and source.get("len") == 64 and isinstance(source.get("addr"), str),
                    "Sharing IPv6 DNS requires its /64 control prefix.")
            prefix = ipaddress.IPv6Network(source["addr"] + "/64", strict=True)
            require(prefix.subnet_of(ipaddress.IPv6Network("fd00::/8")), "Sharing IPv6 DNS requires a ULA prefix.")
            if upstream not in external_interfaces:
                require(missing_upstream["ipv6"] is not None and
                        missing_upstream["control6"]["network"] == str(prefix) and
                        missing_upstream["control6"]["address"] == str(prefix.network_address + 1),
                        "Sharing IPv6 DNS differs from its protected state.")
            expected = [[iif("ctrl0"), port("ip6", "saddr", {"prefix": {"addr": str(prefix.network_address), "len": 64}}),
                         port("ip6", "daddr", str(prefix.network_address + 1)), port(protocol, "dport", 1053), ALLOW]
                        for protocol in ("udp", "tcp")]
            require([expr for expr, _ in rules[:2]] == expected, "Unexpected sharing IPv6 DNS scope.")
            rules, comments = rules[2:], comments[2:]
        require(not any(comment in SHARE_V6_TAGS + SHARE_DNS6_TAGS for comment in comments),
                "Duplicate or misplaced sharing IPv6 rules.")
    has_guest_dns = any(comment in SHARE_GUEST_DNS_TAGS for comment in comments)
    if has_guest_dns:
        require("autoap0" not in excluded and comments[:4] == SHARE_GUEST_DNS_TAGS and
                [expr for expr, _ in rules[:4]] == SHARE_GUEST_DNS_RULES and
                not any(comment in SHARE_GUEST_DNS_TAGS for comment in comments[4:]),
                "Unexpected guest sharing DNS rules; no changes made.")
        rules, comments = rules[4:], comments[4:]
    if excluded or has_guest_dns:
        require(has_v6 and has_dns4 != ("ctrl0" in excluded) and
                has_guest_dns != ("autoap0" in excluded),
                "Incomplete or conflicting sharing source rules; no changes made.")
    expressions = [expr for expr, _ in rules]
    require(expressions in (RULES, RULES + [SSH_RULE]),
            "The live input chain differs from the supported v05 rules; no changes made.")
    return rules[-1][1] if len(rules) == len(RULES) + 1 else None


def run_command(args, input_text=None):
    result = subprocess.run(args, input=input_text, text=True, capture_output=True, timeout=15,
                            env={**os.environ, "LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
    if result.returncode:
        raise Error(f"{args[0]} failed: {result.stderr.strip() or result.stdout.strip() or result.returncode}")
    return result.stdout


class DirectTransports:
    """Identify only accepted TCP-22 transports, never remote destination ports."""
    def __init__(self, proc=Path("/proc"), opener=None, signaler=None, closer=os.close,
                 sleeper=time.sleep):
        self.proc = Path(proc)
        self.open = opener or getattr(os, "pidfd_open", None)
        self.signal = signaler or getattr(signal, "pidfd_send_signal", None)
        self.close, self.sleep = closer, sleeper

    def sockets(self):
        direct, protected = {}, set()
        for name in ("tcp", "tcp6"):
            lines = (self.proc / "net" / name).read_text().splitlines()
            require(lines and "local_address" in lines[0], "Invalid TCP socket inventory.")
            for line in lines[1:]:
                fields = line.split()
                require(len(fields) >= 10, "Invalid TCP socket entry.")
                local, remote, state, inode = fields[1], fields[2], fields[3], fields[9]
                port_number = int(local.rsplit(":", 1)[1], 16)
                require(inode.isdigit(), "Invalid TCP socket inode.")
                if port_number == 2222 and int(inode):
                    protected.add(inode)
                if port_number != 22 or state == "0A" or int(inode) == 0:
                    continue  # Listener and kernel-only TIME_WAIT are not sessions.
                require(name == "tcp", "Unexpected IPv6 direct SSH transport; no process was selected.")
                require(inode not in direct, "Duplicate direct SSH socket inode.")
                direct[inode] = (local, remote)
        return direct, protected

    def process(self, pid):
        path = self.proc / str(pid)
        fields = (path / "stat").read_text().rsplit(")", 1)[1].split()
        require(len(fields) >= 20, "Invalid process identity.")
        status = dict(line.split(":", 1) for line in (path / "status").read_text().splitlines() if ":" in line)
        uids = tuple(int(value) for value in status["Uid"].split())
        require(len(uids) == 4, "Invalid process ownership.")
        return (int(fields[1]), int(fields[19]), uids)

    def monitor(self, pid, main_pid, inodes, protected):
        identity = self.process(pid)
        require(pid != main_pid and identity[0] == main_pid and identity[2] == (0, 0, 0, 0),
                "Direct SSH monitor ancestry or ownership differs.")
        path = self.proc / str(pid)
        require(os.readlink(path / "exe") == SESSION_EXE, "Unexpected direct SSH executable.")
        title = (path / "cmdline").read_bytes().split(b"\0", 1)[0]
        require(title.startswith(b"sshd-session: ") and len(title) <= 256,
                "Unexpected direct SSH process title.")
        owned = set()
        for fd in (path / "fd").iterdir():
            try:
                target = os.readlink(fd)
            except FileNotFoundError:
                continue
            if target.startswith("socket:[") and target.endswith("]"):
                owned.add(target[8:-1])
        require(not owned.intersection(protected), "A direct SSH candidate also owns a protected Guacamole socket.")
        selected = owned.intersection(inodes)
        require(len(selected) == 1, "A direct SSH monitor must own exactly one selected transport.")
        return identity, next(iter(selected))

    def terminate(self, main_pid):
        require(self.open is not None and self.signal is not None, "Safe pidfd signaling is unavailable.")
        main = self.process(main_pid)
        require(main[2] == (0, 0, 0, 0) and
                os.readlink(self.proc / str(main_pid) / "exe") == "/usr/sbin/sshd",
                "Unexpected main SSH process identity.")
        direct, protected = self.sockets()
        selected, handles = {}, []
        try:
            for entry in self.proc.iterdir():
                if not entry.name.isdigit() or int(entry.name) == main_pid:
                    continue
                pid = int(entry.name)
                try:
                    info = self.process(pid)
                    if info[0] != main_pid or info[2] != (0, 0, 0, 0):
                        continue
                    # Other direct children, including Guacamole monitors, are
                    # ignored unless an FD belongs to a selected port-22 inode.
                    links = []
                    for fd in (entry / "fd").iterdir():
                        try:
                            links.append(os.readlink(fd))
                        except FileNotFoundError:
                            continue
                    if not any("socket:[" + inode + "]" in links for inode in direct):
                        continue
                    identity, inode = self.monitor(pid, main_pid, direct, protected)
                    require(inode not in selected, "Ambiguous direct SSH monitor ownership.")
                    handle = self.open(pid, 0)
                    handles.append(handle)
                    require(self.monitor(pid, main_pid, direct, protected) == (identity, inode),
                            "Direct SSH process changed while obtaining pidfd.")
                    selected[inode] = (pid, identity, handle)
                except (FileNotFoundError, ProcessLookupError):
                    continue
            current, protected_now = self.sockets()
            require(current.items() <= direct.items() and set(current) <= set(selected),
                    "Not every direct SSH transport has a verified monitor.")
            for inode, (pid, identity, handle) in selected.items():
                current, protected_now = self.sockets()
                if inode not in current:
                    continue
                require(current[inode] == direct[inode] and self.process(main_pid) == main,
                        "SSH transport or main process changed before signaling.")
                require(self.monitor(pid, main_pid, current, protected_now) == (identity, inode),
                        "Direct SSH monitor changed before signaling.")
                try:
                    # OpenSSH's privileged monitor forwards TERM to its own
                    # session child. No process tree or process-name kill.
                    self.signal(handle, signal.SIGTERM, None, 0)
                except ProcessLookupError:
                    pass  # Success still requires socket disappearance below.
            for attempt in range(31):
                remaining, _ = self.sockets()
                if not remaining:
                    require(self.process(main_pid) == main, "The main SSH process changed during disconnection.")
                    return len(direct)
                if attempt < 30:
                    self.sleep(0.1)
            raise Error(f"{len(remaining)} direct SSH transport(s) remain after the bounded termination wait.")
        finally:
            for handle in handles:
                self.close(handle)


class Platform:
    """Filesystem and runner injection is for tests only; the CLI has no root override."""
    def __init__(self, root=Path("/"), runner=run_command, owner=0, sleeper=time.sleep, transports=None):
        self.root, self.run, self.owner, self.sleep = Path(root), runner, owner, sleeper
        self.transports = transports or DirectTransports(self.root / "proc", sleeper=sleeper)

    def path(self, relative):
        return self.root / relative

    def read(self, relative):
        path = self.root
        for part in Path(relative).parts:
            path /= part
            info = path.lstat()
            require(not stat.S_ISLNK(info.st_mode) and info.st_uid == self.owner and not info.st_mode & 0o022,
                    f"Unsafe ownership, permissions or symlink: {relative}")
        require(stat.S_ISREG(info.st_mode), f"Expected a regular file: {relative}")
        return path.read_text(encoding="utf-8")

    def atomic_write(self, relative, text, *, expected=None):
        path = self.path(relative)
        previous = self.read(relative)
        require(expected is None or previous == expected, "Concurrent external edit detected before writing.")
        metadata = path.lstat()
        require(stat.S_ISREG(metadata.st_mode), f"Expected a regular file: {relative}")
        fd, temporary = tempfile.mkstemp(prefix=".auto-ssh-", dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                os.fchown(stream.fileno(), metadata.st_uid, metadata.st_gid)
                os.fchmod(stream.fileno(), stat.S_IMODE(metadata.st_mode))
                stream.write(text)
                stream.flush()
                os.fsync(stream.fileno())
            require(self.read(relative) == previous, "Concurrent external edit detected before replacing the file.")
            latest = path.lstat()
            require((latest.st_dev, latest.st_ino, latest.st_mode, latest.st_uid, latest.st_gid) ==
                    (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid, metadata.st_gid),
                    "Concurrent file replacement or permission change detected.")
            os.replace(temporary, path)
            directory = os.open(path.parent, os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            Path(temporary).unlink(missing_ok=True)

    @contextmanager
    def lock(self):
        fd = os.open(self.path("run/automations-ssh.lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        share_fd = None
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == self.owner and
                    stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1, "Unsafe SSH control lock.")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise Error("Another SSH control operation is running.") from exc
            if self.path("usr/local/libexec/automations-support/egress.py").exists():
                # Optional privacy activation edits narrowly owned INPUT rules.
                # Serialize with that operation even before its state is created.
                share_fd = os.open(self.path("run/automations-share.lock"),
                                   os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
                info = os.fstat(share_fd)
                require(stat.S_ISREG(info.st_mode) and info.st_uid == self.owner and
                        stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
                        "Unsafe shared egress lock.")
                try:
                    fcntl.flock(share_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise Error("Another sharing or anonymity operation is running.") from None
            yield
        finally:
            if share_fd is not None: os.close(share_fd)
            os.close(fd)

    def service(self):
        values = dict(line.split("=", 1) for line in self.run([
            "systemctl", "show", SERVICE, "--property=ActiveState,SubState,MainPID,FragmentPath,DropInPaths,ExecStart,KillMode,Requires,After"
        ]).splitlines() if "=" in line)
        require(values.get("ActiveState") == "active" and values.get("SubState") == "running", "The Guacamole SSH service is not running.")
        require(values.get("MainPID", "").isdigit() and int(values["MainPID"]) > 1, "Invalid SSH service PID.")
        require(values.get("FragmentPath") == "/" + UNIT and not values.get("DropInPaths") and values.get("KillMode") == "process",
                "Unsupported SSH unit or overrides.")
        require("argv[]=/usr/sbin/sshd -D -e -f /etc/pi4/sshd_config ;" in values.get("ExecStart", ""),
                "Unexpected running SSH command.")
        return values

    def missing_share_upstream(self, upstream):
        """An absent USB link remains known only through the owned V2 state."""
        require(isinstance(upstream, str) and re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}", upstream) and
                upstream not in ("lo", "ctrl0"), "Invalid missing sharing interface.")
        path = self.path(SHARE_STATE)
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 65536 and
                stat.S_IMODE(path.parent.lstat().st_mode) == 0o700,
                "Unsafe sharing-state file metadata.")
        # read() checks every path component for root ownership and symlinks.
        state = json.loads(self.read(SHARE_STATE))
        require(isinstance(state, dict) and set(state) == {"version", "selection", "forwarding",
                "ipv6_forwarding", "owned_addresses", "ready", "steps"} and
                type(state["version"]) is int and state["version"] == 2 and type(state["ready"]) is bool,
                "Unrecognized sharing-state schema.")
        selected = state["selection"]
        keys = {"mode", "interface", "address", "network", "gateway", "dns", "ipv6", "control6"}
        require(isinstance(selected, dict) and keys <= selected.keys() <= keys | {"guest", "sources"} and
                selected["mode"] in ("wifi", "lan") and
                selected["interface"] == upstream, "Sharing state does not identify the missing upstream.")
        if "guest" in selected:
            require(selected["guest"] == SHARE_GUEST, "Invalid sharing guest role.")
        if "sources" in selected:
            sources = selected["sources"]
            require(isinstance(sources, list) and len(sources) <= 2 and
                    all(isinstance(name, str) and name in ("ctrl0", "autoap0") for name in sources) and
                    len(set(sources)) == len(sources) and ("autoap0" not in sources or "guest" in selected),
                    "Invalid sharing source selection.")
        network = ipaddress.IPv4Network(selected["network"])
        require(not network.overlaps(ipaddress.IPv4Network("10.78.0.0/24")), "Unsupported sharing subnet.")
        if "guest" in selected:
            require(not any(network.overlaps(ipaddress.IPv4Network(SHARE_GUEST[key]))
                            for key in ("network", "transit")), "Sharing upstream overlaps the guest role.")
        for key in ("address", "gateway"):
            address = ipaddress.IPv4Address(selected[key])
            require(address in network and not (address.is_unspecified or address.is_loopback or
                    address.is_multicast or address.is_link_local or address.is_reserved), "Invalid sharing IPv4 state.")
        control = selected["control6"]
        require(isinstance(control, dict) and set(control) == {"network", "address", "linklocal"},
                "Invalid sharing control IPv6 state.")
        prefix = ipaddress.IPv6Network(control["network"])
        require(prefix.prefixlen == 64 and prefix.subnet_of(ipaddress.IPv6Network("fd00::/8")) and
                control["address"] == str(prefix.network_address + 1) and
                ipaddress.IPv6Address(control["linklocal"]).is_link_local, "Invalid sharing control IPv6 prefix.")
        v6 = selected["ipv6"]
        if v6 is not None:
            require(isinstance(v6, dict) and set(v6) == {"addresses", "address", "network", "gateway"} and
                    isinstance(v6["addresses"], list) and 1 <= len(v6["addresses"]) <= 16 and
                    len(set(v6["addresses"])) == len(v6["addresses"]), "Invalid sharing upstream IPv6 state.")
            net6 = ipaddress.IPv6Network(v6["network"])
            require(all(ipaddress.IPv6Address(value) in ipaddress.IPv6Network("2000::/3") for value in v6["addresses"]) and
                    v6["address"] in v6["addresses"] and ipaddress.IPv6Address(v6["address"]) in net6 and
                    (ipaddress.IPv6Address(v6["gateway"]).is_link_local or ipaddress.IPv6Address(v6["gateway"]) in net6),
                    "Invalid sharing upstream IPv6 addresses.")
        dns = selected["dns"]
        require(isinstance(dns, list) and 1 <= len(dns) <= 16 and len(set(dns)) == len(dns), "Invalid sharing DNS state.")
        for value in dns:
            require(isinstance(value, str), "Invalid sharing DNS value.")
            plain, *scope = value.split("%")
            address = ipaddress.ip_address(plain)
            require(not (address.is_unspecified or address.is_loopback or address.is_multicast) and
                    (address.version != 6 or v6 is not None) and
                    (scope == [upstream] if address.version == 6 and address.is_link_local else not scope),
                    "Invalid sharing DNS address or scope.")
        expected_forwarding = {"ctrl0", upstream} | ({"autoap0"} if "guest" in selected else set())
        require(isinstance(state["forwarding"], dict) and set(state["forwarding"]) == expected_forwarding and
                all(value in ("0", "1") for value in state["forwarding"].values()), "Invalid sharing forwarding state.")
        settings = state["ipv6_forwarding"]
        require(isinstance(settings, dict) and {"all", "default", "ctrl0", upstream} <= settings.keys() and
                all(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,14}", name) and
                    value in ("0", "1") for name, value in settings.items()), "Invalid sharing IPv6 forwarding state.")
        steps = state["steps"]
        require(isinstance(steps, list) and len(set(steps)) == len(steps) and
                set(steps) <= {"gate", "admission", "addresses", "routes", "unit", "firewall", "forwarding"} and
                ("admission" in steps or "firewall" in steps), "Sharing state does not own live input exceptions.")
        owned = state["owned_addresses"]
        expected = {control["address"] + "/64", control["linklocal"] + "/64"} if v6 is not None else set()
        require(isinstance(owned, list) and len(set(owned)) == len(owned) and set(owned) <= expected,
                "Invalid owned sharing addresses.")
        return selected

    def handle(self):
        data = json.loads(self.run(["nft", "--json", "--handle", "list", "chain", "inet", "pi4", "input"]))
        require(isinstance(data, dict) and isinstance(data.get("nftables"), list) and
                all(isinstance(item, dict) for item in data["nftables"]), "Invalid nftables response.")
        if self.path("run/automations-anonymity/state.json").exists() or any(
                item.get("rule", {}).get("comment", "").startswith("auto-privacy:")
                for item in data["nftables"]):
            relative = "usr/local/libexec/automations-support/egress.py"
            self.read(relative)  # Check all parent ownership/permissions before import.
            info = self.path(relative).stat()
            require(info.st_nlink == 1 and info.st_size <= 131072, "Unsafe anonymity helper file.")
            spec = importlib.util.spec_from_file_location("_automations_ssh_privacy", self.path(relative))
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            try:
                full = json.loads(self.run(["nft", "--json", "--handle", "list", "ruleset"]))
                view = module.firewall_view(full, self.root, self.owner)
            except module.Error as error:
                raise Error(str(error)) from None
            data = {"nftables": [item for item in view["nftables"] if
                item.get("chain", {}).get("family") == "inet" and
                item.get("chain", {}).get("table") == "pi4" and item["chain"].get("name") == "input" or
                item.get("rule", {}).get("family") == "inet" and
                item.get("rule", {}).get("table") == "pi4" and item["rule"].get("chain") == "input"]}
        if any(item.get("rule", {}).get("comment") in SHARE_V6_TAGS + SHARE_DNS6_TAGS
               for item in data.get("nftables", [])):
            links = json.loads(self.run(["ip", "-json", "address", "show"]))
            require(isinstance(links, list), "Invalid network interfaces for sharing.")
            require(all(isinstance(item, dict) for item in links), "Invalid network interface entry.")
            external = {item.get("ifname") for item in links if isinstance(item.get("ifname"), str) and
                        item["ifname"] not in ("lo", "ctrl0")}
            candidates = [item["rule"].get("expr", []) for item in data["nftables"]
                          if item.get("rule", {}).get("comment") == SHARE_V6_TAGS[0]]
            require(len(candidates) == 1 and isinstance(candidates[0], list) and candidates[0] and
                    isinstance(candidates[0][0], dict) and isinstance(candidates[0][0].get("match"), dict),
                    "Invalid sharing upstream rule.")
            upstream = candidates[0][0].get("match", {}).get("right")
            require(isinstance(upstream, str), "Invalid sharing upstream name.")
            missing = self.missing_share_upstream(upstream) if upstream not in external else None
        else:
            external, missing = set(), None
        return live_ssh_handle(data, external, missing)

    def listeners(self, pid):
        found = set()
        for line in self.run(["ss", "-H", "-ltnp"]).splitlines():
            parts = line.split()
            require(len(parts) >= 5, "Invalid TCP listener response.")
            address = parts[3]
            if address.rsplit(":", 1)[-1] not in ("22", "2222"):
                continue
            require(address in ("0.0.0.0:22", "127.0.0.1:2222") and f"pid={pid}," in line,
                    "An unexpected process or address owns an SSH listener.")
            found.add(address)
        require("127.0.0.1:2222" in found, "Guacamole loopback SSH is not listening.")
        return "0.0.0.0:22" in found

    def inspect(self):
        files = {name: self.read(name) for name in (CONFIG, FIREWALL, UNIT)}
        cfg = canonical(files[CONFIG])
        require(cfg in (canonical(config_text(False)), canonical(config_text(True))), "Unsupported SSH configuration; no changes made.")
        enabled = cfg == canonical(config_text(True))
        require(canonical(files[FIREWALL]) == canonical(firewall_text(enabled)), "Persistent firewall and SSH configuration differ from the supported v05 state.")
        require(canonical(files[UNIT]) in (canonical(UNIT_OFF), canonical(UNIT_ON)), "Unsupported persistent SSH unit.")
        service = self.service()
        if enabled:
            require(canonical(files[UNIT]) == canonical(UNIT_ON) and
                    "nftables.service" in service.get("Requires", "").split() and
                    "nftables.service" in service.get("After", "").split(), "Direct SSH requires the loaded nftables startup dependency.")
        require((self.handle() is not None) == enabled and self.listeners(service["MainPID"]) == enabled,
                "Persistent and running SSH states differ; inspect the platform before retrying.")
        interfaces = json.loads(self.run(["ip", "-json", "address", "show"]))
        require(isinstance(interfaces, list), "Invalid network interface response.")
        direct, _ = self.transports.sockets()
        return {"enabled": enabled, "files": files, "interfaces": interfaces,
                "main_pid": int(service["MainPID"]), "direct_connections": len(direct)}

    def check_candidates(self, files):
        for name, command in ((CONFIG, ["/usr/sbin/sshd", "-t", "-f"]), (FIREWALL, ["nft", "--check", "--file"])):
            fd, temporary = tempfile.mkstemp(prefix=".auto-ssh-check-", dir=self.path(name).parent)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as stream:
                    stream.write(files[name])
                self.run([*command, temporary])
            finally:
                Path(temporary).unlink(missing_ok=True)

    def apply_live(self, enabled):
        handle = self.handle()
        if (handle is not None) == enabled:
            return
        batch = ('add rule inet pi4 input iifname "ctrl0" tcp dport 22 accept\n' if enabled else
                 f"delete rule inet pi4 input handle {handle}\n")
        self.run(["nft", "--check", "--file", "-"], batch)
        self.run(["nft", "--file", "-"], batch)

    def hup(self):
        self.run(["systemctl", "kill", "--kill-whom=main", "--signal=HUP", SERVICE])

    def wait_state(self, expected):
        last = None
        for attempt in range(15):
            try:
                state = self.inspect()
                require(state["enabled"] == expected, "The requested SSH state was not reached.")
                return state
            except Error as exc:
                last = exc
                if attempt < 14:
                    self.sleep(0.1)
        raise last

    def change(self, enabled):
        state = self.inspect()
        if state["enabled"] == enabled:
            return state, False
        if enabled:
            require(any(item.get("ifname") == "ctrl0" and "UP" in item.get("flags", []) and
                        any(address.get("local") == "10.78.0.1" and address.get("prefixlen") == 24 for address in item.get("addr_info", []))
                        for item in state["interfaces"]), "Control interface ctrl0 is not configured as 10.78.0.1/24 and up.")
        old = state["files"]
        new = {CONFIG: config_text(enabled), FIREWALL: firewall_text(enabled), UNIT: UNIT_ON}
        self.check_candidates(new)
        changed = [name for name in (UNIT, FIREWALL, CONFIG) if new[name] != old[name]]
        written = []
        try:
            for name in changed:
                require(self.read(name) == old[name], "Configuration changed during the operation.")
                written.append(name)
                self.atomic_write(name, new[name], expected=old[name])
            if UNIT in changed:
                self.run(["systemctl", "daemon-reload"])
            self.apply_live(enabled)
            self.hup()
            return self.wait_state(enabled), True
        except (Exception, KeyboardInterrupt) as failure:
            errors = []
            for name in reversed(written):
                try:
                    current = self.read(name)
                    require(current in (old[name], new[name]),
                            "Concurrent external edit detected; that file was not overwritten.")
                    if current != old[name]:
                        self.atomic_write(name, old[name], expected=current)
                except (Exception, KeyboardInterrupt) as exc:
                    errors.append(f"restore {name}: {exc}")
            if UNIT in written:
                try:
                    # Never deliberately load an administrator's concurrent edit.
                    require(self.read(UNIT) == old[UNIT],
                            "Original service definition was not restored; daemon-reload was skipped.")
                    self.run(["systemctl", "daemon-reload"])
                except (Exception, KeyboardInterrupt) as exc:
                    errors.append(f"restore service definition: {exc}")

            def restore_listeners():
                # HUP re-reads the on-disk sshd config. A restore conflict must
                # not turn into activation of unknown directives or listeners.
                require(self.read(CONFIG) == old[CONFIG] and self.read(UNIT) == old[UNIT],
                        "Original SSH configuration or service definition was not restored; HUP was skipped.")
                self.run(["/usr/sbin/sshd", "-t", "-f", str(self.path(CONFIG))])
                require(self.read(CONFIG) == old[CONFIG] and self.read(UNIT) == old[UNIT],
                        "SSH configuration changed during rollback validation; HUP was skipped.")
                self.hup()

            for label, operation in (("restore firewall", lambda: self.apply_live(state["enabled"])),
                                     ("restore SSH listeners", restore_listeners),
                                     ("verify restored state", lambda: self.wait_state(state["enabled"]))):
                try:
                    operation()
                except (Exception, KeyboardInterrupt) as exc:
                    errors.append(f"{label}: {exc}")
            reason = "Operation interrupted" if isinstance(failure, KeyboardInterrupt) else str(failure)
            if errors:
                raise Error(f"SSH change failed: {reason}. Rollback incomplete: {'; '.join(errors)}") from failure
            raise Error(f"SSH change failed; previous state restored: {reason}") from failure


    def turn_off(self):
        """Commit reversible OFF before starting irreversible disconnection."""
        before = self.inspect()
        state, changed = self.change(False)
        try:
            require(state["main_pid"] == before["main_pid"], "The main SSH process changed before disconnection.")
            self.transports.terminate(state["main_pid"])
            final = self.inspect()
            require(not final["enabled"] and final["main_pid"] == before["main_pid"] and
                    final["direct_connections"] == 0, "Direct SSH shutdown verification failed.")
            return final, changed
        except (Exception, KeyboardInterrupt) as exc:
            # Disconnecting callers cannot be undone. Never put the listener
            # or firewall permit back after this boundary, even on an error.
            raise Error("New direct SSH connections remain blocked; existing direct SSH connections "
                        "could not all be terminated. " + str(exc)) from exc


def off_worker(platform):
    """Fixed systemd-only action, independent of a disconnected calling SSH TTY."""
    values = dict(line.split("=", 1) for line in platform.run([
        "systemctl", "show", OFF_SERVICE,
        "--property=Transient,User,Group,ControlGroup,ExecStart,StandardInput,StandardOutput,StandardError"
    ]).splitlines() if "=" in line)
    group = "/system.slice/" + OFF_SERVICE
    require(values.get("Transient") == "yes" and values.get("User") == "root" and
            values.get("Group") == "root" and values.get("ControlGroup") == group and
            values.get("StandardInput") == "null" and values.get("StandardOutput") == "journal" and
            values.get("StandardError") == "journal" and
            f"argv[]=/usr/bin/python3 -I {RUNTIME} --internal-off ;" in values.get("ExecStart", "") and
            (platform.path("proc/self/cgroup").read_text().strip() == "0::" + group),
            "The internal SSH OFF action requires its fixed root systemd worker.")
    with platform.lock():
        state, _ = platform.turn_off()
        print("Direct SSH connections terminated. Guacamole sessions are preserved.")
        print_status(state)


def interrupt_worker(signum, frame):
    raise Error("SSH OFF worker was interrupted.")


def request_off(platform):
    # Do not hold the caller lock while waiting: the independent worker owns it
    # throughout the configuration transaction and selective disconnection.
    platform.read(RUNTIME.lstrip("/"))
    command = ["systemd-run", "--quiet", "--wait", "--collect", "--unit=" + OFF_SERVICE,
               "--property=Type=exec", "--property=User=root", "--property=Group=root",
               "--property=UMask=0077", "--property=RuntimeMaxSec=90s", "--property=TimeoutStopSec=120s",
               "--property=KillMode=control-group", "--property=StandardInput=null",
               "--property=StandardOutput=journal", "--property=StandardError=journal",
               "/usr/bin/python3", "-I", RUNTIME, "--internal-off"]
    try:
        result = subprocess.run(command, text=True, capture_output=True, timeout=220,
                                stdin=subprocess.DEVNULL,
                                env={"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
    except (subprocess.TimeoutExpired, KeyboardInterrupt) as exc:
        raise Error("The SSH OFF worker may still be running independently. Check auto ssh --status "
                    "and journalctl -u " + OFF_SERVICE + ".") from exc
    if result.returncode:
        state = platform.inspect()
        if not state["enabled"]:
            raise Error("New direct SSH connections remain blocked; existing direct SSH connections "
                        "could not all be terminated. Check journalctl -u " + OFF_SERVICE + ".")
        raise Error("SSH OFF did not complete. Check journalctl -u " + OFF_SERVICE + ".")
    state = platform.inspect()
    require(not state["enabled"] and state["direct_connections"] == 0,
            "The SSH OFF worker finished but direct SSH is not fully disconnected.")
    return state


def print_status(state):
    print(f"Direct SSH: {'enabled' if state['enabled'] else 'disabled'}")
    print("Access: ctrl0 only, TCP 22" if state["enabled"] else "New direct SSH connections: blocked")
    print("Guacamole SSH: 127.0.0.1:2222 (running)")
    print(f"Existing direct SSH transports: {state['direct_connections']}")
    for interface in state["interfaces"]:
        if interface.get("ifname") == "lo":
            continue
        addresses = ", ".join(f"{entry['local']}/{entry['prefixlen']}" for entry in interface.get("addr_info", []) if "local" in entry)
        print(f"Interface {interface.get('ifname', '?')}: {interface.get('operstate', 'UNKNOWN')}, {addresses or 'no address'}")


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--internal-off"]:
        try:
            require(os.geteuid() == 0, "Root privileges are required for the internal SSH worker.")
            previous = signal.signal(signal.SIGTERM, interrupt_worker)
            try:
                off_worker(Platform())
            finally:
                signal.signal(signal.SIGTERM, previous)
            return 0
        except (Exception, KeyboardInterrupt) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
    parser = argparse.ArgumentParser(prog="auto ssh", description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--on", action="store_true", help="Enable new direct SSH connections through ctrl0 only")
    group.add_argument("--off", action="store_true", help="Block and terminate direct SSH connections; preserve Guacamole")
    group.add_argument("--status", action="store_true", help="Verify persistent and running state and show interfaces (requires root)")
    args = parser.parse_args(argv)
    try:
        require(os.geteuid() == 0, "Root privileges are required; run sudo auto ssh with the requested option.")
        platform = Platform()
        if args.off:
            print("Disabling direct SSH, including existing direct connections. This may disconnect your SSH terminal.", flush=True)
            state = request_off(platform)
            print("Direct SSH connections terminated. Guacamole sessions are preserved.")
            print_status(state)
            return 0
        with platform.lock():
            if args.status or not (args.on or args.off):
                state = platform.inspect()
            else:
                state, changed = platform.change(args.on)
                print("SSH setting updated." if changed else "SSH setting already matches.")
            print_status(state)
        return 0
    except (Error, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("ERROR: Operation interrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
