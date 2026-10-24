#!/usr/bin/env python3
"""Opt-in real-packet refresh check in a fresh network namespace.

Run as root: unshare -n python3 this-file.py [--tools EXTRACTED_PACKAGE_ROOT].
Refuses host/occupied network namespaces. No host service, NM profile, route,
firewall or Internet endpoint is used. Native dnsmasq and actual kernel policies
are exercised; the process manager and network discovery are local adapters.
The Tor transport is a dedicated-UID relay fixture, not a real Tor circuit.
"""
import argparse
import copy
import ctypes
import errno
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import select
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fixture = load("native_watch_fixture", HERE / "test_share_control.py")
share = fixture.share
egress = load("native_watch_egress", ROOT / "python/egress.py")


def execute(*args, check=True, input=None, env=None):
    return subprocess.run(args, input=input, text=True, capture_output=True, check=check, timeout=12, env=env)


def ip(*args):
    return execute("/usr/sbin/ip", *args).stdout


def question(query):
    end = 12
    labels = []
    while query[end]:
        labels.append(query[end + 1:end + 1 + query[end]].decode("ascii"))
        end += query[end] + 1
    kind, _ = struct.unpack("!HH", query[end + 1:end + 5])
    end += 5
    return ".".join(labels), kind, end


def packet_answer(query, answer):
    _, kind, end = question(query)
    assert kind in (1, 28), kind
    raw = (socket.inet_aton(answer) if kind == 1 else
           socket.inet_pton(socket.AF_INET6, "2001:db8::" + answer.rsplit(".", 1)[-1]))
    return (query[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0) + query[12:end] +
            b"\xc0\x0c" + struct.pack("!HHIH", kind, 1, 0, len(raw)) + raw)


def receive_exact(stream, length):
    value = b""
    while len(value) < length:
        part = stream.recv(length - len(value))
        if not part:
            raise EOFError("Truncated DNS-over-TCP frame")
        value += part
    return value


class TCP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class TCP6(TCP):
    address_family = socket.AF_INET6


def worker(role):
    servers = []
    if role == "tor":
        os.setgroups([])
        os.setgid(60001)
        os.setuid(60001)
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            if role == "tor":
                with socket.create_connection(("203.0.113.8", 18080), timeout=5) as upstream:
                    upstream.settimeout(None)
                    while True:
                        ready, _, _ = select.select([self.connection, upstream], [], [], 10)
                        if not ready:
                            continue
                        for source in ready:
                            data = source.recv(4096)
                            if not data:
                                return
                            (upstream if source is self.connection else self.connection).sendall(data)
            else:
                for line in self.rfile:
                    self.wfile.write(role.encode() + b":" + line)
                    self.wfile.flush()
    targets = [("0.0.0.0", 18080)] if role in ("selected", "alternate") else (
        [("10.78.0.1", 443)] if role == "control" else [("127.0.0.1", 19040), ("10.78.0.1", 19040)])
    for address in targets:
        server = TCP(address, Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
    if role in ("selected", "alternate"):
        server = TCP6(("2001:db8:ffff::8", 18080), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
    dns = ({"192.168.1.1": "192.0.2.10", "192.168.1.4": "192.0.2.20",
            "fd90:1::53": "192.0.2.40", "2001:db8:1::53": "192.0.2.50"} if role == "selected" else
           {"192.168.2.1": "192.0.2.99"} if role == "alternate" else
           {"127.0.0.1": "192.0.2.30"} if role == "tor" else {})
    def serve(sock, answer):
        while True:
            query, remote = sock.recvfrom(2048)
            if role == "tor":
                name, kind, _ = question(query)
                print("DNS_QUERY " + json.dumps({"name": name, "type": kind, "transport": "udp"}), flush=True)
            sock.sendto(packet_answer(query, answer), remote)
    def tcp_handler(answer):
        class DNS(socketserver.BaseRequestHandler):
            def handle(self):
                length, = struct.unpack("!H", receive_exact(self.request, 2))
                query = receive_exact(self.request, length)
                if role == "tor":
                    name, kind, _ = question(query)
                    print("DNS_QUERY " + json.dumps({"name": name, "type": kind, "transport": "tcp"}), flush=True)
                response = packet_answer(query, answer)
                self.request.sendall(struct.pack("!H", len(response)) + response)
        return DNS
    for address, answer in dns.items():
        sock = socket.socket(socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((address, 19053 if role == "tor" else 53))
        threading.Thread(target=serve, args=(sock, answer), daemon=True).start()
        if role != "tor":  # Real Tor DNSPort accepts UDP only.
            server = (TCP6 if ":" in address else TCP)((address, 53), tcp_handler(answer))
            threading.Thread(target=server.serve_forever, daemon=True).start()
            servers.append(server)
    print("READY", flush=True)
    threading.Event().wait()


def agent(host, port):
    with socket.create_connection((host, int(port)), timeout=5) as stream:
        identity = [stream.getsockname(), stream.getpeername()]
        reader = stream.makefile("rb")
        print(json.dumps(identity), flush=True)
        for line in sys.stdin:
            stream.sendall(line.encode())
            response = reader.readline().decode().strip()
            assert identity == [stream.getsockname(), stream.getpeername()]
            print(response, flush=True)


def dns_probe(name="probe.test", kind="A", report=False, tcp=False):
    qtype = {"A": 1, "AAAA": 28}[kind]
    encoded = b"".join(bytes([len(part)]) + part.encode("ascii") for part in name.split(".")) + b"\x00"
    query = struct.pack("!HHHHHH", 1234, 0x100, 1, 0, 0, 0) + encoded + struct.pack("!HH", qtype, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        try:
            if tcp:
                sock.connect(("10.78.0.1", 53))
                sock.sendall(struct.pack("!H", len(query)) + query)
                length, = struct.unpack("!H", receive_exact(sock, 2))
                response = receive_exact(sock, length)
            else:
                sock.sendto(query, ("10.78.0.1", 53))
                response, _ = sock.recvfrom(2048)
        except TimeoutError:
            if not report:
                raise
            print(json.dumps({"name": name, "type": qtype, "rcode": None,
                              "answers": [], "timeout": True}), flush=True)
            return
        assert response[:2] == query[:2]
        flags, questions, answers, _, _ = struct.unpack("!HHHHH", response[2:12])
        offset = 12
        def skip_name(position):
            while response[position]:
                if response[position] & 0xc0 == 0xc0:
                    return position + 2
                position += response[position] + 1
            return position + 1
        for _ in range(questions):
            offset = skip_name(offset) + 4
        addresses = []
        for _ in range(answers):
            offset = skip_name(offset)
            answer_type, _, _, length = struct.unpack("!HHIH", response[offset:offset + 10])
            offset += 10
            raw = response[offset:offset + length]
            offset += length
            if answer_type == qtype and length == (4 if qtype == 1 else 16):
                addresses.append(socket.inet_ntop(socket.AF_INET if qtype == 1 else socket.AF_INET6, raw))
        value = {"name": name, "type": qtype, "rcode": flags & 15, "answers": addresses}
        if report:
            print(json.dumps(value), flush=True)
        else:
            assert value["rcode"] == 0 and addresses, value
            print(addresses[0])


def sandbox_exec(command):
    """Kernel restrictions matching the DNS unit, without a host systemd unit.

    Only this child receives its own mount namespace and socket-family filter.
    Its executable/servers-file live below the owning check's private /run tree.
    The caller remains able to publish server-file changes for native HUP reads.
    """
    libc = ctypes.CDLL(None, use_errno=True)
    seccomp = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                           ctypes.c_ulong, ctypes.c_void_p]
    def checked(result):
        if result != 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
    previous = os.readlink("/proc/self/ns/mnt")
    checked(libc.unshare(0x20000))  # CLONE_NEWNS
    assert os.readlink("/proc/self/ns/mnt") != previous
    checked(libc.mount(None, b"/", None, 0x40000 | 0x4000, None))  # PRIVATE|REC
    class MountAttr(ctypes.Structure):
        _fields_ = [(name, ctypes.c_uint64) for name in
                    ("attr_set", "attr_clr", "propagation", "userns_fd")]
    # ProtectSystem=strict: recursively read-only mounts; API files remain read
    # accessible. No pathname in the parent namespace is mounted or remounted.
    readonly = MountAttr(1, 0, 0, 0)  # MOUNT_ATTR_RDONLY
    checked(libc.syscall(442, -100, b"/", 0x8000, ctypes.byref(readonly),
                         ctypes.sizeof(readonly)))  # mount_setattr, AT_RECURSIVE
    for target in (b"/tmp", b"/var/tmp"):
        checked(libc.mount(b"tmpfs", target, b"tmpfs", 2 | 4, b"mode=1777"))
    for target in (b"/home", b"/root", b"/run/user"):
        if os.path.isdir(target):
            checked(libc.mount(b"tmpfs", target, b"tmpfs", 1 | 2 | 4, b"mode=000"))
    assert os.statvfs("/").f_flag & os.ST_RDONLY
    assert os.statvfs("/usr").f_flag & os.ST_RDONLY
    assert not os.listdir("/home") and not os.listdir("/tmp")
    checked(libc.prctl(38, 1, 0, 0, 0))  # PR_SET_NO_NEW_PRIVS
    class ArgCmp(ctypes.Structure):
        _fields_ = [("arg", ctypes.c_uint), ("op", ctypes.c_uint),
                    ("datum_a", ctypes.c_uint64), ("datum_b", ctypes.c_uint64)]
    seccomp.seccomp_init.argtypes = [ctypes.c_uint32]
    seccomp.seccomp_init.restype = ctypes.c_void_p
    seccomp.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    seccomp.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32,
                                             ctypes.c_int, ctypes.c_uint, ctypes.POINTER(ArgCmp)]
    seccomp.seccomp_load.argtypes = [ctypes.c_void_p]
    seccomp.seccomp_release.argtypes = [ctypes.c_void_p]
    context = seccomp.seccomp_init(0x7fff0000)  # SCMP_ACT_ALLOW
    assert context
    try:
        syscall = seccomp.seccomp_syscall_resolve_name(b"socket")
        assert syscall >= 0
        # RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK.
        # Deny every other family, including future/out-of-range values.
        for family in set(range(17)) - {1, 2, 10, 16}:
            assert seccomp.seccomp_rule_add_array(context, 0x50000 | errno.EAFNOSUPPORT,
                syscall, 1, ctypes.byref(ArgCmp(0, 4, family, 0))) == 0  # EQ
        assert seccomp.seccomp_rule_add_array(context, 0x50000 | errno.EAFNOSUPPORT,
            syscall, 1, ctypes.byref(ArgCmp(0, 5, 17, 0))) == 0  # GE
        assert seccomp.seccomp_load(context) == 0
    finally:
        seccomp.seccomp_release(context)
    try:
        socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM)
    except OSError as error:
        assert error.errno == errno.EAFNOSUPPORT, error
    else:
        raise AssertionError("Address-family restriction was not installed")
    for family in (socket.AF_INET, socket.AF_INET6, socket.AF_UNIX, socket.AF_NETLINK):
        with socket.socket(family, socket.SOCK_DGRAM):
            pass
    print("DNSMASQ_SANDBOX: private mounts; readonly system; hidden home; private tmp; "
          "NoNewPrivileges=1; kernel socket-family seccomp filter", flush=True)
    os.execv(command[0], command)


class Native(fixture.Fixture):
    def __init__(self, root, tools, sandbox=False):
        self.live = False
        super().__init__(root)
        self.live = True
        self.tools = tools
        self.sandbox = sandbox
        if sandbox:
            executable = tools / "usr/sbin/dnsmasq" if tools else Path("/usr/sbin/dnsmasq")
            self.sandbox_binary = self.path("dnsmasq")
            self.sandbox_binary.write_bytes(executable.read_bytes())
            self.sandbox_binary.chmod(0o755)
        self.dns = self.tor = None
        self.loaded_unit = ""
        self.selection["dns"] = ["192.168.1.1"]
        self.env = {**os.environ, "LC_ALL": "C"}
        if tools:
            self.env["LD_LIBRARY_PATH"] = str(tools / "usr/lib/x86_64-linux-gnu")
        self.log = self.path("dns.log").open("w+")

    def path(self, relative):
        if self.live and relative.startswith("proc/"):
            return Path("/") / relative
        return super().path(relative)

    def select(self, mode, interface=None):
        share.validate_selection(self.selection)
        rows = json.loads(ip("-j", "address", "show", "dev", self.selection["interface"]))
        share.require(rows and "UP" in rows[0]["flags"] and any(x.get("local") == self.selection["address"] for x in rows[0]["addr_info"]), "Selected uplink unavailable")
        if self.selection["ipv6"]:
            present = {x.get("local") for x in rows[0]["addr_info"]}
            share.require(set(self.selection["ipv6"]["addresses"]) <= present, "Declared IPv6 source is absent")
        return copy.deepcopy(self.selection)

    def refresh_support(self):
        module = super().refresh_support()
        original = module.refresh
        def observed(*args, **kwargs):
            try:
                return original(*args, **kwargs)
            except BaseException as error:
                print("NATIVE REFRESH FAILURE: " + repr(error), file=sys.stderr, flush=True)
                raise
        module.refresh = observed
        return module

    def command(self, args, input_text=None, accepted=(0,)):
        self.calls.append((args[:], input_text))
        if args[0] == "/usr/bin/systemctl":
            action = args[1]
            if action == "show" and args[2] == "automations-tor.service":
                active = self.tor is not None and self.tor.poll() is None
                return "MainPID=" + str(self.tor.pid if active else 0) + "\nActiveState=" + ("active" if active else "inactive") + "\n"
            assert action != "show" or args[2] == share.SERVICE, args
            if action == "show":
                exists = self.path(share.UNIT).exists()
                active = self.dns is not None and self.dns.poll() is None
                return "LoadState=" + ("loaded" if exists else "not-found") + "\nActiveState=" + ("active" if active else "inactive") + "\nMainPID=" + str(self.dns.pid if active else 0) + "\nFragmentPath=" + ("/" + share.UNIT if exists else "") + "\nDropInPaths=\n"
            if action in ("stop", "restart") and self.dns is not None:
                self.dns.terminate()
                self.dns.wait(timeout=5)
                self.dns = None
            if action in ("start", "restart"):
                command = self.loaded_unit.split("ExecStart=", 1)[1].splitlines()[0].split()
                command = self.adjust(command)
                if self.sandbox:
                    command = [sys.executable, "-B", str(Path(__file__).resolve()), "--sandbox-exec"] + command
                self.dns = subprocess.Popen(command, stdout=self.log, stderr=self.log, env=self.env)
            elif action == "kill":
                assert args == ["/usr/bin/systemctl", "kill", "--kill-whom=main", "--signal=HUP", share.SERVICE]
                self.dns.send_signal(signal.SIGHUP)
            else:
                assert action in ("stop", "daemon-reload"), args
                if action == "daemon-reload":
                    self.loaded_unit = self.read(share.UNIT) if self.path(share.UNIT).exists() else ""
            return ""
        assert args[0] in ("/usr/sbin/ip", "/usr/sbin/nft", "/usr/bin/ss", "/usr/sbin/dnsmasq", "/usr/sbin/conntrack"), args
        result = execute(*self.adjust(args), check=False, input=input_text, env=self.env)
        share.require(result.returncode in accepted, "Native command failed: " + repr(args) + "\n" + result.stderr)
        return result.stdout

    def adjust(self, args):
        result = args[:]
        if self.tools and args[0] in ("/usr/sbin/dnsmasq", "/usr/sbin/conntrack"):
            result[0] = str(self.tools / args[0].lstrip("/"))
        if args[0] == "/usr/sbin/dnsmasq":
            if self.sandbox:
                result[0] = str(self.sandbox_binary)
            result += ["--log-facility=-", "--log-queries"]
        return [arg.replace("--servers-file=/" + share.DNS_SERVERS, "--servers-file=" + str(self.path(share.DNS_SERVERS))) for arg in result]


def main(tools, dns_lifecycle_repro=False, dns_late_backend_repro=False,
         dns_mixed_resolver_repro=None, dns_systemd_sandbox=False, dns_ifindex_reuse_repro=False,
         dns_tor_binding="implicit", dns_tor_post_enumerate=False,
         dns_bind_dynamic=False, dns_roundtrip=False):
    if dns_ifindex_reuse_repro and not dns_mixed_resolver_repro:
        dns_mixed_resolver_repro = "global"
    tor_servers = {"implicit": share.servers_text(fixture.SELECTION, tor=True),
                   "lo": "server=127.0.0.1#19053@lo\n",
                   "source": "server=127.0.0.1#19053@127.0.0.1\n",
                   "hash-lo": "server=/#/127.0.0.1#19053@lo\n"}[dns_tor_binding]
    if dns_tor_binding != "implicit":
        original_servers_text = share.servers_text
        def experimental_servers_text(selection, tor=False):
            value = original_servers_text(selection, tor=tor)
            return tor_servers if tor else value
        share.servers_text = experimental_servers_text
        print("TEST_OVERRIDE_TOR_SERVERS " + tor_servers.strip(), flush=True)
    if dns_bind_dynamic:
        original_unit_text = share.unit_text
        def experimental_unit_text(*args, **kwargs):
            return original_unit_text(*args, **kwargs).replace("--bind-interfaces", "--bind-dynamic")
        share.unit_text = experimental_unit_text
        print("TEST_OVERRIDE_BIND_MODE --bind-dynamic", flush=True)
    assert os.geteuid() == 0
    assert os.readlink("/proc/self/ns/net") != os.readlink("/proc/1/ns/net"), "Refusing host network namespace"
    assert [x["ifname"] for x in json.loads(ip("-j", "link", "show"))] == ["lo"], "Network namespace is not fresh"
    data = json.loads(execute("/usr/sbin/nft", "-j", "list", "ruleset").stdout)
    assert all("metainfo" in x for x in data.get("nftables", [])), "Firewall is not empty"
    children = []
    temporary = tempfile.TemporaryDirectory(prefix="native-share-watch-",
                                             dir="/run" if dns_systemd_sandbox else None)
    root = Path(temporary.name)
    root.chmod(0o755)  # dnsmasq drops privileges before re-reading servers-file
    p = Native(root, tools, sandbox=dns_systemd_sandbox)
    def spawn(args):
        process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        children.append(process)
        return process
    def line(process):
        assert select.select([process.stdout], [], [], 8)[0], "Worker did not answer"
        value = process.stdout.readline().strip()
        assert value, process.stderr.read() if process.poll() is not None else "Worker ended"
        return value
    def remote(net, *args, check=True):
        return execute("/usr/bin/nsenter", "-t", str(net.pid), "-n", "--", *args, check=check)
    def start(net, role):
        command = [sys.executable, "-B", str(Path(__file__).resolve()), "--worker", role]
        process = spawn((["/usr/bin/nsenter", "-t", str(net.pid), "-n", "--"] if net else []) + command)
        assert line(process) == "READY"
        return process
    def connect(net, host, port):
        process = spawn((["/usr/bin/nsenter", "-t", str(net.pid), "-n", "--"] if net else []) +
                        [sys.executable, "-B", str(Path(__file__).resolve()), "--agent", host, str(port)])
        json.loads(line(process))
        return process
    def exchange(process, expected):
        process.stdin.write("probe\n")
        process.stdin.flush()
        assert line(process) == expected + ":probe"
    def dns(net, expected):
        result = remote(net, sys.executable, "-B", str(Path(__file__).resolve()), "--dns", check=False)
        if result.returncode:
            p.log.flush()
            print(p.path("dns.log").read_text(), file=sys.stderr)
            print(p.command(["/usr/sbin/conntrack", "-L"], accepted=(0,)), file=sys.stderr)
        assert result.returncode == 0 and result.stdout.strip() == expected, result.stderr + result.stdout
    def ticks():
        with p.lock():
            assert p.watch_once() == "pending"
        with p.lock():
            outcome = p.watch_once()
            if outcome == "failed":
                p.log.flush()
                print(p.path("dns.log").read_text(), file=sys.stderr)
                if p.path(share.REFRESH_STATE).exists():
                    p.refresh_support().resume(p)
                else:
                    p.refresh_support().refresh(p, p.load(), p.selection)
            assert outcome == "refreshed"
    def dns_lifecycle(runtime, late_backend=False, remove_v6=None):
        """No cached reply counts: each wire query must reach the UDP backend."""
        executable = str(tools / "usr/sbin/dnsmasq") if tools else "/usr/sbin/dnsmasq"
        print(execute(executable, "--version", env=p.env).stdout.splitlines()[0], flush=True)
        pid = p.dns.pid
        nonce = str(time.monotonic_ns())
        assert "--interface=ctrl0" in p.loaded_unit and "--enable-ra" in p.loaded_unit
        assert p.load()["selection"]["ipv6"] is not None
        print("INITIAL_DNS_UNIT " + p.loaded_unit.split("ExecStart=", 1)[1].splitlines()[0], flush=True)
        print("INITIAL_DNS_SERVERS\n" + p.read(share.DNS_SERVERS), flush=True)
        def security(stage):
            status = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines()
                          if ":" in line)
            value = {key: status[key].strip() for key in
                     ("Uid", "Gid", "CapEff", "NoNewPrivs", "Seccomp")}
            print("DNSMASQ_SECURITY " + json.dumps({"stage": stage, **value}), flush=True)
            assert value["Uid"].split() == ["65534"] * 4
            assert value["Gid"].split() == ["65534"] * 4
            assert int(value["CapEff"], 16) == 0x3000
            if dns_systemd_sandbox:
                assert value["NoNewPrivs"] == "1" and value["Seccomp"] == "2"
                assert os.readlink(f"/proc/{pid}/ns/mnt") != os.readlink("/proc/self/ns/mnt")
        security("normal")
        def probe(net, name, kind, expected, backend=False, tcp=False):
            command = [sys.executable, "-B", str(Path(__file__).resolve()), "--dns",
                       "--dns-name", name, "--dns-type", kind, "--dns-report"]
            if tcp:
                command.append("--dns-tcp")
            result = remote(net, *command, check=False) if net else execute(*command, check=False)
            print(json.dumps({"origin": "client" if net else "Pi", "query": name,
                              "type": kind, "transport": "tcp" if tcp else "udp", "exit": result.returncode, "stdout": result.stdout.strip(),
                              "stderr": result.stderr.strip()}), flush=True)
            assert result.returncode == 0, result.stderr
            value = json.loads(result.stdout)
            if expected is None:
                assert not value["answers"] and (value["rcode"] != 0 or value.get("timeout")), value
            else:
                assert (value["rcode"] == 0 and set(value["answers"]) <= set(expected)
                        and (value["answers"] or not expected)), value
            if backend:
                observed = json.loads(line(p.tor).removeprefix("DNS_QUERY "))
                assert observed == {"name": name, "type": {"A": 1, "AAAA": 28}[kind],
                                    "transport": "tcp" if tcp else "udp"}, observed
                print("BACKEND19053 " + json.dumps(observed), flush=True)
            return value
        try:
            if dns_ifindex_reuse_repro:
                # Production RA re-enumerates after NEWADDR. Load servers first,
                # then deliver a real netlink event to populate cached ifindex.
                ip("address", "add", "198.18.0.1/32", "dev", "eth1")
                time.sleep(.15)
                print("IFINDEX_CACHE_PRIMED_BY_NEWADDR " + json.dumps(
                    json.loads(ip("-j", "link", "show", "dev", "eth0"))), flush=True)
            if remove_v6:
                original_servers = ["192.168.1.1", "fd90:1::53", "2001:db8:1::53"]
                removed = {"ula": "fd90:1::53", "global": "2001:db8:1::53"}[remove_v6]
                remaining_servers = [server for server in original_servers if server != removed]
                expected = ("192.0.2.10", "192.0.2.40", "192.0.2.50")
                assert p.selection["dns"] == original_servers
                assert p.read(share.DNS_SERVERS) == (
                    "server=192.168.1.1@eth0@192.168.1.2\n"
                    "server=fd90:1::53@eth0\nserver=2001:db8:1::53@eth0\n")
            else:
                original_servers = ["192.168.1.1", "192.168.1.4"]
                remaining_servers = ["192.168.1.1"]
                expected = ("192.0.2.10", "192.0.2.20")
            probe(client, "baseline-" + nonce + ".example.com", "A", expected)
            for label, servers in (("remove", remaining_servers), ("restore", original_servers)):
                p.selection["dns"] = servers
                ticks()
                time.sleep(.1)  # HUP is asynchronous; do not retry a failed query.
                assert p.dns.pid == pid
                probe(client, label + "-" + nonce + ".example.com", "A", expected)
            normal_answers = expected
            if dns_roundtrip:
                stream = connect(client, "2001:db8:ffff::8", 18080)
                exchange(stream, "selected")
                stream.stdin.close()
                stream.wait(timeout=5)
            for cycle in range(1, 3 if dns_roundtrip else 2):
                if late_backend:
                    # Prove the listener is absent at resolver-mode publication.
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as absent:
                        absent.bind(("127.0.0.1", 19053))
                else:
                    p.tor = start(None, "tor")
                activated_at = time.monotonic()
                with runtime.operation("tor") as op:
                    op.activate(60001, 19040, 19053)
                    if late_backend:
                        time.sleep(.1)  # Deliver activation HUP before querying.
                        assert p.dns.pid == pid
                        assert p.read(share.DNS_SERVERS) == tor_servers
                        probe(client, "before-backend-" + str(cycle) + "-" + nonce + ".example.com", "A", None)
                        time.sleep(max(0, .75 - (time.monotonic() - activated_at)))
                        p.tor = start(None, "tor")
                        print("LATE_BACKEND19053_READY_MS " + str(round(
                            1000 * (time.monotonic() - activated_at))), flush=True)
                    op.ready()
                time.sleep(.1)
                assert p.dns.pid == pid
                assert p.read(share.DNS_SERVERS) == tor_servers
                if dns_tor_post_enumerate:
                    ip("address", "add", "198.18.0." + str(cycle + 1) + "/32", "dev", "eth1")
                    time.sleep(.15)
                    print("TOR_NEWADDR_ENUMERATED", flush=True)
                security("tor-cycle-" + str(cycle))
                hup_count = sum(args[:2] == ["/usr/bin/systemctl", "kill"] for args, _ in p.calls)
                restart_count = sum(args[:2] == ["/usr/bin/systemctl", "restart"] for args, _ in p.calls)
                for tcp in ((False, True) if dns_roundtrip else (False,)):
                    probe(client, "pi4", "A", ("10.78.0.1",), tcp=tcp)
                    probe(client, "pi4", "AAAA", (), tcp=tcp)
                    for net, label in ((client, "client"), (None, "pi")):
                        for kind in ("A", "AAAA"):
                            name = ("www.icann.org" if not late_backend and not dns_roundtrip
                                    and label == "client" and kind == "A" else
                                    label + "-" + kind.lower() + "-" + ("tcp" if tcp else "udp") +
                                    "-" + str(cycle) + "-" + nonce + ".example.com")
                            expected = ("192.0.2.30",) if kind == "A" else ("2001:db8::30",)
                            probe(net, name, kind, None if tcp else expected, backend=not tcp, tcp=tcp)
                if dns_roundtrip:
                    guarded = execute(sys.executable, "-B", "-c", """
import os, socket, struct
os.setgroups([]); os.setgid(65534); os.setuid(65534)
query = struct.pack('!HHHHHH', 4321, 0x100, 1, 0, 0, 0) + b'\\x05guard\\x04test\\x00' + struct.pack('!HH', 1, 1)
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as stream:
    stream.settimeout(2)
    stream.sendto(query, ('192.168.1.1', 53))
    response, _ = stream.recvfrom(2048)
    assert response[-4:] == socket.inet_aton('192.0.2.30'), response
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as stream:
    stream.settimeout(1)
    try:
        stream.connect(('192.168.1.1', 53))
    except (PermissionError, TimeoutError):
        print('DNS_UDP_REDIRECTED_TCP_DENIED')
    else:
        raise AssertionError('Dedicated DNS UID connected directly to physical TCP DNS')
""", check=False)
                    assert guarded.returncode == 0 and guarded.stdout.strip() == "DNS_UDP_REDIRECTED_TCP_DENIED", guarded
                    observed = json.loads(line(p.tor).removeprefix("DNS_QUERY "))
                    assert observed == {"name": "guard.test", "type": 1, "transport": "udp"}, observed
                    denied6 = remote(client, sys.executable, "-c",
                        "import socket; socket.create_connection(('2001:db8:ffff::8',18080),.5)", check=False)
                    assert denied6.returncode != 0, "External IPv6 escaped the Tor guard"
                    egress.check_objects(runtime.raw_firewall(), runtime.state())
                    exchange(management, "control")
                    print("GUARD_PASS: resolver UDP redirected to Tor; direct TCP DNS denied; external IPv6 blocked; control TCP retained", flush=True)
                assert p.dns.pid == pid
                assert hup_count == sum(args[:2] == ["/usr/bin/systemctl", "kill"] for args, _ in p.calls)
                assert restart_count == sum(args[:2] == ["/usr/bin/systemctl", "restart"] for args, _ in p.calls)
                print("PASS: Tor cycle " + str(cycle) + "; unchanged dnsmasq PID; client/Pi UDP A+AAAA reached19053; " +
                      ("TCP external DNS failed closed; local pi4 UDP+TCP; " if dns_roundtrip else "") +
                      ("primed ifindex cache; " if dns_ifindex_reuse_repro else "") +
                      ("late backend; " if late_backend else "") +
                      "no extra HUP/restart during queries", flush=True)
                if dns_roundtrip:
                    with runtime.operation("tor") as op:
                        op.block()
                        p.tor.terminate()
                        p.tor.wait(timeout=5)
                        op.deactivate()
                    time.sleep(.1)
                    assert p.dns.pid == pid
                    assert p.read(share.DNS_SERVERS) == share.servers_text(p.selection)
                    security("normal-return-" + str(cycle))
                    for tcp in (False, True):
                        for net, label in ((client, "client"), (None, "pi")):
                            for kind in ("A", "AAAA"):
                                expected = normal_answers if kind == "A" else tuple(
                                    "2001:db8::" + value.rsplit(".", 1)[-1] for value in normal_answers)
                                probe(net, "normal-" + label + "-" + kind.lower() + "-" +
                                      ("tcp" if tcp else "udp") + "-" + str(cycle) + "-" + nonce +
                                      ".example.com", kind, expected, tcp=tcp)
                    exchange(management, "control")
                    print("PASS: normal return " + str(cycle) + "; client/Pi UDP+TCP A+AAAA; same dnsmasq PID", flush=True)
        finally:
            p.log.flush()
            print("DNSMASQ LOG\n" + p.path("dns.log").read_text(), flush=True)
            if runtime.state():
                with runtime.operation("tor") as op:
                    op.block()
                    if p.tor is not None and p.tor.poll() is None:
                        p.tor.terminate()
                        p.tor.wait(timeout=5)
                    op.deactivate()
            p.change("off")
    try:
        nets = [spawn(["/usr/bin/unshare", "-n", "/usr/bin/sleep", "600"]) for _ in range(3)]
        for net in nets:
            for _ in range(100):
                if os.readlink(f"/proc/{net.pid}/ns/net") != os.readlink("/proc/self/ns/net"):
                    break
                time.sleep(.01)
            else:
                raise AssertionError("Child namespace not ready")
        client, selected, alternate = nets
        for local, peer, net, a, b in (("ctrl0", "client0", client, "10.78.0.1/24", "10.78.0.20/24"),
                                     ("eth0", "wan0", selected, "192.168.1.2/24", "192.168.1.1/24"),
                                     ("eth1", "wan1", alternate, "192.168.2.2/24", "192.168.2.1/24")):
            ip("link", "add", local, "type", "veth", "peer", "name", peer)
            ip("link", "set", peer, "netns", str(net.pid))
            ip("address", "add", a, "dev", local)
            ip("link", "set", local, "up")
            remote(net, "/usr/sbin/ip", "address", "add", b, "dev", peer)
            remote(net, "/usr/sbin/ip", "link", "set", peer, "up")
            remote(net, "/usr/sbin/ip", "link", "set", "lo", "up")
        ip("link", "set", "lo", "up")
        # Match production: Share owns the control link-local/ULA addresses.
        ip("-6", "address", "flush", "dev", "ctrl0", "scope", "link")
        remote(client, "/usr/sbin/ip", "route", "add", "default", "via", "10.78.0.1")
        remote(client, "/usr/sbin/sysctl", "-q", "-w", "net.ipv6.conf.client0.accept_ra=0")
        remote(client, "/usr/sbin/ip", "-6", "address", "add", "fd12:3456:789a:1::20/64", "dev", "client0", "nodad")
        remote(client, "/usr/sbin/ip", "-6", "route", "add", "default", "via", fixture.SELECTION["control6"]["address"])
        for net in (selected, alternate):
            remote(net, "/usr/sbin/ip", "address", "add", "203.0.113.8/32", "dev", "lo")
            remote(net, "/usr/sbin/ip", "-6", "address", "add", "2001:db8:ffff::8/128", "dev", "lo", "nodad")
        for address in ("2001:db8:1::2/64", "2001:db8:2::2/64"):
            ip("-6", "address", "add", address, "dev", "eth0", "nodad")
        for address in ("2001:db8:1::1/64", "2001:db8:2::1/64", "fe80::1/64",
                        "fd90:1::53/64", "2001:db8:1::53/64"):
            remote(selected, "/usr/sbin/ip", "-6", "address", "add", address, "dev", "wan0", "nodad")
        ip("-6", "address", "add", "2001:db8:aa::2/64", "dev", "eth1", "nodad")
        remote(alternate, "/usr/sbin/ip", "-6", "address", "add", "2001:db8:aa::1/64", "dev", "wan1", "nodad")
        ip("-6", "route", "add", "default", "via", "2001:db8:aa::1", "dev", "eth1")
        remote(selected, "/usr/sbin/ip", "address", "add", "192.168.1.4/24", "dev", "wan0")
        ip("route", "add", "default", "via", "192.168.2.1", "dev", "eth1")
        main_before = json.loads(ip("-j", "route", "show", "table", "main"))
        start(selected, "selected")
        start(alternate, "alternate")
        p.nft({"nftables": [{"add": {kind: {k: v for k, v in value.items() if k != "handle"}}}
                             for item in fixture.baseline()["nftables"] for kind, value in item.items()]})
        if dns_lifecycle_repro or dns_late_backend_repro or dns_mixed_resolver_repro:
            p.selection["dns"] = (["192.168.1.1", "fd90:1::53", "2001:db8:1::53"]
                                  if dns_mixed_resolver_repro else ["192.168.1.1", "192.168.1.4"])
            p.selection["ipv6"] = dict(addresses=["2001:db8:1::2"], address="2001:db8:1::2",
                                         network="2001:db8:1::/64", gateway="fe80::1")
        p.change("lan")
        start(None, "control")
        management = connect(client, "10.78.0.1", 443)
        helper = p.path("usr/local/libexec/automations-support/egress.py")
        helper.parent.mkdir(parents=True)
        helper.write_bytes((ROOT / "python/egress.py").read_bytes())
        helper.chmod(0o644)
        runtime = egress.Runtime(share, p, lambda name: type("Account", (), {"pw_uid": 60001})())
        if dns_lifecycle_repro or dns_late_backend_repro or dns_mixed_resolver_repro:
            dns_lifecycle(runtime, late_backend=dns_late_backend_repro,
                          remove_v6=dns_mixed_resolver_repro)
            return
        for tor in (False, True):
            if tor:
                p.tor = start(None, "tor")
                with runtime.operation("tor") as op:
                    op.activate(60001, 19040, 19053)
                    op.ready()
            streams = [connect(net, "203.0.113.8", 18080) for net in (None, client)]
            dns(client, "192.0.2.30" if tor else "192.0.2.10")
            pid = p.dns.pid
            transport_pid = p.tor.pid if tor else None
            for servers, answer in ((["192.168.1.4"], "192.0.2.20"), (["192.168.1.1"], "192.0.2.10")):
                p.selection["dns"] = servers
                ticks()
                # Native HUP delivery is asynchronous; wait only for this probe,
                # never repeat an application download or hide the first failure.
                time.sleep(.1)
                dns(client, "192.0.2.30" if tor else answer)
                for stream in streams:
                    exchange(stream, "selected")
                exchange(management, "control")
                assert p.dns.pid == pid and (not tor or p.tor.pid == transport_pid)
            ip("link", "set", "eth0", "down")
            with p.lock():
                assert p.watch_once() == "unavailable"
            for net in (None, client):
                command = ["/usr/bin/python3", "-c", "import socket; s=socket.create_connection(('203.0.113.8',18080),1); s.sendall(b'outage\\n'); answer=s.recv(80); assert answer; print(answer.decode())"]
                result = remote(net, *command, check=False) if net else execute(*command, check=False)
                assert result.returncode != 0, "Traffic escaped through alternate main default"
            exchange(management, "control")
            ip("link", "set", "eth0", "up")
            # Linux discards IPv6 addresses on administrative link-down by
            # default. Re-populate them as NM would before declaring IPv6 ready.
            for address in ("2001:db8:1::2/64", "2001:db8:2::2/64"):
                ip("-6", "address", "replace", address, "dev", "eth0", "nodad")
            for address in ("2001:db8:1::1/64", "2001:db8:2::1/64", "fe80::1/64"):
                remote(selected, "/usr/sbin/ip", "-6", "address", "replace", address, "dev", "wan0", "nodad")
            with p.lock():
                outcome = p.watch_once()
            if outcome == "pending":
                with p.lock():
                    assert p.watch_once() == "refreshed"
            else:
                assert outcome == "active"
            for stream in streams:
                exchange(stream, "selected")
            # Preserve established sockets on the still-valid old source while
            # a new preferred address is selected; no physical address is lost.
            ip("address", "add", "192.168.1.3/24", "dev", "eth0")
            p.selection["address"] = "192.168.1.3"
            ticks()
            dns(client, "192.0.2.30" if tor else "192.0.2.10")
            for stream in streams:
                exchange(stream, "selected")
            exchange(management, "control")
            p.selection["address"] = "192.168.1.2"
            ticks()
            ip("address", "del", "192.168.1.3/24", "dev", "eth0")
            p.selection["ipv6"] = dict(addresses=["2001:db8:1::2"], address="2001:db8:1::2",
                                        network="2001:db8:1::/64", gateway="fe80::1")
            ticks()
            v6streams = [] if tor else [connect(net, "2001:db8:ffff::8", 18080) for net in (None, client)]
            if tor:
                blocked = remote(client, sys.executable, "-c", "import socket; socket.create_connection(('2001:db8:ffff::8',18080),1)", check=False)
                assert blocked.returncode != 0, "External IPv6 escaped the Tor guard"
            ip("-6", "address", "change", "2001:db8:1::2/64", "dev", "eth0", "preferred_lft", "0")
            p.selection["ipv6"] = dict(addresses=["2001:db8:2::2"], address="2001:db8:2::2",
                                        network="2001:db8:2::/64", gateway="fe80::1")
            ticks()
            for stream in streams + v6streams:
                exchange(stream, "selected")
            exchange(management, "control")
            for stream in v6streams:
                stream.stdin.close()
                stream.wait(timeout=5)
            p.selection["ipv6"] = None
            ticks()
            ip("-6", "address", "change", "2001:db8:1::2/64", "dev", "eth0", "preferred_lft", "forever")
            dns(client, "192.0.2.30" if tor else "192.0.2.10")
            exchange(management, "control")
            for stream in streams:
                exchange(stream, "selected")
                stream.stdin.close()
                stream.wait(timeout=5)
            assert main_before == json.loads(ip("-j", "route", "show", "table", "main"))
            print("PASS: " + ("Tor guard/UID relay" if tor else "normal") + ": DNS/IPv4/IPv6 changes, established TCP retained, no alternate fallback, control retained", flush=True)
        with runtime.operation("tor") as op:
            op.block()
            p.tor.terminate()
            p.tor.wait(timeout=5)
            op.deactivate()
        p.change("off")
        share.firewall_check(p.firewall())
        p.routes_check()
        assert main_before == json.loads(ip("-j", "route", "show", "table", "main"))
        print("PASS: normal cleanup, core firewall and main routes preserved; no real Tor-circuit claim", flush=True)
    finally:
        if p.dns is not None and p.dns.poll() is None:
            p.dns.terminate()
            p.dns.wait(timeout=5)
        for child in reversed(children):
            if child.poll() is None:
                child.terminate()
            child.wait(timeout=5)
        p.log.close()
        temporary.cleanup()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--tools", type=Path)
    parser.add_argument("--worker")
    parser.add_argument("--agent", nargs=2)
    parser.add_argument("--dns", action="store_true")
    parser.add_argument("--dns-name", default="probe.test")
    parser.add_argument("--dns-type", choices=("A", "AAAA"), default="A")
    parser.add_argument("--dns-report", action="store_true")
    parser.add_argument("--dns-tcp", action="store_true")
    parser.add_argument("--dns-lifecycle-repro", action="store_true")
    parser.add_argument("--dns-late-backend-repro", action="store_true")
    parser.add_argument("--dns-mixed-resolver-repro", choices=("ula", "global"))
    parser.add_argument("--dns-systemd-sandbox", action="store_true")
    parser.add_argument("--dns-ifindex-reuse-repro", action="store_true")
    parser.add_argument("--dns-tor-binding", choices=("implicit", "lo", "source", "hash-lo"), default="implicit")
    parser.add_argument("--dns-tor-post-enumerate", action="store_true")
    parser.add_argument("--dns-bind-dynamic", action="store_true")
    parser.add_argument("--dns-roundtrip", action="store_true")
    parser.add_argument("--sandbox-exec", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.sandbox_exec:
        sandbox_exec(args.sandbox_exec)
    elif args.worker:
        worker(args.worker)
    elif args.agent:
        agent(*args.agent)
    elif args.dns:
        dns_probe(args.dns_name, args.dns_type, args.dns_report, args.dns_tcp)
    else:
        main(args.tools, args.dns_lifecycle_repro, args.dns_late_backend_repro,
             args.dns_mixed_resolver_repro, args.dns_systemd_sandbox, args.dns_ifindex_reuse_repro,
             args.dns_tor_binding, args.dns_tor_post_enumerate, args.dns_bind_dynamic, args.dns_roundtrip)
