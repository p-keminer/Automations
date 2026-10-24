#!/usr/bin/env python3
"""Opt-in native data-path test. Run: sudo unshare -n python3 this-file.py.

Refuses the init network namespace and any namespace containing non-loopback links.
All veths and subprocess network namespaces disappear on exit; no named netns,
host interface, host route, host firewall, real DNS or Internet endpoint is used.
"""
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import time

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("share_fixture", HERE / "test_share_control.py")
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)
share = fixture.share


def command(*args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=8)


def ip(*args):
    return command("/usr/sbin/ip", *args)


def remote(process, *args, check=True):
    return command("/usr/bin/nsenter", "-t", str(process.pid), "-n", "--", *args, check=check)


def main():
    assert os.geteuid() == 0, "Requires root inside a fresh network namespace"
    assert os.readlink("/proc/self/ns/net") != os.readlink("/proc/1/ns/net"), "Refusing init network namespace"
    assert [x["ifname"] for x in json.loads(ip("-j", "link", "show").stdout)] == ["lo"], "Namespace is not empty"
    assert not json.loads(command("/usr/sbin/nft", "-j", "list", "ruleset").stdout).get("nftables", [])[1:], "Namespace firewall is not empty"
    children, sockets = [], []
    try:
        for _ in range(3):
            children.append(subprocess.Popen(["/usr/bin/unshare", "-n", "/usr/bin/sleep", "120"]))
        # Wait for unshare's exec to finish before transferring links.
        for child in children:
            for _ in range(100):
                if os.readlink(f"/proc/{child.pid}/ns/net") != os.readlink("/proc/self/ns/net"):
                    break
                time.sleep(0.01)
            else:
                raise AssertionError("Child network namespace did not start")
        client, selected, alternate = children
        for local, peer, process, local_address, peer_address in (
                ("ctrl0", "client0", client, "10.78.0.1/24", "10.78.0.20/24"),
                ("eth0", "wan0", selected, "192.168.1.2/24", "192.168.1.1/24"),
                ("eth1", "wan1", alternate, "192.168.2.2/24", "192.168.2.1/24")):
            ip("link", "add", local, "type", "veth", "peer", "name", peer)
            ip("link", "set", peer, "netns", str(process.pid))
            ip("address", "add", local_address, "dev", local)
            ip("link", "set", local, "up")
            remote(process, "/usr/sbin/ip", "address", "add", peer_address, "dev", peer)
            remote(process, "/usr/sbin/ip", "link", "set", peer, "up")
            remote(process, "/usr/sbin/ip", "link", "set", "lo", "up")
        ip("link", "set", "lo", "up")
        for process in (selected, alternate):
            remote(process, "/usr/sbin/ip", "address", "add", "203.0.113.8/32", "dev", "lo")
        remote(client, "/usr/sbin/ip", "route", "add", "default", "via", share.ADDRESS)
        ip("route", "add", "default", "via", "192.168.2.1", "dev", "eth1")
        main_before = ip("-j", "-4", "route", "show", "table", "main").stdout
        baseline = fixture.baseline()
        platform = share.Platform()
        platform.nft({"nftables": [{"add": {kind: {key: value for key, value in obj.items() if key != "handle"}}}
                                   for item in baseline["nftables"] for kind, obj in item.items()]})
        platform.add_routes(fixture.SELECTION)
        platform.routes_check(fixture.SELECTION)
        platform.nft(share.nft_add(fixture.SELECTION))
        share.firewall_check(platform.firewall(), fixture.SELECTION)
        for name in ("ctrl0", "eth0"):
            platform.forwarding(name, "1")
        # Linux per-interface forwarding works while the global/all value stays zero.
        assert Path("/proc/sys/net/ipv4/conf/all/forwarding").read_text().strip() == "0"
        route = json.loads(ip("-j", "route", "get", "203.0.113.8", "from", "10.78.0.20", "iif", "ctrl0").stdout)[0]
        assert route["dev"] == "eth0" and str(route["table"]) == str(share.TABLE), route
        assert json.loads(ip("-j", "route", "get", "203.0.113.8").stdout)[0]["dev"] == "eth0"
        remote(client, "/usr/bin/ping", "-c", "1", "-W", "2", "203.0.113.8")
        command("/usr/bin/ping", "-c", "1", "-W", "2", "203.0.113.8")
        print("PASS: both forwarded and Pi-local IPv4 use the selected uplink")

        # Exercise real DNAT/reply translation without querying any real DNS server.
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind((share.ADDRESS, share.DNS_PORT))
        server.settimeout(4)
        sockets.append(server)
        received = []
        def echo():
            try:
                for _ in range(2):
                    data, origin = server.recvfrom(1024)
                    received.append(origin[0])
                    server.sendto(data, origin)
            except TimeoutError:
                pass
        worker = threading.Thread(target=echo)
        worker.start()
        probe = "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2); s.sendto(b'namespace-only',('1.1.1.1',53)); assert s.recvfrom(128)==(b'namespace-only',('1.1.1.1',53))"
        remote(client, "/usr/bin/python3", "-c", probe)
        command("/usr/bin/python3", "-c", probe)
        worker.join()
        assert received == ["10.78.0.20", "192.168.1.2"]
        print("PASS: control-client and Pi-local DNS translate to the helper and replies translate back")

        # Prove IPv6 is blocked even if another actor enables IPv6 forwarding.
        Path("/proc/sys/net/ipv6/conf/all/forwarding").write_text("1\n")
        ip("-6", "address", "add", "2001:db8:78::1/64", "dev", "ctrl0", "nodad")
        ip("-6", "address", "add", "2001:db8:1::2/64", "dev", "eth0", "nodad")
        remote(client, "/usr/sbin/ip", "-6", "address", "add", "2001:db8:78::20/64", "dev", "client0", "nodad")
        remote(selected, "/usr/sbin/ip", "-6", "address", "add", "2001:db8:1::1/64", "dev", "wan0", "nodad")
        remote(client, "/usr/sbin/ip", "-6", "route", "add", "default", "via", "2001:db8:78::1")
        assert remote(client, "/usr/bin/ping", "-6", "-c", "1", "-W", "1", "2001:db8:1::1", check=False).returncode != 0
        print("PASS: IPv6 forwarding from control clients is blocked")

        # Simulate unplugging the chosen uplink, while an alternate default is usable.
        ip("link", "delete", "eth0")
        failed = command(
            "/usr/sbin/ip", "route", "get", "203.0.113.8", "from", "10.78.0.20", "iif", "ctrl0", check=False)
        assert failed.returncode != 0
        assert remote(client, "/usr/bin/ping", "-c", "1", "-W", "1", "203.0.113.8", check=False).returncode != 0
        assert command("/usr/bin/ping", "-c", "1", "-W", "1", "203.0.113.8", check=False).returncode != 0
        print("PASS: unplugged selected uplink blocks Pi and clients instead of falling back")
        platform.nft(share.nft_delete(platform.firewall(), fixture.SELECTION))
        share.firewall_check(platform.firewall())
        platform.remove_routes(fixture.SELECTION)
        platform.routes_check()
        command("/usr/bin/ping", "-c", "1", "-W", "1", "203.0.113.8")
        # The only main-table difference is the connected route removed with unplugged eth0.
        before = [r for r in json.loads(main_before) if r.get("dev") != "eth0"]
        after = json.loads(ip("-j", "-4", "route", "show", "table", "main").stdout)
        assert before == after
        print("PASS: owned cleanup restores Pi alternate routing; SSH and main routes are preserved")
    finally:
        for sock in sockets:
            sock.close()
        for child in children:
            child.terminate()
            child.wait(timeout=4)


if __name__ == "__main__":
    main()
