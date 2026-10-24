"""Real kernel AP-veth loss and cleanup; isolated namespace, no uplink/network traffic."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("share", root / "python/auto_share.py")
share = importlib.util.module_from_spec(spec)
spec.loader.exec_module(share)
assert os.geteuid() == 0, "Run this isolated check as root"
namespace = "share-detached-" + str(os.getpid())
subprocess.run(["ip", "netns", "add", namespace], check=True)
try:
    def ip(*args):
        return subprocess.run(["ip", "-n", namespace, *args], check=True, capture_output=True, text=True).stdout
    for name in ("ctrl0", "eth0"):
        ip("link", "add", name, "type", "dummy")
    ip("link", "add", "autoap0", "type", "veth", "peer", "name", "ap-peer")
    for name, address in (("ctrl0", "10.78.0.1/24"), ("eth0", "192.0.2.2/24"),
                          ("autoap0", "169.254.95.1/30"), ("ap-peer", "169.254.95.2/30")):
        ip("address", "add", address, "dev", name)
        ip("link", "set", name, "up")
    selected = dict(mode="lan", interface="eth0", address="192.0.2.2", network="192.0.2.0/24",
                    gateway="192.0.2.1", dns=["192.0.2.1"], ipv6=None, sources=["ctrl0"],
                    guest=copy.deepcopy(share.GUEST),
                    control6=dict(network="fd12:3456:789a:1::/64", address="fd12:3456:789a:1::1", linklocal="fe80::1234"))
    def command(args, input_text=None, accepted=(0,)):
        assert args[0] == "/usr/sbin/ip"
        value = subprocess.run(["ip", "-n", namespace, *args[1:]], input=input_text, capture_output=True, text=True)
        assert value.returncode in accepted, value.stderr
        return value.stdout
    with tempfile.TemporaryDirectory() as folder:
        platform = share.Platform(Path(folder), command, 0)
        platform.add_routes(selected)
        platform.routes_check(selected)
        ip("link", "delete", "autoap0")
        rules = json.loads(ip("-j", "-4", "rule", "show"))
        detached = next(row for row in rules if row.get("priority") == 17857)
        assert "iif_detached" in detached and detached["iif_detached"] is None, detached
        try:
            platform.routes_check(selected)
        except share.Error:
            pass
        else:
            raise AssertionError("Detached AP rule must not pass live health validation")
        state = dict(selection=selected, ready=False, owned_addresses=[])
        platform.routes_check(selected, state)
        platform.remove_routes(selected, state)
        platform.routes_check()
        print(json.dumps({"passed": True, "kernel_detached_rule": detached,
                          "live_health_rejected": True, "regular_cleanup_succeeded": True,
                          "scope": "isolated namespace; no traffic, firewall or Pi mutation"}, indent=2))
finally:
    subprocess.run(["ip", "netns", "delete", namespace], check=True)
