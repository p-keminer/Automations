"""Serialized in-place Share refresh. No gate, conntrack flush or Tor restart.

The caller supplies its already validated Share module and holds the common
flock. A private intent record permits exact old/new intermediate states after
process death; unknown objects are never adopted. Kernel nft changes are one
atomic batch. Routing always retains the terminal unreachable defaults.
"""
from __future__ import annotations

import copy
import importlib.util
import json
import re
import stat
import time

share = None  # supplied by the trusted Share loader, never read from user data
STEPS = ["gate", "addresses", "routes", "unit", "firewall", "forwarding"]
FIXED = ("mode", "interface", "control6", "sources", "guest")


def require(condition, message):
    share.require(condition, message)


def privacy_module(p):
    path = p.trusted("usr/local/libexec/automations-support/egress.py")
    spec = importlib.util.spec_from_file_location("_share_refresh_privacy", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def raw_firewall(p):
    return json.loads(p.run(["/usr/sbin/nft", "--json", "list", "ruleset"]))


def private_state(p, module):
    return module.load_state(p.root, p.owner) if module else None


def private_new(old, selection):
    return {**old, "selection": selection} if old else None


def servers(state, intent):
    return share.servers_text(state["selection"], tor=bool(intent["privacy"]))


def view(data, selection, privacy, module):
    require(not any(v.get("name") == share.GATE or v.get("table") == share.GATE
                    for row in data["nftables"] for v in row.values() if isinstance(v, dict)),
            "A sharing activation/cleanup gate remains; refresh refused.")
    if module:
        module.check_objects(data, privacy)
    else:
        require(not any(v.get("table") == "auto_privacy" or v.get("name") == "auto_privacy" or
                        v.get("comment", "").startswith("auto-privacy:")
                        for row in data["nftables"] for v in row.values() if isinstance(v, dict)),
                "An anonymity guard exists without its protected state.")
    admissions = module.extension_rules(privacy) if privacy else []
    clean = {"nftables": [row for row in data["nftables"] if not ("rule" in row and any(
        module.normalize(row["rule"]) == module.normalize(expected) for expected in admissions))]}
    share.firewall_check(clean, selection)
    return clean


def firewall_variant(p, intent, module):
    data = raw_firewall(p)
    for state in (intent["old"], intent["new"]):
        privacy = private_new(intent["privacy"], state["selection"])
        try:
            return state, data, view(data, state["selection"], privacy, module)
        except (share.Error, RuntimeError):
            pass
    raise share.Error("Firewall differs from both verified refresh snapshots.")


def firewall_apply(p, intent, target, module):
    actual, data, clean = firewall_variant(p, intent, module)
    old, new = actual["selection"], target["selection"]
    if old == new:
        return
    old_privacy, new_privacy = (private_new(intent["privacy"], x) for x in (old, new))
    private_changed = bool(old_privacy and module.objects(old_privacy) != module.objects(new_privacy))
    commands = []
    if private_changed:
        for kind, value in module.check_objects(data, old_privacy):
            if kind == "rule" and value["table"] != module.TABLE:
                commands.append(delete_rule(value))
        commands.append({"delete": {"table": {"family": "inet", "name": module.TABLE}}})
    # Keep the actual chains/hooks (and conntrack). Delete only our exact rules,
    # preserving privacy admissions and all core SSH/Guacamole rules.
    owned = {value["comment"] for kind, value in share.nft_objects(old) if kind == "rule"}
    for row in clean["nftables"]:
        value = row.get("rule", {})
        if value.get("comment") in owned:
            commands.append(delete_rule(value))
    objects = share.nft_objects(new)
    commands += [{"add": {kind: value}} for kind, value in objects if kind == "rule" and
                 not (value["table"] == "pi4" and value["chain"] == "input")]
    commands += [{"insert": {"rule": value}} for value in reversed(share.input_rules(new))]
    if private_changed:
        commands += [{"add": {kind: value}} for kind, value in module.objects(new_privacy)
                     if not (kind == "rule" and value["table"] != module.TABLE)]
        commands += [{"insert": {"rule": value}} for value in reversed(module.extension_rules(new_privacy))]
    batch = {"nftables": commands}
    p.run(["/usr/sbin/nft", "--check", "--json", "-f", "-"], json.dumps(batch))
    p.nft(batch)
    view(raw_firewall(p), new, new_privacy, module)


def delete_rule(value):
    require(type(value.get("handle")) is int and value["handle"] > 0, "Missing refresh rule handle.")
    return {"delete": {"rule": {k: value[k] for k in ("family", "table", "chain", "handle")}}}


def route_key(row):
    return (row.get("type", "unicast"), row["dst"], row["metric"])


def routing_view(p, intent):
    result = {}
    for family in (4, 6):
        routes, rules = p.route_state(family)
        plans = [p.route_plan(state["selection"], family) for state in (intent["old"], intent["new"])]
        expected = [p.normalize_route(row, family) for plan, _ in plans for _, row in plan]
        # Native address loss can strip prefsrc; carrier loss marks linkdown.
        expected += [{k: v for k, v in row.items() if k != "prefsrc"} for row in expected
                     if row.get("dev") == intent["old"]["selection"]["interface"]]
        actual = []
        links = p.ip("-j", "address", "show")
        uplinks = [row for row in links if row.get("ifname") == intent["old"]["selection"]["interface"]]
        down = not uplinks or "UP" not in uplinks[0].get("flags", []) or uplinks[0].get("operstate") in ("DOWN", "LOWERLAYERDOWN", "NOTPRESENT")
        for row in routes:
            if down and row.get("dev") == intent["old"]["selection"]["interface"] and row.get("flags") == ["linkdown"]:
                row = {**row, "flags": []}
            normal = p.normalize_route(row, family)
            require(normal in expected, "Foreign reserved route; refresh refused.")
            actual.append(normal)
        require(len(actual) == len({route_key(row) for row in actual}), "Duplicate reserved routes.")
        expected_rules = [p.normalize_rule(row) for _, row in plans[0][1]]
        require(expected_rules == [p.normalize_rule(row) for _, row in plans[1][1]], "Refresh may not change source policy.")
        own = []
        for row in rules:
            normal = p.normalize_rule(row)
            if (normal.get("priority"), normal.get("table")) in ((0, "local"), (32766, "main"), (32767, "default")):
                require(set(normal) == {"priority", "src", "table"} and normal["src"] == "all", "Changed standard routing rule.")
            else:
                require(normal in expected_rules, "Foreign policy rule; refresh refused.")
                own.append(normal)
        require(len(own) == len(expected_rules) and len(own) == len({json.dumps(x, sort_keys=True) for x in own}),
                "Missing or duplicate source policy; refresh refused.")
        terminal = {"type": "unreachable", "dst": "default", "table": share.TABLE, "protocol": "static", "metric": 32760}
        require(terminal in actual, "The terminal no-fallback route is missing.")
        result[family] = actual
    return result


def routes_apply(p, intent, target):
    current = routing_view(p, intent)
    interfaces = p.ip("-j", "address", "show")
    uplink = target["selection"]["interface"]
    upstream = next((row for row in interfaces if row.get("ifname") == uplink), None)
    available = {x.get("local") for x in (upstream or {}).get("addr_info", [])}
    for family in (4, 6):
        planned, _ = p.route_plan(target["selection"], family)
        for command, row in planned:
            if row.get("dev") == uplink and upstream is None:
                continue  # USB removal already removed its kernel routes. Keep the terminal drop.
            if row in current[family]:
                continue
            # Route replace updates the preferred source without flushing the
            # table or touching policy rules/conntrack/main-table routing.
            command = command[:]
            command[3] = "replace"
            if row.get("dev") == uplink and row.get("prefsrc") not in available and "src" in command:
                offset = command.index("src")
                del command[offset:offset + 2]
            p.run(command)
        desired = [row for _, row in planned]
        keys = {route_key(row) for row in desired}
        for row in current[family]:
            if route_key(row) not in keys:
                p.run(["/usr/sbin/ip", "-" + str(family), "route", "del", row["dst"],
                       "table", str(share.TABLE), "proto", "static", "metric", str(row["metric"])])


def expected_v6(state):
    original = state["ipv6_forwarding"]
    return ({**original, "all": "1", share.CTRL: "1", state["selection"]["interface"]: "1"}
            if state["owned_addresses"] or state["selection"]["ipv6"] else original)


def resources(p, intent, replay=False):
    old, new = intent["old"], intent["new"]
    require(p.load() in (old, new), "Sharing state changed outside the refresh.")
    p.validate()
    if not replay:
        require(p.load() == old and p.read(share.UNIT) == share.unit_text(old["selection"]) and
                p.read(share.DNS_SERVERS) == servers(old, intent), "Runtime changed before refresh intent was recorded.")
        p.routes_check(old["selection"], {**old, "ready": False})
    routing_view(p, intent)
    require(p.read(share.UNIT) in (share.unit_text(old["selection"]), share.unit_text(new["selection"])),
            "Changed resolver unit; refresh refused.")
    require(p.read(share.DNS_SERVERS) in (servers(old, intent), servers(new, intent)) and
            stat.S_IMODE(p.path(share.DNS_SERVERS).stat().st_mode) == 0o644, "Changed resolver server file.")
    configured = next(state for state in (old, new) if p.read(share.UNIT) == share.unit_text(state["selection"]))
    active = p.service_check(configured["selection"], server_config=False)
    # An interrupted capability transition may have written the new unit while
    # the old verified process still runs. Only the two fixed listener sets fit.
    if not active and replay and share.unit_text(old["selection"]) != share.unit_text(new["selection"]):
        values = p.service()
        if values.get("ActiveState") == "active":
            require(any(p.service_check(state["selection"], server_config=False, unit_config=False) for state in (old, new)),
                    "Resolver sockets differ from both known configurations.")
        else:
            require(not values.get("DropInPaths") and values.get("FragmentPath") == "/" + share.UNIT and
                    values.get("MainPID") == "0" and values.get("ActiveState") in ("inactive", "failed"), "Unrecognized resolver service.")
            for protocol in ("-ltnp", "-lunp"):
                require(not any(len(line.split()) >= 4 and line.split()[3].rsplit(":", 1)[-1] == str(share.DNS_PORT)
                                for line in p.run(["/usr/bin/ss", "-H", protocol]).splitlines()), "Foreign resolver sockets.")
    else:
        require(active, "The selected resolver is unavailable or changed.")
    interfaces = {row["ifname"] for row in p.ip("-j", "address", "show")}
    for name in old["forwarding"]:
        if name == old["selection"]["interface"] and name not in interfaces:
            continue
        require(p.forwarding(name) in ("1", old["forwarding"][name]), "IPv4 forwarding was edited externally.")
    current = p.ipv6_settings()
    a, b = expected_v6(old), expected_v6(new)
    required = {"all", "default", share.CTRL} | ({old["selection"]["interface"]} if old["selection"]["interface"] in interfaces else set())
    require(required <= current.keys() and
            all(current[name] in ({a[name], b[name], old["ipv6_forwarding"][name]} | ({"1"} if replay and name != "default" else set()))
                for name in current.keys() & a.keys()), "IPv6 forwarding was edited externally.")
    rows = p.ip("-j", "-6", "address", "show", "dev", share.CTRL)
    addresses = {x["local"] + "/" + str(x["prefixlen"]) for row in rows for x in row.get("addr_info", []) if x.get("family") == "inet6"}
    managed = {new["selection"]["control6"][key] + "/64" for key in ("address", "linklocal")}
    allowed = set(new["owned_addresses"] if replay else old["owned_addresses"])
    require(addresses.intersection(managed) <= allowed, "A control IPv6 address was not created by this operation.")


def apply(p, intent, target, module):
    old, new = intent["old"], intent["new"]
    resources(p, intent, replay=True)
    firewall_variant(p, intent, module)
    require(private_state(p, module) in (intent["privacy"], private_new(intent["privacy"], new["selection"])),
            "Privacy state changed outside the refresh.")
    selection = target["selection"]
    interfaces = {row["ifname"] for row in p.ip("-j", "address", "show")}
    for name in target["forwarding"]:
        if name in interfaces and p.forwarding(name) != "1":
            p.forwarding(name, "1")
    # Prepare addresses before using them as preferred sources. Keep an existing
    # control ULA through external IPv6 loss, including during explicit off.
    rows = p.ip("-j", "-6", "address", "show", "dev", share.CTRL)
    present = {x["local"] + "/" + str(x["prefixlen"]) for row in rows for x in row.get("addr_info", []) if x.get("family") == "inet6"}
    for address in target["owned_addresses"]:
        if address not in present:
            p.run(["/usr/sbin/ip", "-6", "address", "add", address, "dev", share.CTRL])
    if target["owned_addresses"]:
        for attempt in range(30):
            rows = p.ip("-j", "-6", "address", "show", "dev", share.CTRL)
            entries = [x for row in rows for x in row.get("addr_info", []) if x.get("local") in {a.split("/")[0] for a in target["owned_addresses"]}]
            require(not any(x.get("dadfailed") or "dadfailed" in x.get("flags", []) for x in entries), "Control IPv6 address collision.")
            if len(entries) == len(target["owned_addresses"]) and not any(x.get("tentative") or "tentative" in x.get("flags", []) for x in entries):
                break
            require(attempt != 29, "Control IPv6 address detection is pending.")
            time.sleep(0.1)
    current = p.ipv6_settings()
    desired = {name: value for name, value in expected_v6(target).items() if name in current}
    if any(current[name] != value for name, value in desired.items()):
        saved = {**current, **desired}
        if current["all"] != desired["all"]:
            p.write_ipv6_forwarding("all", desired["all"])
        for name, value in saved.items():
            if name != "all" and p.ipv6_settings()[name] != value:
                p.write_ipv6_forwarding(name, value)
    # When DNS is the only change this performs no ip/sysctl work.
    routes_apply(p, intent, target)
    server_text = servers(target, intent)
    before_servers = p.read(share.DNS_SERVERS)
    if before_servers != server_text:
        p.write(share.DNS_SERVERS, server_text, before_servers, mode=0o644)
    unit = share.unit_text(selection)
    before_unit = p.read(share.UNIT)
    # Apply the complete egress policies in one atomic batch. No point with a
    # missing privacy guard or an accepting fallback route is exposed.
    firewall_apply(p, intent, target, module)
    if before_unit != unit:
        p.write(share.UNIT, unit, before_unit)
    capability_changed = share.unit_text(old["selection"]) != share.unit_text(new["selection"])
    if capability_changed:
        # A killed process may have published the unit before daemon-reload.
        # Reload even when its on-disk text is already the target text.
        p.run(["/usr/bin/systemctl", "daemon-reload"])
    if capability_changed and not p.service_check(selection, server_config=False):
        # Only a genuine IPv6 capability transition changes RA/listener setup.
        # Downloads/forwarding and Tor are not restarted or flushed.
        p.run(["/usr/bin/systemctl", "restart", share.SERVICE])
        for attempt in range(20):
            if p.service_check(selection, starting=True, server_config=False):
                break
            require(attempt != 19, "The updated resolver did not become ready.")
            time.sleep(0.1)
    else:
        # Always repeat HUP on journal recovery: a crash after file replacement
        # but before the signal must not leave the old servers in memory.
        pid = p.service().get("MainPID")
        p.run(["/usr/bin/systemctl", "kill", "--kill-whom=main", "--signal=HUP", share.SERVICE])
        require(p.service_check(selection, server_config=False) and p.service().get("MainPID") == pid,
                "Resolver identity/listeners changed during reload.")
    # Publish under the same lock. The intent supports either snapshot after a
    # crash between these two atomic protected writes.
    if p.load() != target:
        p.save(target)
    if module and intent["privacy"]:
        runtime = module.Runtime(share, p)
        value = private_new(intent["privacy"], selection)
        if runtime.state() != value:
            runtime.save(value, runtime.state())
    p.routes_check(selection, {**target, "ready": False})
    view(raw_firewall(p), selection, private_new(intent["privacy"], selection), module)
    require(p.service_check(selection), "Updated resolver verification failed.")


def read_intent(p):
    path = p.path(share.REFRESH_STATE)
    if not path.exists() and not path.is_symlink():
        return None
    require(stat.S_IMODE(path.lstat().st_mode) == 0o600 and
            stat.S_IMODE(path.parent.lstat().st_mode) == 0o700, "Unsafe refresh intent permissions.")
    value = json.loads(p.read(share.REFRESH_STATE))
    require(isinstance(value, dict) and set(value) == {"version", "old", "new", "privacy"} and
            type(value["version"]) is int and value["version"] == 1, "Unrecognized refresh intent.")
    a, b = (p.validate_snapshot(value[key]) for key in ("old", "new"))
    require(a["ready"] and b["ready"] and a["steps"] == b["steps"] == STEPS and
            all(a["selection"].get(key) == b["selection"].get(key) for key in FIXED) and
            a["forwarding"] == b["forwarding"] and a["ipv6_forwarding"] == b["ipv6_forwarding"],
            "Refresh may not change interface, sources or original settings.")
    expected = sorted(set(a["owned_addresses"]) | ({b["selection"]["control6"][key] + "/64" for key in ("address", "linklocal")} if b["selection"]["ipv6"] else set()))
    require(sorted(b["owned_addresses"]) == expected, "Unexpected control IPv6 ownership transition.")
    module = privacy_module(p) if value["privacy"] is not None else None
    if module:
        module.validate_state(value["privacy"])
        require(value["privacy"]["mode"] == "tor" and value["privacy"]["selection"] == a["selection"],
                "Refresh intent has a different privacy selection.")
    return value, module


def resume(p):
    value = read_intent(p)
    if not value:
        return
    intent, module = value
    apply(p, intent, intent["new"], module)
    p.path(share.REFRESH_STATE).unlink()
    try:
        healthy = p.healthy(intent["new"])
    except (RuntimeError, OSError, ValueError, KeyError, TypeError):
        healthy = False
    p.watch_publish(intent["new"], "active" if healthy else "degraded", "refreshed" if healthy else "unavailable",
                    [key for key in ("address", "network", "gateway", "dns", "ipv6")
                     if intent["old"]["selection"][key] != intent["new"]["selection"][key]])


def refresh(p, old, selection):
    require(old["ready"] and old["steps"] == STEPS, "Sharing activation is incomplete.")
    share.validate_selection(selection)
    require(all(old["selection"].get(key) == selection.get(key) for key in FIXED), "Refresh cannot select another uplink/source.")
    new = copy.deepcopy(old)
    new["selection"] = copy.deepcopy(selection)
    if selection["ipv6"]:
        new["owned_addresses"] = sorted({selection["control6"][key] + "/64" for key in ("address", "linklocal")})
    p.validate_snapshot(new)
    path = p.path("run/automations-anonymity/state.json")
    module = privacy_module(p) if path.exists() or path.is_symlink() else None
    privacy = private_state(p, module)
    require(not privacy or privacy["mode"] == "tor" and privacy["selection"] == old["selection"],
            "Privacy selects another uplink.")
    if privacy and privacy["phase"] == "starting":
        raise share.Busy("Privacy activation is still in progress.")
    intent = {"version": 1, "old": old, "new": new, "privacy": privacy}
    resources(p, intent)
    view(raw_firewall(p), old["selection"], privacy, module)
    current = p.with_sources(p.select(selection["mode"], selection["interface"]), selection.get("sources"))
    require(current == selection, "Uplink data changed during inspection; defer refresh.")
    p.write(share.REFRESH_STATE, json.dumps(intent, sort_keys=True) + "\n")
    try:
        apply(p, intent, new, module)
    except BaseException:
        # DNS-only failures can be rolled back without changing routing or
        # connections. A failed rollback retains the intent for the next lock.
        if all(old["selection"][key] == selection[key] for key in ("address", "network", "gateway", "ipv6")):
            try:
                apply(p, intent, old, module)
                p.path(share.REFRESH_STATE).unlink()
            except BaseException:
                pass
        raise
    p.path(share.REFRESH_STATE).unlink()
