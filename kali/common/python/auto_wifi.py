#!/usr/bin/python3
"""Connect or change the mode of one external USB Wi-Fi adapter."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from typing import NamedTuple

SYSFS = Path("/sys")
LOCK = Path("/run/automations-wifi.lock")
CONTROL = "ctrl0"
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}")
MAC = re.compile(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}")
UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
NM_FIELDS = ("GENERAL.DEVICE,GENERAL.TYPE,GENERAL.STATE,GENERAL.NM-MANAGED,"
             "GENERAL.AUTOCONNECT,GENERAL.CON-UUID")
ENV = {"LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}
STABLE_STATES = {10, 20, 30, 100, 120}


class Error(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise Error(message)


def printable(value):
    return json.dumps(str(value), ensure_ascii=True)


class Adapter(NamedTuple):
    name: str
    index: int
    phy: str
    phy_path: str
    device_path: str
    usb_id: str | None


class State(NamedTuple):
    adapter: Adapter
    mode: str
    up: bool
    managed: bool
    autoconnect: bool
    nm_state: int
    connection: str | None
    ssid: str | None
    addresses: tuple[str, ...]
    operstate: str = "unknown"


class Profile(NamedTuple):
    uuid: str
    ssid: str
    interface: str
    mode: str
    mac: str
    controller: str
    match: tuple[str, ...]
    autoconnect: bool
    storage: tuple[str, str]


def inventory(root=SYSFS):
    """Read physical ancestry; neither wlan names nor USB product branding are trusted."""
    root = Path(root)
    network = root / "class/net"
    require(network.is_dir(), "Network interface information is unavailable.")
    adapters = {}
    for entry in sorted(network.iterdir()):
        phy_link = entry / "phy80211"
        if not phy_link.exists() and not phy_link.is_symlink():
            continue
        require(bool(NAME.fullmatch(entry.name)), "An unsupported wireless interface name was found.")
        try:
            phy = phy_link.resolve(strict=True)
            device = (entry / "device").resolve(strict=True)
            index = int((entry / "ifindex").read_text(encoding="ascii").strip())
        except (OSError, ValueError) as exc:
            raise Error(f"Cannot identify wireless interface {printable(entry.name)}.") from exc
        require(re.fullmatch(r"phy[0-9]+", phy.name) and index > 0,
                "Invalid wireless interface identity.")
        require(root.resolve() in phy.parents and root.resolve() in device.parents,
                "Wireless hardware links leave sysfs.")
        usb_id = None
        for ancestor in (device, *device.parents):
            vendor, product = ancestor / "idVendor", ancestor / "idProduct"
            if vendor.is_file() or product.is_file():
                try:
                    identifier = vendor.read_text(encoding="ascii").strip().lower() + ":" + product.read_text(encoding="ascii").strip().lower()
                    subsystem = (ancestor / "subsystem").resolve(strict=True)
                except OSError as exc:
                    raise Error("Incomplete USB hardware information.") from exc
                require(re.fullmatch(r"[0-9a-f]{4}:[0-9a-f]{4}", identifier) and subsystem == root.resolve() / "bus/usb",
                        "Invalid USB hardware identity.")
                usb_id = identifier
                break
            if ancestor == root.resolve():
                break
        adapters[entry.name] = Adapter(entry.name, index, phy.name, str(phy), str(device), usb_id)
    return adapters


def external_adapters(adapters):
    require(CONTROL in adapters, "Protected control interface ctrl0 could not be identified; refusing to choose an adapter.")
    protected = adapters[CONTROL]
    return {name: adapter for name, adapter in adapters.items()
            if name != CONTROL and adapter.usb_id is not None
            and adapter.phy_path != protected.phy_path and adapter.device_path != protected.device_path}


def selection_support():
    helper = Path(__file__).with_name("adapter_selection.py") if Path(__file__).name == "auto_wifi.py" else Path("/usr/local/libexec/automations-support/adapter_selection.py")
    if Path(__file__).name != "auto_wifi.py":
        for entry in (helper, *helper.parents):
            info = entry.lstat()
            require(not stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, "Unsafe adapter selection helper.")
    spec = importlib.util.spec_from_file_location("_wifi_selection", helper)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def policy_support():
    helper = (Path(__file__).resolve().parents[2] / "pi4/python/wifi_autoconnect.py") if Path(__file__).name == "auto_wifi.py" else Path("/usr/local/libexec/automations-support/wifi_autoconnect.py")
    for entry in (helper, *helper.parents):
        info = entry.lstat()
        require(not stat.S_ISLNK(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o022,
                "Unsafe Wi-Fi policy helper.")
    spec = importlib.util.spec_from_file_location("_wifi_policy", helper)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def select_adapter(adapters, requested=None):
    candidates = external_adapters(adapters)
    if requested:
        require(requested in candidates,
                "The requested interface is not an eligible external USB Wi-Fi adapter; ctrl0 and its radio are protected.")
        return candidates[requested]
    require(bool(candidates), "No external USB Wi-Fi interface is available.")
    if len(candidates) == 1:
        return next(iter(candidates.values()))
    try:
        chosen = selection_support().choose([(name, "USB " + adapter.usb_id + ", " + adapter.phy) for name, adapter in candidates.items()],
            "Multiple external Wi-Fi interfaces are available; use --interface: " + ", ".join(candidates))
    except ValueError as exc:
        raise Error(str(exc)) from None
    return candidates[chosen]


def parse_iw(text, adapter):
    lines = text.splitlines()
    require(lines and lines[0].strip() == f"Interface {adapter.name}", "Unexpected iw interface response.")
    fields = {}
    for line in lines[1:]:
        parts = line.strip().split(maxsplit=1)
        if len(parts) == 2 and parts[0] in {"ifindex", "wiphy", "type"}:
            require(parts[0] not in fields, "Duplicate iw identity field.")
            fields[parts[0]] = parts[1]
    require(fields.get("ifindex") == str(adapter.index) and "phy" + fields.get("wiphy", "") == adapter.phy,
            "The wireless interface identity changed.")
    require("type" in fields, "iw did not report an interface mode.")
    return fields["type"]


def parse_nm(text, adapter):
    fields = {}
    for line in text.splitlines():
        key, separator, value = line.partition(":")
        require(separator and key not in fields, "Malformed NetworkManager response.")
        fields[key] = value
    require(fields.get("GENERAL.DEVICE") == adapter.name, "NetworkManager returned another interface.")
    require(fields.get("GENERAL.TYPE") in {"wifi", "generic"}, "NetworkManager does not identify a supported wireless device.")
    for key in ("GENERAL.NM-MANAGED", "GENERAL.AUTOCONNECT"):
        require(fields.get(key) in {"yes", "no"}, "NetworkManager did not report device ownership/autoconnect.")
    match = re.fullmatch(r"([0-9]+)(?: \([^\n]*\))?", fields.get("GENERAL.STATE", ""))
    require(match is not None, "NetworkManager did not report a device state.")
    connection = fields.get("GENERAL.CON-UUID")
    require(connection is not None, "NetworkManager did not report a connection identity.")
    if connection in {"", "--"}:
        connection = None
    else:
        require(UUID.fullmatch(connection), "Invalid active connection UUID.")
    return fields["GENERAL.NM-MANAGED"] == "yes", fields["GENERAL.AUTOCONNECT"] == "yes", int(match[1]), connection


def run_command(arguments, *, interactive=False):
    """The native secret agent owns the TTY; credentials never enter this process."""
    try:
        result = subprocess.run(
            arguments, text=True, capture_output=not interactive, stdin=None if interactive else subprocess.DEVNULL,
            timeout=None if interactive else 105, check=False, env={**os.environ, **ENV},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Error(f"Could not run {arguments[0]}: {type(exc).__name__}.") from exc
    if result.returncode:
        # Do not log arbitrary native output: profile names or agent output can be sensitive.
        raise Error(f"{arguments[0]} failed with exit code {result.returncode}.")
    return result.stdout or ""


class Platform:
    """Path/runner injection exists for tests only, never as runtime CLI options."""
    def __init__(self, root=SYSFS, lock=LOCK, runner=run_command, sleeper=time.sleep, policy=None):
        self.root, self.lock_path, self.run, self.sleep = Path(root), Path(lock), runner, sleeper
        self._policy = policy

    def policy(self):
        if self._policy is None:
            self._policy = policy_support().Store()
        return self._policy

    @contextmanager
    def locked(self):
        fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            metadata = os.fstat(fd)
            require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == os.geteuid()
                    and stat.S_IMODE(metadata.st_mode) == 0o600 and metadata.st_nlink == 1,
                    "Unsafe Wi-Fi operation lock.")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise Error("Another Wi-Fi operation is running.") from exc
            yield
        finally:
            os.close(fd)

    def devices(self):
        return inventory(self.root)

    def guard(self, adapter, *, exclusive=False):
        devices = self.devices()
        eligible = external_adapters(devices)
        require(eligible.get(adapter.name) == adapter, "Adapter disappeared or changed; no replacement device will be modified.")
        # A shared radio must never be changed underneath another interface.
        if exclusive:
            require(sum(item.phy_path == adapter.phy_path for item in devices.values()) == 1,
                    "Another interface shares this external radio; refusing to change its mode or connection.")
        control = devices[CONTROL]
        parse_iw(self.run(["iw", "dev", CONTROL, "info"]), control)
        parse_iw(self.run(["iw", "dev", adapter.name, "info"]), adapter)

    def read_state(self, adapter):
        self.guard(adapter)
        mode = parse_iw(self.run(["iw", "dev", adapter.name, "info"]), adapter)
        nm = self.run(["nmcli", "--terse", "--escape", "no", "--fields", NM_FIELDS, "device", "show", adapter.name])
        managed, autoconnect, state, connection = parse_nm(nm, adapter)
        try:
            links = json.loads(self.run(["ip", "-json", "address", "show", "dev", adapter.name]))
        except ValueError as exc:
            raise Error("Invalid kernel link response.") from exc
        require(isinstance(links, list) and len(links) == 1 and links[0].get("ifname") == adapter.name
                and links[0].get("ifindex") == adapter.index and isinstance(links[0].get("flags"), list),
                "Kernel link identity changed.")
        addresses = []
        for info in links[0].get("addr_info", []):
            try:
                address = ipaddress.ip_address(info["local"])
                prefix = info["prefixlen"]
                require(type(prefix) is int and 0 <= prefix <= address.max_prefixlen,
                        "Invalid interface address prefix.")
                addresses.append(f"{address}/{prefix}")
            except (KeyError, ValueError, TypeError) as exc:
                raise Error("Invalid interface address.") from exc
        ssid = None
        if connection:
            ssid = self.run(["nmcli", "--terse", "--escape", "no", "--get-values", "802-11-wireless.ssid",
                             "connection", "show", "uuid", connection]).removesuffix("\n")
        # IFF_UP is the administrative switch, not evidence of an associated link.
        operational = links[0].get("operstate")
        operstate = operational.lower() if isinstance(operational, str) and operational in {
            "UNKNOWN", "NOTPRESENT", "DOWN", "LOWERLAYERDOWN", "TESTING", "DORMANT", "UP"
        } else "unknown"
        return State(adapter, mode, "UP" in links[0]["flags"], managed, autoconnect, state, connection,
                     ssid, tuple(addresses), operstate)

    def execute(self, adapter, arguments, *, interactive=False):
        self.guard(adapter, exclusive=True)
        return self.run(arguments, interactive=interactive)

    def nm_value(self, field, *target):
        # Each value is read separately: SSIDs may contain colons and backslashes.
        text = self.run(["nmcli", "--terse", "--escape", "no", "--get-values", field, *target])
        value = text.removesuffix("\n")
        require(len(value) <= 4096 and "\n" not in value and "\r" not in value,
                "Malformed NetworkManager profile metadata.")
        return value

    def persistent_location(self, identifier):
        text = self.run(["nmcli", "--terse", "--escape", "no", "--fields", "UUID,DBUS-PATH,FILENAME",
                         "connection", "show"])
        lines = text.splitlines()
        require(len(text) <= 262144 and len(lines) <= 512, "Cannot read saved profile storage metadata.")
        found = []
        for line in lines:
            fields = line.split(":", 2)
            require(len(fields) == 3 and UUID.fullmatch(fields[0]), "Invalid saved profile storage metadata.")
            if fields[0] == identifier:
                found.append(fields[1:])
        require(len(found) == 1, "The saved profile storage identity changed.")
        bus_path, filename = found[0]
        require(re.fullmatch(r"/org/freedesktop/NetworkManager/Settings/[0-9]+", bus_path),
                "Invalid saved profile D-Bus identity.")
        path = Path(filename)
        require(path.parent == Path("/etc/NetworkManager/system-connections")
                and path.name not in {"", ".", ".."},
                "This profile is not stored in persistent NetworkManager system connections; no profile was changed.")
        for prop, expected in (("Unsaved", "b false"), ("Flags", "u 0")):
            value = self.run(["busctl", "--system", "get-property", "org.freedesktop.NetworkManager",
                              bus_path, "org.freedesktop.NetworkManager.Settings.Connection", prop]).strip()
            require(value == expected,
                    "This profile is temporary, generated or has unsaved changes; no profile was changed.")
        return bus_path, filename

    def profile(self, identifier):
        require(UUID.fullmatch(identifier), "Invalid saved profile UUID.")
        target = ("connection", "show", "uuid", identifier)
        require(self.nm_value("connection.uuid", *target) == identifier,
                "The saved profile identity changed.")
        require(self.nm_value("connection.type", *target) == "802-11-wireless",
                "The saved profile is no longer a Wi-Fi profile.")
        ssid = self.nm_value("802-11-wireless.ssid", *target)
        def optional(field):
            value = self.nm_value(field, *target)
            return "" if value == "--" else value
        interface = optional("connection.interface-name")
        mode = optional("802-11-wireless.mode")
        mac = optional("802-11-wireless.mac-address").lower()
        require(not mac or MAC.fullmatch(mac), "Invalid saved profile hardware binding.")
        controller = optional("connection.controller")
        matches = tuple(optional("match." + field) for field in
                        ("interface-name", "path", "driver", "kernel-command-line"))
        bit = self.nm_value("connection.autoconnect", *target)
        require(bit in {"yes", "no"}, "NetworkManager did not report profile autoconnect.")
        return Profile(identifier, ssid, interface, mode, mac, controller, matches, bit == "yes",
                       self.persistent_location(identifier))

    def select_profile(self, adapter, ssid):
        self.guard(adapter, exclusive=True)
        text = self.run(["nmcli", "--terse", "--escape", "no", "--get-values", "UUID",
                         "connection", "show"])
        identifiers = text.splitlines()
        require(len(text) <= 65536 and len(identifiers) <= 512
                and len(set(identifiers)) == len(identifiers)
                and all(UUID.fullmatch(value) for value in identifiers),
                "Cannot read the saved NetworkManager profile list.")
        matches = []
        for identifier in identifiers:
            target = ("connection", "show", "uuid", identifier)
            if self.nm_value("connection.type", *target) != "802-11-wireless":
                continue
            if self.nm_value("802-11-wireless.ssid", *target) != ssid:
                continue
            profile = self.profile(identifier)
            if (profile.ssid != ssid or profile.mode not in {"", "infrastructure"}
                    or profile.interface not in {"", adapter.name} or profile.controller
                    or any(profile.match)):
                continue
            require(not profile.mac,
                    "A matching profile has a MAC binding that cannot be verified safely; no profile was changed.")
            matches.append(profile)
        require(matches, "No eligible saved client Wi-Fi profile matches this SSID and adapter; connect to the WLAN first.")
        require(len(matches) == 1, "Multiple saved client Wi-Fi profiles match this SSID and adapter; no profile was changed.")
        profile = matches[0]
        # A wildcard client profile currently used by the protected radio is excluded too.
        devices = self.devices()
        protected = devices[CONTROL]
        for other in devices.values():
            if other.phy_path == protected.phy_path or other.device_path == protected.device_path:
                active = self.nm_value("GENERAL.CON-UUID", "device", "show", other.name)
                require(active != profile.uuid, "This profile is active on the protected control radio; no profile was changed.")
        return profile

    def profile_autoconnect(self, adapter, ssid, enabled):
        with self.policy().locked():
            return self._profile_autoconnect(adapter, ssid, enabled)

    def _profile_autoconnect(self, adapter, ssid, enabled):
        """Persist the opt-in and one profile bit; never restore device state."""
        old = self.select_profile(adapter, ssid)
        require(self.select_profile(adapter, ssid) == old,
                "The selected saved profile changed before the operation; retry.")
        previous_approval = self.policy().enabled(old.uuid)
        if old.autoconnect == enabled and previous_approval == enabled:
            return old
        desired = old._replace(autoconnect=enabled)
        command = ["nmcli", "connection", "modify", "uuid", old.uuid,
                   "connection.autoconnect", "yes" if enabled else "no"]
        try:
            self.policy().set(old.uuid, enabled)
            if old.autoconnect != enabled:
                self.execute(adapter, command)
            require(self.profile(old.uuid) == desired, "Saved profile autoconnect verification failed.")
            return desired
        except (Exception, KeyboardInterrupt) as exc:
            reason = "Operation interrupted." if isinstance(exc, KeyboardInterrupt) else str(exc)
            try:
                self.policy().set(old.uuid, previous_approval)
                current = self.profile(old.uuid)
                require(current in (old, desired),
                        "The saved profile changed independently; refusing to overwrite it.")
                if current != old:
                    self.execute(adapter, ["nmcli", "connection", "modify", "uuid", old.uuid,
                                          "connection.autoconnect", "yes" if old.autoconnect else "no"])
                require(self.profile(old.uuid) == old, "Profile autoconnect restoration could not be verified.")
            except (Exception, KeyboardInterrupt) as rollback:
                raise Error(f"{reason} Previous profile autoconnect could not be fully restored: {rollback}") from exc
            raise Error(f"{reason} Previous profile autoconnect restored.") from exc

    def nm_set(self, adapter, field, value):
        self.execute(adapter, ["nmcli", "device", "set", adapter.name, field, "yes" if value else "no"])

    def link(self, adapter, up):
        self.execute(adapter, ["ip", "link", "set", "dev", adapter.name, "up" if up else "down"])

    def type(self, adapter, mode):
        self.execute(adapter, ["iw", "dev", adapter.name, "set", "type", mode])

    def disconnect(self, adapter):
        self.execute(adapter, ["nmcli", "--wait", "15", "device", "disconnect", adapter.name])

    def await_state(self, adapter, predicate):
        last = None
        for attempt in range(20):
            last = self.read_state(adapter)
            if predicate(last):
                return last
            if attempt < 19:
                self.sleep(0.1)
        raise Error("The requested adapter state was not reached.")

    def supported(self, adapter, mode):
        self.guard(adapter)
        text = self.run(["iw", "phy", adapter.phy, "info"])
        modes = []
        collecting = False
        for line in text.splitlines():
            if line.strip() == "Supported interface modes:":
                collecting = True
                continue
            if collecting:
                if line.strip().startswith("* "):
                    modes.append(line.strip()[2:])
                elif line.strip():
                    break
        require(mode in modes, f"This adapter/driver does not advertise {mode} mode.")

    def restore(self, old):
        """Restore only the original hardware, never delete or reveal saved profiles."""
        adapter = old.adapter
        self.guard(adapter)
        current = self.read_state(adapter)
        self.nm_set(adapter, "autoconnect", False)
        if current.managed and current.connection and current.connection != old.connection:
            self.disconnect(adapter)
        if current.mode != old.mode:
            if current.managed:
                self.nm_set(adapter, "managed", False)
            self.link(adapter, False)
            self.type(adapter, old.mode)
            self.link(adapter, old.up)
        self.nm_set(adapter, "managed", old.managed)
        if old.managed and old.connection:
            active = self.read_state(adapter)
            if active.connection != old.connection or active.nm_state != 100:
                self.execute(adapter, ["nmcli", "--wait", "90", "connection", "up", "uuid", old.connection, "ifname", adapter.name])
        elif old.managed:
            current = self.read_state(adapter)
            if current.connection:
                self.disconnect(adapter)
        self.nm_set(adapter, "autoconnect", old.autoconnect)
        if self.read_state(adapter).up != old.up:
            self.link(adapter, old.up)
        return self.await_state(adapter, lambda now: now.mode == old.mode and now.up == old.up
                                and now.managed == old.managed and now.autoconnect == old.autoconnect
                                and now.connection == old.connection)

    def transaction(self, old, operation):
        try:
            return operation()
        except (Exception, KeyboardInterrupt) as exc:
            reason = "Operation interrupted" if isinstance(exc, KeyboardInterrupt) else str(exc)
            try:
                self.restore(old)
            except (Exception, KeyboardInterrupt) as rollback:
                raise Error(f"{reason} Previous adapter state could not be fully restored: {rollback}") from exc
            raise Error(f"{reason} Previous adapter state restored.") from exc

    def change_mode(self, adapter, mode):
        self.guard(adapter, exclusive=True)
        old = self.read_state(adapter)
        require(old.mode in {"managed", "monitor"}, "Only client/monitor mode transitions are supported.")
        require(old.nm_state in STABLE_STATES, "NetworkManager is busy; retry when the adapter is stable.")
        if mode == "managed" and old.mode == "managed" and old.managed:
            return old
        if mode == "monitor" and old.mode == "monitor" and not old.managed and old.up:
            return old
        require(mode == "managed" or old.mode == "monitor" or old.managed,
                "An unmanaged client interface may belong to another service; use --managed explicitly first.")
        self.supported(adapter, mode)

        def apply():
            self.nm_set(adapter, "autoconnect", False)
            if old.managed and old.connection:
                self.disconnect(adapter)
            if old.managed:
                self.nm_set(adapter, "managed", False)
            self.link(adapter, False)
            if old.mode != mode:
                self.type(adapter, mode)
            self.link(adapter, True)
            if mode == "managed":
                self.nm_set(adapter, "managed", True)
                self.nm_set(adapter, "autoconnect", False)
            return self.await_state(adapter, lambda now: now.mode == mode and now.up
                                    and now.managed == (mode == "managed") and not now.connection)

        return self.transaction(old, apply)

    def off(self, adapter):
        self.guard(adapter, exclusive=True)
        old = self.read_state(adapter)
        require(old.mode in {"managed", "monitor"}, "Unsupported interface mode.")
        require(old.nm_state in STABLE_STATES, "NetworkManager is busy; retry when the adapter is stable.")
        if old.mode == "monitor":
            if not old.up:
                return old
            return self.transaction(old, lambda: (self.link(adapter, False),
                self.await_state(adapter, lambda now: now.mode == "monitor" and not now.up))[1])
        require(old.managed, "NetworkManager does not own this client interface; use --managed first.")
        if not old.connection and not old.autoconnect:
            return old

        def apply():
            self.nm_set(adapter, "autoconnect", False)
            if old.connection:
                self.disconnect(adapter)
            return self.await_state(adapter, lambda now: now.managed and not now.connection and not now.autoconnect)

        return self.transaction(old, apply)

    def connect(self, adapter, ssid, interactive):
        self.guard(adapter, exclusive=True)
        old = self.read_state(adapter)
        require(old.mode == "managed" and old.managed, "The adapter must be in managed client mode; use --managed first.")
        require(old.nm_state in STABLE_STATES, "NetworkManager is busy; retry when the adapter is stable.")

        def apply():
            self.execute(adapter, ["nmcli", "--wait", "30", "--get-values", "BSSID",
                                   "device", "wifi", "list", "--rescan", "yes", "ifname", adapter.name])
            arguments = ["nmcli", "--colors", "no", "--wait", "90"]
            if interactive:
                arguments.append("--ask")
            arguments += ["device", "wifi", "connect", ssid, "ifname", adapter.name]
            self.execute(adapter, arguments, interactive=interactive)
            result = self.await_state(adapter, lambda now: now.mode == "managed" and now.managed
                                    and now.nm_state == 100 and now.connection is not None and now.ssid == ssid)
            with self.policy().locked():
                if not self.policy().enabled(result.connection):
                    self.execute(adapter, ["nmcli", "connection", "modify", "uuid", result.connection,
                                           "connection.autoconnect", "no"])
            return result

        return self.transaction(old, apply)


def validate_ssid(value):
    require(1 <= len(value.encode("utf-8")) <= 32, "SSID must contain 1 to 32 UTF-8 bytes.")
    require(not any(ord(char) < 32 or ord(char) == 127 for char in value), "SSID cannot contain control characters.")
    require(not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", value),
            "An SSID that looks exactly like a BSSID is ambiguous to nmcli and is unsupported.")


def show(state):
    print(f"Interface {state.adapter.name}: USB {state.adapter.usb_id}, {state.adapter.phy}, mode {state.mode}, "
          f"admin {'up' if state.up else 'down'}, operational {state.operstate}")
    print(f"  NetworkManager: {'managed' if state.managed else 'unmanaged'}, "
          f"state {state.nm_state}, device autoconnect {'on' if state.autoconnect else 'off'}")
    print(f"  SSID: {printable(state.ssid) if state.ssid is not None else 'none'}")
    print(f"  Addresses: {', '.join(state.addresses) or 'none'}")
    print(f"  Active profile: {state.connection or 'none'}")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="auto wifi", description=__doc__)
    parser.add_argument("ssid", nargs="?", help="SSID to connect to or select a saved profile; missing credentials are requested privately by nmcli")
    parser.add_argument("--interface", metavar="IFACE", help="Select one external USB Wi-Fi interface")
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--off", action="store_true", help="Disconnect the selected client adapter, or stop its monitor link")
    actions.add_argument("--monitor", action="store_true", help="Put the selected external adapter into monitor mode")
    actions.add_argument("--managed", action="store_true", help="Return from monitor to client mode, disconnected; leave an existing client connection unchanged")
    actions.add_argument("--status", action="store_true", help="Show actual adapter state (default)")
    actions.add_argument("--autoconnect-on", action="store_true", help="Enable persistent autoconnect for one saved SSID profile; do not explicitly connect")
    actions.add_argument("--autoconnect-off", action="store_true", help="Disable persistent autoconnect for one saved SSID profile; do not disconnect")
    args = parser.parse_args(argv)
    if (args.autoconnect_on or args.autoconnect_off) and args.ssid is None:
        parser.error("--autoconnect-on and --autoconnect-off require an SSID.")
    if args.ssid is not None and any((args.off, args.monitor, args.managed, args.status)):
        parser.error("SSID cannot be combined with a mode, --off or --status.")
    try:
        mutation = args.ssid is not None or args.off or args.monitor or args.managed
        if args.ssid is not None:
            validate_ssid(args.ssid)
        if mutation:
            require(os.geteuid() == 0, "Root privileges are required; run sudo auto wifi with the requested operation.")
        platform = Platform()
        if not mutation:
            candidates = external_adapters(platform.devices())
            ap = None
            if os.geteuid()==0 and Path('/run/automations-hotspot/state.json').exists():
                optional=selection_support().load_peer('auto_hotspot.py','/usr/local/libexec/automations-support/hotspot.py','_wifi_hotspot_status')
                try:
                    ap=optional.load()
                    ap_ready=optional.service_ready(ap)
                except optional.Error as exc:raise Error(str(exc)) from None
            require(bool(candidates) or ap, "No external USB Wi-Fi interface is available.")
            if ap and (not args.interface or args.interface==ap['adapter'][0]):
                print('Interface: '+ap['adapter'][0]+' (additional AP; use auto share ap --status)')
                print('  SSID: '+printable(ap['ssid']))
                print('  AP state: '+('up' if ap_ready else 'starting or degraded')+'; runtime only')
                if args.interface: return 0
            if args.interface:
                candidates = {args.interface: select_adapter(platform.devices(), args.interface)}
            for adapter in candidates.values():
                show(platform.read_state(adapter))
            return 0
        with platform.locked():
            adapter = select_adapter(platform.devices(), args.interface)
            if args.autoconnect_on or args.autoconnect_off:
                profile = platform.profile_autoconnect(adapter, args.ssid, args.autoconnect_on)
                print(f"Saved profile {profile.uuid} for {printable(profile.ssid)}: "
                      f"autoconnect {'on' if profile.autoconnect else 'off'}.")
                print("No explicit connection or device autoconnect change was requested.")
                return 0
            if args.ssid is not None:
                # Without a TTY nmcli may use saved credentials, but this tool never
                # asks for a plaintext secret through redirected stdin.
                interactive = sys.stdin.isatty() and sys.stdout.isatty()
                state = platform.connect(adapter, args.ssid, interactive)
                print(f"Connected to {printable(args.ssid)} on {adapter.name}.")
            elif args.off:
                state = platform.off(adapter)
                print("Selected adapter disconnected/stopped. Saved profiles were retained.")
            else:
                state = platform.change_mode(adapter, "monitor" if args.monitor else "managed")
                print(f"Selected adapter is in {state.mode} mode.")
            show(state)
        return 0
    except (Error, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Wi-Fi operation cancelled.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
