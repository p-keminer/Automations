#!/usr/bin/python3
"""Wi-Fi control for explicitly selected PCI/USB radios on a configured Kali host."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
from importlib.machinery import SourceFileLoader
import importlib.util
import os
from pathlib import Path
import re
import stat
import sys
from typing import NamedTuple


def _fixed_peer(filename, installed, module_name):
    """Source siblings or a fixed, trusted installed path; never search sys.path."""
    sibling = Path(__file__).with_name(filename)
    if Path(__file__).parent.name == "python" and not sibling.is_file():
        sibling = Path(__file__).resolve().parents[2] / "common/python" / filename
    if Path(__file__).parent.name == "python" and sibling.is_file():
        path = sibling
    else:
        path = Path(installed)
        for entry in (path, *path.parents):
            info = entry.lstat()
            if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError("Unsafe installed host Wi-Fi helper.")
    spec = importlib.util.spec_from_loader(module_name, SourceFileLoader(module_name, str(path)))
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


_wifi = _fixed_peer("auto_wifi.py", "/usr/local/libexec/automations/wifi", "_host_wifi_base")
Error = _wifi.Error
require = _wifi.require
SYSFS = _wifi.SYSFS


class NotAvailable(Error):
    """No eligible physical Wi-Fi interface is available."""


class HostAdapter(NamedTuple):
    name: str
    index: int
    phy: str
    phy_path: str
    device_path: str
    usb_id: str | None
    bus: str
    hardware_id: str


def load_profile():
    support = _fixed_peer("platform_support.py",
                          "/usr/local/libexec/automations-support/platform_support.py",
                          "_host_wifi_profile")
    return support.load_profile()


def _profile_key(profile):
    require(profile.platform == "kali-host", "This Wi-Fi backend requires a Kali-host profile.")
    protected = profile.protected_interfaces
    require(type(profile.configured) is bool and isinstance(protected, tuple)
            and len(set(protected)) == len(protected)
            and all(isinstance(name, str) and _wifi.NAME.fullmatch(name) for name in protected),
            "Invalid host platform profile.")
    return (profile.platform, profile.configured, tuple(sorted(protected)),
            profile.ssh_service, profile.identity)


def inventory(root=SYSFS):
    """Keep the existing PHY/ifindex checks, adding identified PCI hardware."""
    root = Path(root).resolve()
    result = {}
    for adapter in _wifi.inventory(root).values():
        bus, identifier = "usb", adapter.usb_id
        if identifier is None:
            bus = "pci"
            for ancestor in (Path(adapter.device_path), *Path(adapter.device_path).parents):
                if ancestor == root:
                    break
                subsystem = ancestor / "subsystem"
                if not (subsystem.exists() or subsystem.is_symlink()):
                    continue
                try:
                    if subsystem.resolve(strict=True) != root / "bus/pci":
                        # A different actual bus (e.g. SDIO) is not a PCI radio,
                        # even if its controller has a PCI ancestor.
                        break
                    vendor = (ancestor / "vendor").read_text(encoding="ascii").strip().lower()
                    device = (ancestor / "device").read_text(encoding="ascii").strip().lower()
                except OSError as exc:
                    raise Error("Cannot identify PCI wireless hardware.") from exc
                require(re.fullmatch(r"0x[0-9a-f]{4}", vendor)
                        and re.fullmatch(r"0x[0-9a-f]{4}", device),
                        "Invalid PCI wireless hardware identity.")
                identifier = vendor[2:] + ":" + device[2:]
                break
        if identifier is not None:
            result[adapter.name] = HostAdapter(*adapter, bus, identifier)
    return result


def eligible_adapters(devices, profile):
    _profile_key(profile)
    protected = [devices[name] for name in profile.protected_interfaces if name in devices]
    return {name: adapter for name, adapter in devices.items()
            if name not in profile.protected_interfaces
            and all(adapter.phy_path != item.phy_path and adapter.device_path != item.device_path
                    for item in protected)}


def select_adapter(devices, profile, requested=None, *, mutation=True,
                   chooser=None, stdin=None, stdout=None):
    """A mutation never silently chooses even the sole remaining host radio."""
    candidates = eligible_adapters(devices, profile)
    if requested is not None:
        require(requested in candidates,
                "The selected interface is unavailable, unsupported or protected with its radio.")
        return candidates[requested]
    if not candidates:
        raise NotAvailable("No eligible PCI or USB Wi-Fi interface is available.")
    if not mutation and len(candidates) == 1:
        return next(iter(candidates.values()))
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    require(stdin.isatty() and stdout.isatty(),
            "Select a Wi-Fi interface explicitly with --interface; no host radio is chosen automatically.")
    options = [(name, f"{item.bus.upper()} {item.hardware_id}, {item.phy}")
               for name, item in candidates.items()]
    if chooser is not None:
        chosen = chooser(options, stdin=stdin, stdout=stdout)
        require(chosen in candidates, "The interface selection is no longer eligible.")
        return candidates[chosen]
    print("Select a Wi-Fi interface:", file=stdout)
    for number, (name, description) in enumerate(options, 1):
        print(f"  {number}. {name} - {description}", file=stdout)
    names = list(candidates)
    while True:
        print("Interface number or name (Ctrl+C cancels): ", end="", flush=True, file=stdout)
        answer = stdin.readline(66)
        require(bool(answer), "Interface selection cancelled.")
        require(answer.endswith("\n") and len(answer) <= 65, "Interface selection is too long.")
        answer = answer.strip()
        if answer in candidates:
            return candidates[answer]
        if answer.isascii() and answer.isdecimal() and 1 <= int(answer) <= len(names):
            return candidates[names[int(answer) - 1]]
        print("Choose one of the listed interface names or numbers.", file=stdout)


class HostPlatform(_wifi.Platform):
    """Explicit path/runner/profile injection is test-only, never a CLI option."""
    def __init__(self, *, profile=None, profile_loader=None, owner_uid=0, **kwargs):
        super().__init__(**kwargs)
        self.owner_uid = owner_uid
        self.profile_loader = load_profile if profile_loader is None else profile_loader
        self.host_profile = self.profile_loader() if profile is None else profile
        self.profile_key = _profile_key(self.host_profile)
        self._protected_snapshot = None

    def policy(self):
        raise Error("The Kali host backend does not use the Pi Wi-Fi autoconnect policy.")

    def require_configured(self):
        require(self.host_profile.configured,
                "Host Wi-Fi changes require an explicitly installed, valid Kali-host profile.")
        require(isinstance(self.host_profile.identity, str)
                and re.fullmatch(r"[0-9a-f]{64}", self.host_profile.identity),
                "The installed host profile has no stable identity.")
        require(_profile_key(self.profile_loader()) == self.profile_key,
                "The installed host profile changed; no further mutation is permitted.")

    def devices(self):
        return inventory(self.root)

    @contextmanager
    def locked(self):
        # Same outer lock as Share/Tor/AP/installer, before the Wi-Fi lock.
        # A checked selected radio cannot be adopted by Tor mid-mutation.
        sysroot = Path(self.root)
        require(sysroot.name == 'sys', 'Cannot identify the Wi-Fi system root.')
        root = sysroot.parent
        directory = root / 'run'
        info = directory.lstat()
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
                and info.st_uid == self.owner_uid and not info.st_mode & 0o022,
                'Unsafe host network coordination directory.')
        descriptor = os.open(directory / 'automations-host-share.lock',
                             os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(descriptor)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == self.owner_uid
                    and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600,
                    'Unsafe host network coordination lock.')
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Error('Another host network operation is running.') from None
            with super().locked():
                yield
        finally:
            os.close(descriptor)

    def cli_mutation_guard(self, adapter):
        # AP and Tor own their interface lifecycles. Completion/status never
        # loads these optional command modules; only an explicit mutation does.
        for filename, installed, state, name in (
            ('host_ap.py', '/usr/local/libexec/automations-support/host_ap.py',
             '/run/automations-host-ap/state.json', '_host_wifi_ap_guard'),
            ('host_egress.py', '/usr/local/libexec/automations-support/host_egress.py',
             '/run/automations-host-tor/state.json', '_host_wifi_tor_guard')):
            source = Path(__file__).with_name(filename)
            available = source.is_file() if Path(__file__).parent.name == 'python' else Path(installed).exists()
            if available:
                module = _fixed_peer(filename, installed, name)
                try:
                    module.require_wifi_change_allowed(self, adapter)
                except module.Error as error:
                    raise Error(str(error)) from None
            else:
                require(not Path(state).exists() and not Path(state).is_symlink(),
                        'An owned network mode exists but its interface guard is unavailable.')

    def guard(self, adapter, *, exclusive=False):
        if exclusive:
            self.require_configured()
        devices = self.devices()
        require(eligible_adapters(devices, self.host_profile).get(adapter.name) == adapter,
                "Adapter disappeared, changed or became protected; no replacement device will be modified.")
        protected = tuple((name, devices.get(name)) for name in sorted(self.host_profile.protected_interfaces))
        if self._protected_snapshot is None:
            self._protected_snapshot = protected
        require(protected == self._protected_snapshot, "Protected wireless hardware identity changed.")
        if exclusive:
            for name in self.host_profile.protected_interfaces:
                require((self.root / "class/net" / name).exists(),
                        "A protected interface disappeared; refusing to change another radio.")
            require(sum(item.phy_path == adapter.phy_path for item in devices.values()) == 1,
                    "Another interface shares this radio; refusing to change its mode or connection.")
        for _, item in protected:
            if item is not None:
                _wifi.parse_iw(self.run(["iw", "dev", item.name, "info"]), item)
        _wifi.parse_iw(self.run(["iw", "dev", adapter.name, "info"]), adapter)

    def _compatible_profile(self, profile, adapter):
        if (profile.mode not in {"", "infrastructure"} or profile.interface not in {"", adapter.name}
                or profile.controller or any(profile.match)):
            return False
        if profile.mac:
            # Only an explicitly permanent current address is safe to compare here.
            net = self.root / "class/net" / adapter.name
            try:
                permanent = (net / "addr_assign_type").read_text(encoding="ascii").strip() == "0"
                address = (net / "address").read_text(encoding="ascii").strip().lower()
            except OSError as exc:
                raise Error("Cannot verify the saved profile hardware binding.") from exc
            require(permanent and _wifi.MAC.fullmatch(address) and address == profile.mac,
                    "A matching profile has an unverifiable hardware binding; no profile was changed.")
        for other in self.devices().values():
            if other.name != adapter.name:
                active = self.nm_value("GENERAL.CON-UUID", "device", "show", other.name)
                require(active != profile.uuid,
                        "A matching profile is active on another Wi-Fi interface; no profile was changed.")
        return True

    def _matching_profiles(self, adapter, ssid):
        self.guard(adapter, exclusive=True)
        text = self.run(["nmcli", "--terse", "--escape", "no", "--get-values", "UUID",
                         "connection", "show"])
        identifiers = text.splitlines()
        require(len(text) <= 65536 and len(identifiers) <= 512
                and len(set(identifiers)) == len(identifiers)
                and all(_wifi.UUID.fullmatch(value) for value in identifiers),
                "Cannot read the saved NetworkManager profile list.")
        found, seen = [], False
        for identifier in identifiers:
            target = ("connection", "show", "uuid", identifier)
            if self.nm_value("connection.type", *target) != "802-11-wireless":
                continue
            if self.nm_value("802-11-wireless.ssid", *target) != ssid:
                continue
            if self.nm_value("802-11-wireless.mode", *target) == "ap":
                # A local AP and its independent client legitimately share an
                # SSID. The AP may be a runtime profile; it is never a client
                # candidate and must not require client persistent-storage
                # admission. Recheck its public identity without adopting it.
                require(tuple(self.nm_value(field, *target) for field in (
                    "connection.uuid", "connection.type", "802-11-wireless.ssid", "802-11-wireless.mode"
                )) == (identifier, "802-11-wireless", ssid, "ap"),
                        "The saved AP profile identity changed; no profile was changed.")
                continue
            seen = True
            profile = self.profile(identifier)
            require(profile.ssid == ssid, "The saved profile identity changed.")
            if self._compatible_profile(profile, adapter):
                found.append(profile)
        require(len(found) <= 1, "Multiple saved client profiles match this SSID; no profile was changed.")
        require(found or not seen,
                "Saved profiles for this SSID are incompatible with the selected device; no profile was changed.")
        return found

    def select_profile(self, adapter, ssid):
        matches = self._matching_profiles(adapter, ssid)
        require(matches, "No eligible saved Wi-Fi profile matches this SSID and interface; connect first.")
        return matches[0]

    def profile_autoconnect(self, adapter, ssid, enabled):
        require(type(enabled) is bool, "Invalid autoconnect selection.")
        old = self.select_profile(adapter, ssid)
        require(self.select_profile(adapter, ssid) == old,
                "The selected saved profile changed before the operation; retry.")
        if old.autoconnect == enabled:
            return old
        desired = old._replace(autoconnect=enabled)
        try:
            self.execute(adapter, ["nmcli", "connection", "modify", "uuid", old.uuid,
                                   "connection.autoconnect", "yes" if enabled else "no"])
            require(self.profile(old.uuid) == desired, "Saved profile autoconnect verification failed.")
            return desired
        except (Exception, KeyboardInterrupt) as exc:
            try:
                current = self.profile(old.uuid)
                require(current in (old, desired),
                        "The saved profile changed independently; refusing to overwrite it.")
                if current != old:
                    self.execute(adapter, ["nmcli", "connection", "modify", "uuid", old.uuid,
                                           "connection.autoconnect", "yes" if old.autoconnect else "no"])
                require(self.profile(old.uuid) == old, "Profile autoconnect restoration could not be verified.")
            except (Exception, KeyboardInterrupt) as rollback:
                raise Error(f"Profile operation failed. Previous autoconnect could not be restored: {rollback}") from exc
            raise Error("Profile operation failed. Previous profile autoconnect restored.") from exc

    def connect(self, adapter, ssid, interactive):
        self.guard(adapter, exclusive=True)
        old = self.read_state(adapter)
        require(old.mode == "managed" and old.managed,
                "The adapter must be in managed client mode; use --managed first.")
        require(old.nm_state in _wifi.STABLE_STATES, "NetworkManager is busy; retry when stable.")
        matches = self._matching_profiles(adapter, ssid)
        saved = matches[0] if matches else None

        def apply():
            self.execute(adapter, ["nmcli", "--wait", "30", "--get-values", "BSSID",
                                   "device", "wifi", "list", "--rescan", "yes", "ifname", adapter.name])
            require(self._matching_profiles(adapter, ssid) == matches,
                    "Saved profiles changed before connecting; retry.")
            arguments = ["nmcli", "--colors", "no", "--wait", "90"]
            if interactive:
                arguments.append("--ask")
            if saved is not None:
                arguments += ["connection", "up", "uuid", saved.uuid, "ifname", adapter.name]
            else:
                arguments += ["device", "wifi", "connect", ssid, "ifname", adapter.name]
            self.execute(adapter, arguments, interactive=interactive)
            result = self.await_state(adapter, lambda now: now.mode == "managed" and now.managed
                                      and now.nm_state == 100 and now.connection is not None and now.ssid == ssid)
            if saved is not None:
                require(result.connection == saved.uuid and self.profile(saved.uuid) == saved,
                        "The saved profile changed unexpectedly while connecting.")
            else:
                created = self.profile(result.connection)
                require(created.ssid == ssid and self._compatible_profile(created, adapter),
                        "The new connection does not match the selected interface.")
            if result.autoconnect != old.autoconnect:
                self.nm_set(adapter, "autoconnect", old.autoconnect)
                result = self.read_state(adapter)
            return result

        return self.transaction(old, apply)


class _Parser(argparse.ArgumentParser):
    def __init__(self, *, stdout, stderr, **kwargs):
        self.output, self.errors = stdout, stderr
        super().__init__(**kwargs)

    def _print_message(self, message, file=None):
        if message:
            stream = self.errors if file is sys.stderr else self.output
            stream.write(message)


def build_parser(*, stdout=None, stderr=None):
    parser = _Parser(stdout=sys.stdout if stdout is None else stdout,
                     stderr=sys.stderr if stderr is None else stderr, prog="auto wifi", description=__doc__)
    parser.add_argument("ssid", nargs="?", help="SSID to connect to or select a saved profile")
    parser.add_argument("--interface", metavar="IFACE", help="Select one eligible PCI or USB Wi-Fi interface")
    actions = parser.add_mutually_exclusive_group()
    for flag, help_text in (
        ("off", "Disconnect the selected client or stop its monitor link"),
        ("monitor", "Put the selected radio into monitor mode"),
        ("managed", "Return to client mode, disconnected; retain an existing client connection"),
        ("status", "Show actual Wi-Fi state (default)"),
        ("autoconnect-on", "Enable persistent autoconnect for one saved SSID profile; do not connect"),
        ("autoconnect-off", "Disable persistent autoconnect for one saved SSID profile; do not disconnect"),
    ):
        actions.add_argument("--" + flag, action="store_true", help=help_text)
    return parser


def show(state, *, stdout=None):
    stdout = sys.stdout if stdout is None else stdout
    adapter = state.adapter
    print(f"Interface {adapter.name}: {adapter.bus.upper()} {adapter.hardware_id}, {adapter.phy}, "
          f"mode {state.mode}, admin {'up' if state.up else 'down'}, operational {state.operstate}", file=stdout)
    print(f"  NetworkManager: {'managed' if state.managed else 'unmanaged'}, state {state.nm_state}, "
          f"device autoconnect {'on' if state.autoconnect else 'off'}", file=stdout)
    print("  SSID: " + (_wifi.printable(state.ssid) if state.ssid is not None else "none"), file=stdout)
    print("  Addresses: " + (", ".join(state.addresses) or "none"), file=stdout)
    print("  Active profile: " + (state.connection or "none"), file=stdout)


def main(argv=None, *, profile_loader=None, platform_factory=None, chooser=None,
         stdin=None, stdout=None, stderr=None, geteuid=None):
    stdin, stdout, stderr = (sys.stdin if stdin is None else stdin,
                             sys.stdout if stdout is None else stdout,
                             sys.stderr if stderr is None else stderr)
    parser = build_parser(stdout=stdout, stderr=stderr)
    args = parser.parse_args(argv)
    if (args.autoconnect_on or args.autoconnect_off) and args.ssid is None:
        parser.error("--autoconnect-on and --autoconnect-off require an SSID.")
    if args.ssid is not None and any((args.off, args.monitor, args.managed, args.status)):
        parser.error("SSID cannot be combined with a mode, --off or --status.")
    loader = load_profile if profile_loader is None else profile_loader
    factory = HostPlatform if platform_factory is None else platform_factory
    try:
        mutation = args.ssid is not None or args.off or args.monitor or args.managed
        if args.ssid is not None:
            _wifi.validate_ssid(args.ssid)
        profile = loader()
        _profile_key(profile)
        if mutation:
            require((os.geteuid if geteuid is None else geteuid)() == 0,
                    "Root privileges are required; run sudo auto wifi with the requested operation.")
        platform = factory(profile=profile, profile_loader=loader)
        if not mutation:
            candidates = eligible_adapters(platform.devices(), profile)
            if args.interface:
                item = select_adapter(platform.devices(), profile, args.interface, mutation=False)
                candidates = {item.name: item}
            if not candidates:
                raise NotAvailable("No eligible PCI or USB Wi-Fi interface is available.")
            for adapter in candidates.values():
                show(platform.read_state(adapter), stdout=stdout)
            return 0
        platform.require_configured()
        with platform.locked():
            adapter = select_adapter(platform.devices(), profile, args.interface,
                                     chooser=chooser, stdin=stdin, stdout=stdout)
            guard = getattr(platform, 'cli_mutation_guard', None)
            if callable(guard):
                guard(adapter)
            if args.autoconnect_on or args.autoconnect_off:
                saved = platform.profile_autoconnect(adapter, args.ssid, args.autoconnect_on)
                print(f"Saved profile {saved.uuid} for {_wifi.printable(saved.ssid)}: "
                      f"autoconnect {'on' if saved.autoconnect else 'off'}.", file=stdout)
                print("No explicit connection or device autoconnect change was requested.", file=stdout)
                return 0
            if args.ssid is not None:
                state = platform.connect(adapter, args.ssid, stdin.isatty() and stdout.isatty())
                print(f"Connected to {_wifi.printable(args.ssid)} on {adapter.name}.", file=stdout)
            elif args.off:
                state = platform.off(adapter)
                print("Selected adapter disconnected/stopped. Saved profiles were retained.", file=stdout)
            else:
                state = platform.change_mode(adapter, "monitor" if args.monitor else "managed")
                print(f"Selected adapter is in {state.mode} mode.", file=stdout)
            show(state, stdout=stdout)
        return 0
    except NotAvailable as exc:
        print(f"Not available: {exc}", file=stderr)
        return 3
    except (Error, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=stderr)
        return 1
    except KeyboardInterrupt:
        print("Wi-Fi operation cancelled.", file=stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
