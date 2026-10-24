#!/usr/bin/python3
"""Opt-in client-WLAN autoconnect policy. Never request or log NM secrets."""
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import tempfile

UUID = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")
STATE = Path("/var/lib/automations-wifi")
NM = "org.freedesktop.NetworkManager"
SETTINGS = NM + ".Settings"
CONNECTION = SETTINGS + ".Connection"


class PolicyError(RuntimeError):
    pass


def trusted(path, directory=False):
    info = path.lstat()
    if (stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid()
            or info.st_mode & 0o022 or (directory and not stat.S_ISDIR(info.st_mode))
            or (not directory and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1))):
        raise PolicyError("Unsafe Wi-Fi policy storage")
    return info


def atomic(path, data, mode=0o600):
    fd, name = tempfile.mkstemp(prefix=".autoconnect-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


class Store:
    def __init__(self, directory=STATE):
        self.directory = Path(directory)
        self.path = self.directory / "autoconnect.json"

    @contextmanager
    def locked(self):
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        parents = (self.directory, *self.directory.parents) if self.directory == STATE else (self.directory,)
        for parent in parents:
            trusted(parent, directory=True)
        fd = os.open(self.directory / "policy.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
                raise PolicyError("Unsafe Wi-Fi policy lock")
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield self
        finally:
            os.close(fd)

    def read(self):
        if not self.path.exists() and not self.path.is_symlink():
            return set()
        trusted(self.path)
        if self.path.stat().st_size > 65536:
            raise PolicyError("Oversized Wi-Fi policy")
        data = json.loads(self.path.read_text(encoding="utf-8"))
        if (not isinstance(data, dict) or set(data) != {"schema_version", "enabled"}
                or data["schema_version"] != 1 or not isinstance(data["enabled"], list)
                or len(data["enabled"]) > 512
                or any(not isinstance(item, str) or not UUID.fullmatch(item) for item in data["enabled"])
                or len(set(data["enabled"])) != len(data["enabled"])):
            raise PolicyError("Invalid Wi-Fi policy")
        return set(data["enabled"])

    def enabled(self, identifier):
        return identifier in self.read()

    def set(self, identifier, enabled):
        if not UUID.fullmatch(identifier):
            raise PolicyError("Invalid profile UUID")
        values = self.read()
        (values.add if enabled else values.discard)(identifier)
        if len(values) > 512:
            raise PolicyError("Too many Wi-Fi approvals")
        atomic(self.path, (json.dumps({"schema_version": 1, "enabled": sorted(values)}, indent=2) + "\n").encode())


def client_profile(settings):
    connection = settings.get("connection", {})
    wifi = settings.get("802-11-wireless", settings.get("wifi", {}))
    return (connection.get("type") in {"802-11-wireless", "wifi"}
            and connection.get("interface-name", "") != "ctrl0"
            and wifi.get("mode", "infrastructure") in {"", "infrastructure"}
            and bool(UUID.fullmatch(str(connection.get("uuid", "")))))


def normalized_keyfile(data, approved):
    """Change only the connection bit; copy all secret-bearing bytes unchanged."""
    lines = data.splitlines(keepends=True)
    section, fields, connection_header, bit_lines = b"", {}, None, []
    for index, line in enumerate(lines):
        value = line.strip()
        if value.startswith(b"[") and value.endswith(b"]"):
            section = value[1:-1]
            if section == b"connection":
                if connection_header is not None:
                    raise PolicyError("Duplicate connection section")
                connection_header = index
        elif b"=" in value and not value.startswith((b"#", b";")):
            key, value = value.split(b"=", 1)
            if section in {b"connection", b"wifi", b"802-11-wireless"} and key in {
                    b"uuid", b"type", b"interface-name", b"mode", b"autoconnect"}:
                if (section, key) in fields:
                    raise PolicyError("Duplicate Wi-Fi metadata")
                fields[section, key] = value
                if section == b"connection" and key == b"autoconnect":
                    bit_lines.append(index)
    identifier = fields.get((b"connection", b"uuid"), b"").decode("ascii", errors="replace")
    settings = {"connection": {key.decode(): value.decode("ascii", errors="replace")
                for (sec, key), value in fields.items() if sec == b"connection"},
                "wifi": {"mode": fields.get((b"wifi", b"mode"), fields.get((b"802-11-wireless", b"mode"), b"infrastructure")).decode("ascii", errors="replace")}}
    if not client_profile(settings) or identifier in approved:
        return data
    if bit_lines:
        index = bit_lines[0]
        if fields[b"connection", b"autoconnect"].lower() in {b"false", b"no", b"0"}:
            return data
        ending = b"\r\n" if lines[index].endswith(b"\r\n") else b"\n"
        lines[index] = b"autoconnect=false" + ending
    else:
        ending = b"\r\n" if lines[connection_header].endswith(b"\r\n") else b"\n"
        if not lines[connection_header].endswith(b"\n"):
            lines[connection_header] += ending
        lines.insert(connection_header + 1, b"autoconnect=false" + ending)
    return b"".join(lines)


def prepare(directories, store):
    """Run before NM loads profiles. Existing active NM is handled via D-Bus."""
    with store.locked():
        approved = store.read()
        count = 0
        for directory in directories:
            if not directory.exists():
                continue
            trusted(directory, directory=True)
            for path in sorted(directory.glob("*.nmconnection")):
                info = trusted(path)
                old = path.read_bytes()
                new = normalized_keyfile(old, approved)
                if new != old:
                    if path.read_bytes() != old:
                        raise PolicyError("Profile changed during preparation")
                    atomic(path, new, stat.S_IMODE(info.st_mode))
                    count += 1
    return count


def reconcile(settings, store, disable):
    """Only disable an unapproved client; never activate or reapply a connection."""
    if not client_profile(settings):
        return False
    identifier = str(settings["connection"]["uuid"])
    with store.locked():
        if not store.enabled(identifier) and settings["connection"].get("autoconnect", True):
            disable(identifier)
            return True
    return False


def activation_pending(bus, path):
    """Never modify a profile while NM is collecting its activation secrets."""
    import dbus
    properties = "org.freedesktop.DBus.Properties"
    active_interface = NM + ".Connection.Active"
    manager = dbus.Interface(bus.get_object(NM, "/org/freedesktop/NetworkManager"), properties)
    for active_path in manager.Get(NM, "ActiveConnections"):
        try:
            active = dbus.Interface(bus.get_object(NM, active_path), properties)
            if int(active.Get(active_interface, "State")) == 1 and str(active.Get(active_interface, "Connection")) == path:
                return True
        except dbus.DBusException as exc:
            if exc.get_dbus_name() != "org.freedesktop.DBus.Error.UnknownObject":
                raise
    return False


def serve(store, updater=None):
    import dbus
    from dbus.mainloop.glib import DBusGMainLoop
    from gi.repository import GLib
    DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    queued = set()
    deferred = set()

    def process(path):
        queued.discard(path)
        if not bus.name_has_owner(NM):
            return False
        try:
            connection = dbus.Interface(bus.get_object(NM, path), CONNECTION)
            properties = dbus.Interface(bus.get_object(NM, path), "org.freedesktop.DBus.Properties")
            if properties.Get(CONNECTION, "Unsaved") or int(properties.Get(CONNECTION, "Flags")) != 0:
                return False  # Do not turn temporary/generated profiles into saved profiles.
            settings = connection.GetSettings()  # NM deliberately excludes secrets.
            if client_profile(settings) and activation_pending(bus, path):
                deferred.add(path)
                return False
            deferred.discard(path)
            def disable(identifier):
                # Native property-only update preserves credentials and live links.
                if updater is not None:  # Internal injection for private-bus tests only.
                    return updater(identifier)
                result = subprocess.run(["/usr/bin/nmcli", "--colors", "no", "connection", "modify", "uuid", identifier,
                                         "connection.autoconnect", "no"], stdin=subprocess.DEVNULL,
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if result.returncode:
                    raise PolicyError("Profile normalization failed")
            if reconcile(settings, store, disable):
                print("Unapproved client profile autoconnect disabled", flush=True)
        except dbus.DBusException as exc:
            # Updated may already be queued when its connection is deleted.
            # Confirm absence instead of mistaking normal object removal for failure.
            try:
                if not bus.name_has_owner(NM):
                    return False
                manager = dbus.Interface(bus.get_object(NM, "/org/freedesktop/NetworkManager/Settings"), SETTINGS)
                if path not in {str(item) for item in manager.ListConnections()}:
                    deferred.discard(path)
                    return False
            except dbus.DBusException:
                pass
            name = exc.get_dbus_name()
            safe = name if re.fullmatch(r"[A-Za-z0-9_.]+", name or "") else "unclassified"
            print("Wi-Fi policy D-Bus operation failed: " + safe, flush=True)
        except Exception as exc:
            print("Wi-Fi policy operation failed: " + type(exc).__name__, flush=True)
        return False

    def queue(path):
        if path not in queued:
            queued.add(path)
            GLib.idle_add(process, path)

    def scan():
        if bus.name_has_owner(NM):
            settings = dbus.Interface(bus.get_object(NM, "/org/freedesktop/NetworkManager/Settings"), SETTINGS)
            for path in settings.ListConnections():
                queue(str(path))

    def retry_deferred(*unused):
        for path in tuple(deferred):
            queue(path)

    def active_properties(interface, changed, invalidated):
        if str(interface) == NM and ("ActiveConnections" in changed or "ActiveConnections" in invalidated):
            retry_deferred()

    bus.add_signal_receiver(retry_deferred, signal_name="StateChanged", dbus_interface=NM + ".Connection.Active", bus_name=NM)
    bus.add_signal_receiver(active_properties, signal_name="PropertiesChanged", dbus_interface="org.freedesktop.DBus.Properties",
                            bus_name=NM, path="/org/freedesktop/NetworkManager")
    bus.add_signal_receiver(lambda path: queue(str(path)), signal_name="NewConnection", dbus_interface=SETTINGS, bus_name=NM)
    bus.add_signal_receiver(lambda path=None: queue(str(path)), signal_name="Updated", dbus_interface=CONNECTION,
                            bus_name=NM, path_keyword="path")
    bus.add_signal_receiver(lambda name, old, new: scan() if str(name) == NM and new else None,
                            signal_name="NameOwnerChanged", dbus_interface="org.freedesktop.DBus", arg0=NM)
    scan()
    notify = os.environ.get("NOTIFY_SOCKET")
    if notify:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            sock.connect("\0" + notify[1:] if notify.startswith("@") else notify)
            sock.sendall(b"READY=1")
    GLib.MainLoop().run()


def main():
    if os.geteuid() != 0:
        raise PolicyError("Root required")
    store = Store()
    if sys.argv[1:] == ["--prepare"]:
        import dbus
        if not dbus.SystemBus().name_has_owner(NM):
            count = prepare([Path("/etc/NetworkManager/system-connections"), Path("/run/NetworkManager/system-connections")], store)
            print("Prepared client WLAN defaults: " + str(count))
    elif not sys.argv[1:]:
        serve(store)
    else:
        raise PolicyError("Unsupported policy operation")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("Wi-Fi policy stopped: " + type(error).__name__, file=sys.stderr)
        raise SystemExit(1)
