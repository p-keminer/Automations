#!/usr/bin/python3
"""Real private D-Bus/GLib signal test; fake NM, no host profiles/network touched."""
import importlib.util
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("policy", ROOT / "python/wifi_autoconnect.py")
policy = importlib.util.module_from_spec(spec); spec.loader.exec_module(policy)
import dbus
import dbus.service
from dbus.mainloop.glib import DBusGMainLoop
from gi.repository import GLib
BASE = "/org/freedesktop/NetworkManager/Settings"
FIXTURE = "org.automations.PolicyFixture"


def manager():
    DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    name = dbus.service.BusName(policy.NM, bus)
    profiles = {}
    activations = {}

    class Connection(dbus.service.Object):
        def __init__(self, path, kind, interface, temporary):
            super().__init__(bus, path)
            self.settings = {"connection": {"uuid": str(uuid.uuid4()), "type": kind,
                             "interface-name": interface, "autoconnect": dbus.Boolean(True)},
                             "802-11-wireless": {"mode": "infrastructure"}}
            self.temporary = temporary
            self.delete_on_disable = False
            self.secret = b"TEST-ONLY-NOT-A-REAL-PASSWORD"

        @dbus.service.method(policy.CONNECTION, in_signature="", out_signature="a{sa{sv}}")
        def GetSettings(self):
            return self.settings

        @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="ss", out_signature="v")
        def Get(self, interface, prop):
            assert interface == policy.CONNECTION
            return dbus.Boolean(self.temporary) if prop == "Unsaved" else dbus.UInt32(0)

        @dbus.service.signal(policy.CONNECTION, signature="")
        def Updated(self):
            pass

    class Active(dbus.service.Object):
        def __init__(self, path, connection):
            super().__init__(bus, path)
            self.profile_path = connection
            self.state = 1

        @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="ss", out_signature="v")
        def Get(self, interface, prop):
            assert interface == policy.NM + ".Connection.Active"
            return dbus.UInt32(self.state) if prop == "State" else dbus.ObjectPath(self.profile_path)

        @dbus.service.signal(policy.NM + ".Connection.Active", signature="uu")
        def StateChanged(self, state, reason):
            pass

    class Root(dbus.service.Object):
        @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="ss", out_signature="v")
        def Get(self, interface, prop):
            assert interface == policy.NM and prop == "ActiveConnections"
            return dbus.Array(activations.keys(), signature="o")

        @dbus.service.signal("org.freedesktop.DBus.Properties", signature="sa{sv}as")
        def PropertiesChanged(self, interface, changed, invalidated):
            pass

    class Manager(dbus.service.Object):
        @dbus.service.method(policy.SETTINGS, in_signature="", out_signature="ao")
        def ListConnections(self):
            return list(profiles)

        @dbus.service.signal(policy.SETTINGS, signature="o")
        def NewConnection(self, path):
            pass

        @dbus.service.method(FIXTURE, in_signature="ssb", out_signature="os")
        def Add(self, kind, interface, temporary):
            path = BASE + "/" + str(len(profiles) + 1)
            conn = profiles[path] = Connection(path, kind, interface, temporary)
            self.NewConnection(path)
            return path, str(conn.settings["connection"]["uuid"])

        @dbus.service.method(FIXTURE, in_signature="", out_signature="os")
        def AddActivating(self):
            path = BASE + "/" + str(len(profiles) + 1)
            conn = profiles[path] = Connection(path, "802-11-wireless", "wlan-fixture", False)
            active_path = "/org/freedesktop/NetworkManager/ActiveConnection/" + str(len(profiles))
            activations[active_path] = Active(active_path, path)
            self.NewConnection(path)
            return path, str(conn.settings["connection"]["uuid"])

        @dbus.service.method(FIXTURE, in_signature="ou", out_signature="")
        def FinishActivation(self, path, state):
            active = next(a for a in activations.values() if a.profile_path == path)
            active.state = state
            active.StateChanged(state, 0)

        @dbus.service.method(FIXTURE, in_signature="o", out_signature="")
        def RemoveActivation(self, path):
            key = next(k for k, a in activations.items() if a.profile_path == path)
            activations.pop(key).remove_from_connection()
            root.PropertiesChanged(policy.NM, {"ActiveConnections": dbus.Array(activations.keys(), signature="o")}, [])

        @dbus.service.method(FIXTURE, in_signature="sb", out_signature="")
        def SetBit(self, identifier, value):
            conn = next(c for c in profiles.values() if c.settings["connection"]["uuid"] == identifier)
            conn.settings["connection"]["autoconnect"] = dbus.Boolean(value)
            conn.Updated()
            if conn.delete_on_disable and not value:
                path = next(path for path, c in profiles.items() if c is conn)
                profiles.pop(path)
                conn.remove_from_connection()

        @dbus.service.method(FIXTURE, in_signature="s", out_signature="")
        def RemovalProbe(self, identifier):
            conn = next(c for c in profiles.values() if c.settings["connection"]["uuid"] == identifier)
            conn.temporary = False
            conn.delete_on_disable = True
            conn.Updated()

        @dbus.service.method(FIXTURE, in_signature="", out_signature="s")
        def Snapshot(self):
            return json.dumps({p: {"uuid": str(c.settings["connection"]["uuid"]),
                       "autoconnect": bool(c.settings["connection"]["autoconnect"]),
                       "synthetic_secret_unchanged": c.secret == b"TEST-ONLY-NOT-A-REAL-PASSWORD"} for p, c in profiles.items()})

    root = Root(bus, "/org/freedesktop/NetworkManager")
    obj = Manager(bus, BASE)
    print("READY", flush=True)
    GLib.MainLoop().run()


def daemon(directory):
    DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    control = dbus.Interface(bus.get_object(policy.NM, BASE), FIXTURE)
    policy.serve(policy.Store(directory), lambda identifier: control.SetBit(identifier, False))


def check():
    children = []
    try:
        with tempfile.TemporaryDirectory() as temp:
            bus_process = subprocess.Popen(["dbus-daemon", "--session", "--nofork", "--print-address=1"], stdout=subprocess.PIPE, text=True)
            children.append(bus_process)
            address = bus_process.stdout.readline().strip()
            env = {**os.environ, "DBUS_SYSTEM_BUS_ADDRESS": address}
            fake = subprocess.Popen([sys.executable, __file__, "--manager"], env=env, stdout=subprocess.PIPE, text=True)
            children.append(fake)
            assert select.select([fake.stdout], [], [], 5)[0], "Fixture not ready"
            assert fake.stdout.readline().strip() == "READY"
            os.environ["DBUS_SYSTEM_BUS_ADDRESS"] = address
            bus = dbus.SystemBus(private=True)
            control = dbus.Interface(bus.get_object(policy.NM, BASE), FIXTURE)
            existing, identifier = control.Add("802-11-wireless", "wlan-fixture", False)
            state = Path(temp) / "policy"
            output = open(Path(temp) / "policy.log", "w+")
            worker = subprocess.Popen([sys.executable, __file__, "--policy", str(state)], env=env, stdout=output)
            children.append(worker)

            def expect(path, value):
                end = time.monotonic() + 5
                while time.monotonic() < end:
                    data = json.loads(control.Snapshot())
                    if data[str(path)]["autoconnect"] == value:
                        assert all(row["synthetic_secret_unchanged"] for row in data.values())
                        return
                    time.sleep(.02)
                raise AssertionError("Expected policy state not observed")

            expect(existing, False)  # Initial scan.
            added, other = control.Add("802-11-wireless", "wlan-fixture", False)
            expect(added, False)  # NewConnection signal.
            store = policy.Store(state)
            with store.locked():
                store.set(str(identifier), True)
            control.SetBit(identifier, True)
            time.sleep(.15)
            expect(existing, True)  # Opt-in survives Updated signal.
            control.SetBit(other, True)
            expect(added, False)  # External edit is normalized.
            for kind, interface, temporary in [("802-3-ethernet", "eth-fixture", False),
                                                 ("802-11-wireless", "ctrl0", False),
                                                 ("802-11-wireless", "wlan-fixture", True)]:
                path, _ = control.Add(kind, interface, temporary)
                time.sleep(.15)
                expect(path, True)
            for final in (2, 4, None):
                pending, pending_id = control.AddActivating()
                time.sleep(.2)
                expect(pending, True)  # Password prompt stays untouched.
                if final is None:
                    control.RemoveActivation(pending)
                else:
                    control.FinishActivation(pending, final)
                expect(pending, False)  # Success, failure and cancellation all normalize.
            pending, approved_id = control.AddActivating()
            with store.locked():
                store.set(str(approved_id), True)
            time.sleep(.15)
            expect(pending, True)
            control.FinishActivation(pending, 2)
            time.sleep(.15)
            expect(pending, True)  # Explicit approval also survives delayed enforcement.
            removed, removal_id = control.Add("802-11-wireless", "wlan-fixture", True)
            control.RemovalProbe(removal_id)
            end = time.monotonic() + 5
            while str(removed) in json.loads(control.Snapshot()) and time.monotonic() < end:
                time.sleep(.02)
            assert str(removed) not in json.loads(control.Snapshot())
            time.sleep(.15)
            output.flush(); output.seek(0)
            assert "operation failed" not in output.read(), "Ordinary object removal was reported as an error"
            assert worker.poll() is None
            print(json.dumps({"private_dbus_signals": "passed", "initial_and_new_profiles": "disabled",
                              "explicit_optin": "preserved", "external_edit": "normalized",
                              "control_ethernet_temporary": "untouched", "synthetic_secret": "unchanged",
                              "queued_event_after_removal": "ignored after confirming absence",
                              "activation_prompt": "not modified", "after_success_failure_cancellation": "disabled",
                              "approved_after_activation": "preserved", "host_network_changes": False}))
    finally:
        for child in reversed(children):
            child.terminate()
            child.wait(timeout=5)


if __name__ == "__main__":
    if sys.argv[1:] == ["--manager"]:
        manager()
    elif len(sys.argv) == 3 and sys.argv[1] == "--policy":
        daemon(sys.argv[2])
    else:
        check()
