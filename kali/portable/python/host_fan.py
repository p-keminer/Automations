#!/usr/bin/python3
"""Honest fan capability reporting on a Kali host without Pi4 GPIO control.

This backend never writes GPIO, hwmon, firmware or service state. Read-only
hwmon observations are optional and are not evidence of fan-control support.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import stat
import sys

SUPPORT = "/usr/local/libexec/automations-support/platform_support.py"


class Error(RuntimeError):
    pass


class NotAvailable(Error):
    pass


def require(condition, message):
    if not condition:
        raise Error(message)


def load_profile():
    helper = Path(SUPPORT)
    for item in (helper, *helper.parents):
        info = item.lstat()
        require(not stat.S_ISLNK(info.st_mode) and info.st_uid == 0
                and not info.st_mode & 0o022, "Installed platform support is not root-protected.")
    require(helper.is_file() and helper.stat().st_size <= 65536, "Invalid platform support file.")
    content = helper.read_bytes()
    name = "_automations_host_fan_profile_" + hashlib.sha256(content).hexdigest()
    spec = importlib.util.spec_from_file_location(name, helper)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        exec(compile(content, str(helper), "exec"), module.__dict__)
        return module.load_profile()
    finally:
        sys.modules.pop(name, None)


class HostFan:
    def __init__(self, profile, *, sysroot=Path("/sys")):
        require(profile.platform == "kali-host" and type(profile.configured) is bool
                and isinstance(profile.identity, str) and re.fullmatch(r"[0-9a-f]{64}", profile.identity),
                "A valid Kali-host platform profile is required.")
        self.profile, self.sysroot = profile, Path(sysroot)

    def inspect(self):
        sensors, errors = [], []
        root = self.sysroot.resolve(strict=True)
        directory = root / "class/hwmon"
        if directory.is_dir():
            for device in sorted(directory.glob("hwmon*"))[:64]:
                try:
                    resolved = device.resolve(strict=True)
                    require(resolved.is_relative_to(root), "A hwmon path escapes sysfs.")
                    for entry in sorted(device.glob("fan*_input"))[:64]:
                        require(re.fullmatch(r"fan[1-9][0-9]*_input", entry.name), "Invalid hwmon sensor name.")
                        sensor = entry.resolve(strict=True)
                        require(sensor.is_relative_to(root), "A fan sensor path escapes sysfs.")
                        with sensor.open("rb") as stream:
                            raw = stream.read(33)
                        require(len(raw) <= 32 and re.fullmatch(rb"[0-9]+\n?", raw),
                                "Invalid fan RPM observation.")
                        sensors.append({"sensor": device.name + "/" + entry.name,
                                        "rpm": int(raw), "source": "read-only hwmon"})
                except (Error, OSError, ValueError):
                    errors.append(device.name + ": sensor unavailable or not safely readable")
        return {"available": False, "configured": self.profile.configured,
                "control": "unsupported", "requested_mode": None, "live_mode": None,
                "gpio14": "unavailable", "sensors": sensors, "sensor_errors": errors,
                "reason": "No supported Pi4 GPIO14 fan controller exists in the Kali-host backend."}

    def change(self, mode):
        require(mode in ("on", "auto", "off"), "Invalid fan mode.")
        raise NotAvailable("Host fan --" + mode + " is unavailable: no supported controller; nothing was changed.")


def print_status(value):
    print("Host fan control: unavailable (unsupported hardware/backend)")
    print(value["reason"])
    print("Requested/live mode: unknown; GPIO14 output: unavailable; no fan setting was changed.")
    for sensor in value["sensors"]:
        print("Observed " + sensor["sensor"] + ": " + str(sensor["rpm"]) + " RPM (read-only hwmon)")
    for error in value["sensor_errors"]:
        print("Sensor diagnostic: " + error)
    if not value["sensors"]:
        print("Fan RPM sensors: none safely readable (common in virtual machines).")
    print("RPM observations do not establish controllability or a requested AUTO/OFF state.")


def main(argv=None, *, profile_loader=None, backend_factory=HostFan):
    parser = argparse.ArgumentParser(prog="auto fan", description=__doc__)
    actions = parser.add_mutually_exclusive_group()
    for mode in ("auto", "off", "on"):
        actions.add_argument("--" + mode, action="store_true", help="Unavailable on this host; never changes fan hardware")
    actions.add_argument("--status", action="store_true", help="Report capability and optional read-only RPM observations")
    args = parser.parse_args(argv)
    try:
        loader = load_profile if profile_loader is None else profile_loader
        backend = backend_factory(loader())
        for mode in ("auto", "off", "on"):
            if getattr(args, mode):
                backend.change(mode)
        print_status(backend.inspect())
        return 3  # A successful observation must never masquerade as supported fan control.
    except NotAvailable as error:
        print("Unavailable: " + str(error), file=sys.stderr)
        return 3
    except (Error, OSError, ValueError, TypeError):
        error = sys.exc_info()[1]
        print("ERROR: " + (str(error) if isinstance(error, Error) else
                          "Cannot safely inspect host fan capability."), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
