#!/usr/bin/python3
"""Select native fan automation or a persistent exclusive OFF holder."""
from __future__ import annotations

import argparse
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

HELPER = Path("/usr/local/libexec/automations-support/fan-off")
UNIT = "automations-fan-off.service"


class FanError(Exception):
    pass


def load_support():
    # Fixed installed dependency; never search user-controlled Python paths.
    for path in (HELPER, *HELPER.parents):
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise FanError("Unsafe installed fan helper ownership or path.")
    loader = importlib.machinery.SourceFileLoader("automations_fan_support", str(HELPER))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def run_command(arguments):
    try:
        result = subprocess.run(arguments, text=True, capture_output=True, timeout=20,
                                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired):
        raise FanError("A required system command failed or timed out.") from None
    if result.returncode:
        raise FanError("A required fan service command failed; check its journal.")
    return result.stdout.strip()


CPU_SAMPLE_SECONDS = 0.2


def limited_text(path, limit=4096):
    with Path(path).open("r", encoding="ascii") as stream:
        value = stream.read(limit + 1)
    if len(value) > limit:
        raise ValueError("Kernel status entry exceeds the supported size.")
    return value.strip()


def cpu_ticks(path):
    # Only the aggregate row is needed; do not read all per-CPU/IRQ rows.
    with Path(path).open("r", encoding="ascii") as stream:
        line = stream.readline(4097)
    fields = line.split()
    if len(line) > 4096 or len(fields) < 9 or fields[0] != "cpu" or not all(item.isdecimal() for item in fields[1:]):
        raise ValueError("Cannot parse aggregate CPU counters.")
    # Guest time is already included in user/nice: never add fields 9/10 twice.
    return tuple(int(item) for item in fields[1:9])


def cpu_snapshot(root=Path("/"), sleeper=time.sleep, clock=time.monotonic):
    root = Path(root)
    result = {"cpu_usage_percent": None, "cpu_sample_seconds": None,
              "temperature_millidegrees": None, "thermal_mode": "unknown",
              "critical_millidegrees": None}
    try:
        before = cpu_ticks(root / "proc/stat")
        started = clock()
        sleeper(CPU_SAMPLE_SECONDS)
        after = cpu_ticks(root / "proc/stat")
        elapsed = clock() - started
        delta = tuple(new - old for old, new in zip(before, after))
        total = sum(delta)
        # iowait can decrease on Linux. Reject that sample instead of showing a
        # plausible-looking percent from inconsistent counters or hotplug/reset.
        if elapsed > 0 and min(delta) >= 0 and total > 0:
            result["cpu_usage_percent"] = 100.0 * (total - delta[3] - delta[4]) / total
            result["cpu_sample_seconds"] = elapsed
    except (OSError, UnicodeError, ValueError):
        pass
    try:
        zones = [path for path in (root / "sys/class/thermal").glob("thermal_zone*")
                 if limited_text(path / "type", 128) == "cpu-thermal"]
        if len(zones) != 1:
            return result
        zone = zones[0]
        temperature = int(limited_text(zone / "temp", 32))
        if -40000 <= temperature <= 150000:
            result["temperature_millidegrees"] = temperature
        mode = limited_text(zone / "mode", 32)
        if mode in {"enabled", "disabled"}:
            result["thermal_mode"] = mode
        critical = []
        for path in zone.glob("trip_point_*_type"):
            if limited_text(path, 32) == "critical":
                value = int(limited_text(path.with_name(path.name[:-4] + "temp"), 32))
                if 0 < value <= 150000:
                    critical.append(value)
        if critical:
            result["critical_millidegrees"] = min(critical)
    except (OSError, UnicodeError, ValueError):
        pass
    return result

class System:
    def __init__(self, support, root=Path("/"), runner=run_command, clock=time.monotonic_ns, owner=0):
        self.support, self.root, self.runner, self.clock, self.owner = support, Path(root), runner, clock, owner
        self.hardware = support.Hardware(self.root)

    def validate_unit(self):
        path = self.root / "etc/systemd/system" / UNIT
        data = self.support.trusted_read(path, self.root, self.owner)
        if data.decode() != self.support.UNIT_TEXT:
            raise FanError("The installed fan service does not match the supported unit.")
        raw = self.runner(["/usr/bin/systemctl", "show", UNIT,
                           "--property=LoadState,FragmentPath,DropInPaths,UnitFileState,ActiveState,SubState,MainPID"])
        fields = {}
        for line in raw.splitlines():
            if "=" not in line:
                raise FanError("Cannot parse the fan service state.")
            key, value = line.split("=", 1)
            if key in fields:
                raise FanError("Duplicate fan service state field.")
            fields[key] = value
        if (fields.get("LoadState") != "loaded" or fields.get("FragmentPath") != "/etc/systemd/system/" + UNIT
                or fields.get("DropInPaths") != "" or fields.get("UnitFileState") not in {"enabled", "disabled"}
                or fields.get("ActiveState") not in {"active", "inactive", "failed"}
                or not fields.get("MainPID", "").isdigit()):
            raise FanError("Unexpected fan unit, override or service transition; nothing was changed.")
        return fields

    def command(self, action):
        self.validate_unit()
        self.runner(["/usr/bin/systemctl", action, UNIT])

    def restore(self):
        self.runner([str(HELPER), "restore"])

    def observe(self):
        service = self.validate_unit()
        details = self.hardware.inspect()
        _, line = self.hardware.gpio_info()
        result = {**details, "requested": "off" if service["UnitFileState"] == "enabled" else "auto",
                  "service": service["ActiveState"], "live": "unavailable", "output_high": None}
        if details["bound"]:
            if line.used and line.consumer == self.hardware.device.name and service["ActiveState"] != "active":
                result.update(live="auto", output_high=self.hardware.kernel_output())
        elif (service["ActiveState"] == "active" and service["SubState"] == "running"
              and int(service["MainPID"]) > 0 and line.used and line.consumer == self.support.CONSUMER):
            try:
                data = self.support.trusted_read(self.root / "run/automations-fan-off/state", self.root, self.owner, 256)
                state = json.loads(data)
                if (set(state) != {"pid", "monotonic_ns", "output_high"}
                        or type(state["pid"]) is not int or state["pid"] != int(service["MainPID"])
                        or type(state["monotonic_ns"]) is not int
                        or not 0 <= self.clock() - state["monotonic_ns"] <= 3_000_000_000
                        or state["output_high"] is not False):
                    raise ValueError
                result.update(live="off", output_high=False)
            except (OSError, ValueError, self.support.FanError):
                pass
        return result

    def status(self, sampler=cpu_snapshot):
        result = {"requested": "unknown", "service": "unknown", "live": "unavailable",
                  "output_high": None, "on_celsius": None, "off_celsius": None, "faults": []}
        # CPU diagnostics remain useful when a missing overlay or GPIO binding
        # prevents verification of fan ownership. Unknown is never reported OFF.
        cpu = sampler(self.root)
        try:
            service = self.validate_unit()
            result.update(requested="off" if service["UnitFileState"] == "enabled" else "auto",
                          service=service["ActiveState"])
            result.update(self.hardware.inspect(read_temperature=False))
            result.update(self.observe())
            if result["live"] == "unavailable":
                result["faults"].append("Fan ownership or the OFF holder's live sample could not be verified.")
            if result["service"] == "failed":
                result["faults"].append("The OFF holder has failed; inspect journalctl -u automations-fan-off.service.")
        except (FanError, self.support.FanError, OSError, ValueError) as error:
            result["faults"].append(str(error))
        result.update(cpu)
        return result
    def lock(self):
        return self.support.lock(self.root / "run/lock/automations-fan.lock", self.owner)

    def ensure(self, mode):
        observed = self.observe()
        if observed["live"] != mode or observed["requested"] != mode:
            raise FanError("Requested fan mode was not confirmed by the hardware and service state.")
        return observed


def change(system, mode):
    with system.lock():
        before = system.observe()
        if before["live"] == before["requested"] == mode:
            return before
        # Refuse an unknown owner or stale holder state before any service change.
        if before["live"] not in {"auto", "off"}:
            raise FanError("Fan ownership could not be confirmed; nothing was changed.")
        try:
            if mode == "off":
                system.command("enable")
                system.command("start")
            else:
                system.command("stop")
                system.restore()
                system.command("disable")
            return system.ensure(mode)
        except BaseException as original:
            try:
                if before["live"] == "off":
                    system.command("start")
                else:
                    system.command("stop")
                    system.restore()
                system.command("enable" if before["requested"] == "off" else "disable")
                restored = system.observe()
                if restored["live"] != before["live"] or restored["requested"] != before["requested"]:
                    raise FanError("Previous fan state was not restored.")
            except BaseException:
                raise FanError("Fan change failed and rollback is incomplete; inspect auto fan --status and the service journal.") from original
            raise FanError("Fan change failed; the previous fan mode was restored.") from original


def show(status):
    print("Requested mode: " + status["requested"])
    live = status["live"] if status["live"] != "unavailable" else "unknown (fault)"
    print("Live control: " + live)
    print("OFF holder: " + status["service"])
    usage = status.get("cpu_usage_percent")
    if usage is not None:
        print(f"CPU usage: {usage:.1f}% (all CPUs, {status['cpu_sample_seconds']:.2f} s sample)")
    else:
        print("CPU usage: unavailable")
    temperature = status.get("temperature_millidegrees")
    print("CPU temperature: " + (f"{temperature / 1000:.1f} C" if temperature is not None else "unavailable"))
    on, off = status.get("on_celsius"), status.get("off_celsius")
    if on is not None and off is not None:
        print(f"Automatic thresholds: on at {on} C; off below {off} C")
    else:
        print("Automatic thresholds: unavailable")
    if "thermal_mode" in status:
        print("CPU thermal protection: " + status["thermal_mode"])
    critical = status.get("critical_millidegrees")
    if critical is not None:
        print(f"CPU critical trip: {critical / 1000:.1f} C")
    output = "unknown" if status["output_high"] is None else ("HIGH" if status["output_high"] else "LOW")
    print("GPIO14 commanded output: " + output + " (rotation/RPM are not measured)")
    for fault in status.get("faults", []):
        print("Fan diagnostic: " + fault)
    if status["requested"] == "off" and status["live"] == "auto":
        print("Requested OFF is not active; verified kernel automation is running as the fallback.")
    elif status["live"] == "unavailable":
        print("Fan state could not be verified.")
    elif status["requested"] != status["live"]:
        print("Requested and live fan modes differ.")
    if temperature is not None and critical is not None and temperature >= critical:
        print("Cooling hint: CPU temperature has reached its configured critical trip.")
    elif temperature is not None and on is not None and temperature >= on * 1000 and status["live"] == "off":
        print("Cooling hint: OFF overrides the fan-on temperature; use sudo auto fan --auto to resume automatic cooling.")
    elif temperature is not None and off is not None and on is not None and off * 1000 <= temperature < on * 1000 and status["live"] == "auto":
        print("Cooling hint: Temperature is in the hysteresis band; AUTO retains its previous output.")

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, epilog="AUTO uses the image thresholds. OFF persists across boots, but kernel AUTO may run before the holder starts or after it fails. No forced-on mode is provided.")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--auto", action="store_true", help="Restore native temperature-based control")
    modes.add_argument("--off", action="store_true", help="Hold GPIO14 low and enable the OFF holder for subsequent boots")
    modes.add_argument("--status", action="store_true", help="Read actual fan mode, output, CPU usage and temperature (default)")
    args = parser.parse_args(argv)
    support = None
    try:
        if (args.auto or args.off) and os.geteuid() != 0:
            raise FanError("Root privileges are required; use sudo auto fan.")
        support = load_support()
        system = System(support)
        if args.auto or args.off:
            change(system, "auto" if args.auto else "off")
        result = system.status()
        show(result)
        return 0 if result["live"] in {"auto", "off"} and not result["faults"] else 1
    except Exception as error:
        if isinstance(error, (FanError, OSError, ValueError)) or (support is not None and isinstance(error, support.FanError)):
            print("Error: " + str(error), file=sys.stderr)
            return 1
        raise


if __name__ == "__main__":
    raise SystemExit(main())
