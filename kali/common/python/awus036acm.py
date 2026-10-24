#!/usr/bin/env python3
"""Read-only discovery of AWUS036ACM-compatible USB hardware through sysfs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any


USB_ID = "0e8d:7612"
EXPECTED_DRIVER = "mt76x2u"
RESERVED_INTERFACE = "ctrl0"
EXIT_CODES = {"ready": 0, "missing": 2, "not_ready": 3, "multiple": 4, "unavailable": 5}
MESSAGES = {
    "ready": "A matching USB adapter is bound to mt76x2u and has a wireless interface.",
    "missing": "No USB adapter with ID 0e8d:7612 found.",
    "not_ready": "A matching USB adapter is present, but its readiness could not be confirmed.",
    "multiple": "Multiple matching USB adapters found. None will be selected automatically.",
    "unavailable": "USB device information could not be read completely.",
}
ISSUES = {
    "unbound": "No driver is bound to the adapter.",
    "unexpected_driver": "The adapter is not bound exclusively to mt76x2u.",
    "no_wireless_interface": "No associated wireless interface found.",
    "reserved_control_interface": "The associated interface ctrl0 is reserved for the control network.",
    "read_error": "Device information could not be read completely.",
}


def _under(path: Path, parent: Path) -> bool:
    return path == parent or parent in path.parents


def _wireless(path: Path) -> bool:
    return (path / "wireless").is_dir() or (path / "phy80211").exists()


def _adapter(device: Path, bus: Path, sysfs_root: Path) -> dict[str, Any]:
    result: dict[str, Any] = {
        "usb_device": device.name,
        "usb_id": USB_ID,
        "drivers": [],
        "interfaces": [],
        "issues": [],
        "status": "not_ready",
    }
    errors: list[str] = []
    drivers: set[str] = set()
    interfaces: set[str] = set()
    try:
        physical = device.resolve(strict=True)
        # USB interface directories are children of the physical USB device and
        # also appear as aliases in /sys/bus/usb/devices. Never follow unrelated
        # aliases when associating a network interface with this device.
        candidates = [entry for entry in physical.iterdir() if entry.name.startswith(device.name + ":")]
        candidates += [entry for entry in bus.iterdir() if entry.name.startswith(device.name + ":")]
        usb_interfaces: set[Path] = set()
        for candidate in candidates:
            resolved = candidate.resolve(strict=True)
            if _under(resolved, physical) and resolved.is_dir():
                usb_interfaces.add(resolved)
        for interface in usb_interfaces:
            driver = interface / "driver"
            if driver.is_symlink():
                drivers.add(driver.resolve(strict=True).name)
            net = interface / "net"
            if net.is_dir():
                for item in net.iterdir():
                    if _wireless(item):
                        interfaces.add(item.name)
        # Class links also cover drivers that place their net device deeper in
        # the physical USB tree. The device link, not a wlan* name, identifies it.
        class_net = sysfs_root / "class" / "net"
        if class_net.is_dir():
            for item in class_net.iterdir():
                device_link = item / "device"
                if not device_link.exists() or not _wireless(item):
                    continue
                if _under(device_link.resolve(strict=True), physical):
                    interfaces.add(item.name)
    except OSError as exc:
        errors.append(f"{type(exc).__name__}: {exc}")

    result["drivers"] = sorted(drivers)
    result["interfaces"] = sorted(interfaces)
    issues: list[str] = result["issues"]
    if not drivers:
        issues.append("unbound")
    elif drivers != {EXPECTED_DRIVER}:
        issues.append("unexpected_driver")
    if not interfaces:
        issues.append("no_wireless_interface")
    if RESERVED_INTERFACE in interfaces:
        issues.append("reserved_control_interface")
    if errors:
        issues.append("read_error")
        result["errors"] = errors
    if not issues:
        result["status"] = "ready"
    return result


def inspect_adapter(sysfs_root: str | Path = "/sys") -> dict[str, Any]:
    """Return an observation only; never load drivers or change networking.

    sysfs_root can point at an offline fixture tree. A ready observation confirms
    driver binding and interface creation, not association or Internet access.
    The USB ID identifies compatible hardware, not an authenticated ALFA brand.
    """
    root = Path(sysfs_root)
    bus = root / "bus" / "usb" / "devices"
    adapters: list[dict[str, Any]] = []
    errors: list[str] = []
    try:
        entries = sorted(bus.iterdir(), key=lambda item: item.name)
        for device in entries:
            vendor = device / "idVendor"
            product = device / "idProduct"
            if not vendor.exists():
                continue
            try:
                identifier = f"{vendor.read_text(encoding='ascii').strip().lower()}:{product.read_text(encoding='ascii').strip().lower()}"
                if identifier == USB_ID:
                    adapters.append(_adapter(device, bus, root))
            except (OSError, UnicodeError) as exc:
                errors.append(f"{device.name}: {type(exc).__name__}: {exc}")
    except OSError as exc:
        errors.append(f"{type(exc).__name__}: {exc}")

    if errors:
        status = "unavailable"
    elif not adapters:
        status = "missing"
    elif len(adapters) > 1:
        status = "multiple"
    else:
        status = adapters[0]["status"]
    result = {
        "schema_version": 1,
        "component": "awus036acm",
        "status": status,
        "message": MESSAGES[status],
        "adapters": adapters,
    }
    if errors:
        result["errors"] = errors
    return result


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(64, f"{self.prog}: {message}\n")


def main(argv: list[str] | None = None) -> int:
    parser = _ArgumentParser(description="Detect AWUS036ACM hardware without changing devices or networks.")
    parser.add_argument("--json", action="store_true", help="Machine-readable JSON output")
    parser.add_argument("--sysfs-root", type=Path, default=Path("/sys"), help="Alternative sysfs tree for offline checks")
    args = parser.parse_args(argv)
    result = inspect_adapter(args.sysfs_root)
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(result["message"])
        for adapter in result["adapters"]:
            print(f"USB {adapter['usb_device']} ({adapter['usb_id']})")
            print(f"  Driver: {', '.join(adapter['drivers']) or 'none'}")
            print(f"  Wi-Fi: {', '.join(adapter['interfaces']) or 'none'}")
            for issue in adapter["issues"]:
                print(f"  {ISSUES[issue]}")
        for error in result.get("errors", []):
            print(f"  {error}")
    return EXIT_CODES[result["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
