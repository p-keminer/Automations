#!/usr/bin/python3
"""Exclusive OFF holder; normal temperature control belongs to gpio-fan."""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import signal
import socket
import stat
import struct
import sys
import tempfile
import time

UNIT = "automations-fan-off.service"
CONSUMER = "automations-fan-off"
HELPER = "/usr/local/libexec/automations-support/fan-off"
UNIT_TEXT = """[Unit]
Description=Hold the configured Pi4 case fan off
After=systemd-udev-trigger.service
StartLimitIntervalSec=60
StartLimitBurst=3

[Service]
Type=notify
NotifyAccess=main
User=root
Group=root
ExecStart=/usr/local/libexec/automations-support/fan-off hold
ExecStopPost=/usr/local/libexec/automations-support/fan-off restore
Environment=LC_ALL=C
Environment=PATH=/usr/sbin:/usr/bin:/sbin:/bin
RuntimeDirectory=automations-fan-off
RuntimeDirectoryMode=0755
UMask=0022
Restart=on-failure
RestartSec=3
TimeoutStartSec=10
TimeoutStopSec=5

[Install]
WantedBy=multi-user.target
"""


class FanError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise FanError(message)


def cells(path, count=None):
    data = path.read_bytes()
    require(len(data) <= 64 and len(data) % 4 == 0 and (count is None or len(data) == count * 4),
            "Unexpected fan device-tree data; nothing was changed.")
    return struct.unpack(">" + "I" * (len(data) // 4), data)


def trusted_read(path, root=Path("/"), owner=0, limit=8192):
    path, root = Path(path), Path(root)
    require(path.is_relative_to(root), "Unsafe managed file path.")
    for current in (path, *path.parents):
        if current == root:
            break
        info = current.lstat()
        require(not stat.S_ISLNK(info.st_mode) and info.st_uid == owner and not info.st_mode & 0o022,
                "Unsafe managed file ownership or permissions.")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == owner and info.st_nlink == 1,
                "Managed file must be regular and have one link.")
        data = stream.read(limit + 1)
    require(len(data) <= limit, "Managed file exceeds its size limit.")
    return data


@contextmanager
def lock(path, owner=0):
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == owner and info.st_nlink == 1
                and not info.st_mode & 0o077, "Unsafe fan operation lock.")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise FanError("Another fan operation is running; try again when it finishes.") from None
        yield
    finally:
        os.close(fd)


class Hardware:
    """Fixture paths/API are injectable only from tests, never through the CLI."""
    def __init__(self, root=Path("/"), gpio=None):
        self.root = Path(root)
        self.device = self.root / "sys/bus/platform/devices/gpio-fan@0"
        self.driver = self.root / "sys/bus/platform/drivers/gpio-fan"
        self.node = self.device / "of_node"
        self.request = None
        self.gpio = gpio

    def inspect(self, read_temperature=True):
        try:
            model = (self.root / "proc/device-tree/model").read_bytes()
            require(model.startswith(b"Raspberry Pi 4 Model B"), "Only Raspberry Pi 4 Model B with BCM14 case fan is supported.")
            require(self.node.exists(), "Fan overlay is missing. Build a configured fan image and reboot first.")
            require(self.node.joinpath("compatible").read_bytes() == b"gpio-fan\0"
                    and cells(self.node / "gpios", 3)[1:] == (14, 0)
                    and cells(self.node / "gpio-fan,speed-map", 4) == (0, 0, 5000, 1),
                    "Unsupported fan pin, polarity or speed map; nothing was changed.")
            phandle = cells(self.node / "phandle", 1)[0]
            zone = self.root / "sys/firmware/devicetree/base/thermal-zones/cpu-thermal"
            maps = [entry for entry in (zone / "cooling-maps").iterdir()
                    if entry.is_dir() and (entry / "cooling-device").exists()
                    and cells(entry / "cooling-device")[0] == phandle]
            require(len(maps) == 1 and cells(maps[0] / "cooling-device", 3) == (phandle, 1, 1),
                    "Fan must have one supported CPU cooling map.")
            trip_id = cells(maps[0] / "trip", 1)[0]
            trips = [entry for entry in (zone / "trips").iterdir()
                     if entry.is_dir() and (entry / "phandle").exists()
                     and cells(entry / "phandle", 1)[0] == trip_id]
            require(len(trips) == 1 and (trips[0] / "type").read_bytes() == b"active\0",
                    "Fan must refer to one active CPU thermal trip.")
            on = cells(trips[0] / "temperature", 1)[0]
            off = on - cells(trips[0] / "hysteresis", 1)[0]
            require(on % 1000 == off % 1000 == 0 and 20000 <= off < on <= 80000,
                    "Fan thresholds must satisfy 20 <= off < on <= 80 degrees Celsius.")
            zones = [entry for entry in (self.root / "sys/class/thermal").glob("thermal_zone*")
                     if (entry / "type").read_text().strip() == "cpu-thermal"]
            require(len(zones) == 1, "A unique CPU thermal zone is required.")
            self.thermal = zones[0]
            require((self.thermal / "mode").read_text().strip() == "enabled",
                    "CPU thermal protection must remain enabled.")
            critical = [entry for entry in self.thermal.glob("trip_point_*_type")
                        if entry.read_text().strip() == "critical"]
            require(bool(critical), "CPU critical thermal protection is missing.")
            temperature = None
            if read_temperature:
                temperature = int((self.thermal / "temp").read_text())
                require(-40000 <= temperature <= 150000, "CPU temperature is unavailable.")
            if (self.device / "driver").exists():
                require((self.device / "driver").resolve() == self.driver.resolve(), "Unexpected fan driver binding.")
            return {"on_celsius": on // 1000, "off_celsius": off // 1000,
                    "temperature_millidegrees": temperature, "bound": (self.device / "driver").exists()}
        except FanError:
            raise
        except (OSError, ValueError, IndexError):
            raise FanError("Cannot verify the fan overlay and CPU thermal data. Use a configured fan image and reboot first.") from None

    def gpio_info(self, read_temperature=True):
        self.inspect(read_temperature)
        if self.gpio is None:
            try:
                import gpiod
            except ImportError:
                raise FanError("python3-libgpiod version 2 or newer is required.") from None
            self.gpio = gpiod
        require(hasattr(self.gpio, "request_lines") and hasattr(self.gpio, "LineSettings"),
                "python3-libgpiod version 2 or newer is required.")
        matches = {}
        for path in (self.root / "dev").glob("gpiochip*"):
            with self.gpio.Chip(str(path)) as chip:
                info = chip.get_info()
                if info.label == "pinctrl-bcm2711" and info.num_lines == 58:
                    node = self.root / "sys/bus/gpio/devices" / info.name / "of_node/phandle"
                    if node.read_bytes() == (self.node / "gpios").read_bytes()[:4]:
                        matches[path.stat().st_rdev] = path
        require(len(matches) == 1, "Cannot identify one matching BCM2711 GPIO chip.")
        path = next(iter(matches.values()))
        with self.gpio.Chip(str(path)) as chip:
            line = chip.get_line_info(14)
        return path, line

    def kernel_output(self):
        details = self.inspect()
        require(details["bound"], "Kernel fan control is not bound.")
        candidates = [entry for entry in (self.device / "hwmon").glob("hwmon*")
                      if (entry / "name").read_text().strip() == "gpio_fan"]
        require(len(candidates) == 1, "Kernel fan output is unavailable.")
        value = (candidates[0] / "pwm1").read_text().strip()
        require(value in {"0", "255"}, "Unexpected kernel fan output.")
        return value == "255"

    def driver_write(self, action):
        (self.driver / action).write_text(self.device.name)

    def restore(self):
        # Sensor read failures must not prevent handing control back to the kernel.
        self.inspect(read_temperature=False)
        _, line = self.gpio_info(read_temperature=False)
        require(not line.used or line.consumer == self.device.name,
                "GPIO14 has another owner; kernel fan control was not rebound.")
        if not (self.device / "driver").exists():
            self.driver_write("bind")
        require((self.device / "driver").resolve() == self.driver.resolve(), "Kernel fan control could not be restored.")

    def acquire(self):
        path, line = self.gpio_info()
        require(not line.used or line.consumer == self.device.name,
                "GPIO14 is already owned by another consumer; nothing was changed.")
        try:
            if (self.device / "driver").exists():
                self.driver_write("unbind")
            self.request = self.gpio.request_lines(str(path), consumer=CONSUMER,
                config={14: self.gpio.LineSettings(direction=self.gpio.line.Direction.OUTPUT,
                        output_value=self.gpio.line.Value.INACTIVE)})
            require(not self.output(), "GPIO14 did not switch LOW.")
        except BaseException:
            self.close()
            raise

    def output(self):
        require(self.request is not None, "The OFF holder does not own GPIO14.")
        return self.request.get_value(14) == self.gpio.line.Value.ACTIVE

    def close(self):
        if self.request is not None:
            self.request.release()
            self.request = None
        self.restore()


def publish(hardware, path, clock=time.monotonic_ns):
    require(not hardware.output(), "GPIO14 is no longer LOW.")
    data = json.dumps({"pid": os.getpid(), "monotonic_ns": clock(), "output_high": False}).encode() + b"\n"
    fd, name = tempfile.mkstemp(prefix=".state-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o644)
            stream.write(data)
        os.replace(name, path)
    finally:
        Path(name).unlink(missing_ok=True)


def notify_ready():
    address = os.environ.get("NOTIFY_SOCKET")
    require(bool(address), "The OFF holder must be started by systemd.")
    if address.startswith("@"):
        address = "\0" + address[1:]
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as peer:
        peer.connect(address)
        peer.sendall(b"READY=1")


def hold(hardware=None):
    hardware = hardware or Hardware()
    stopped = False
    def stop(*_):
        nonlocal stopped
        stopped = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    path = Path("/run/automations-fan-off/state")
    parent = path.parent.lstat()
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0 and not parent.st_mode & 0o022,
            "Unsafe OFF holder runtime directory.")
    with lock(path.parent / "owner.lock"):
        try:
            hardware.acquire()
            publish(hardware, path)
            notify_ready()
            while not stopped:
                hardware.inspect()
                publish(hardware, path)
                time.sleep(.5)
        finally:
            path.unlink(missing_ok=True)
            hardware.close()


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    try:
        require(os.geteuid() == 0, "Root privileges are required.")
        require(args in (["hold"], ["restore"]), "Internal helper accepts hold or restore only.")
        if args == ["hold"]:
            hold()
        else:
            Hardware().restore()
        return 0
    except (FanError, OSError, ValueError) as error:
        print("Error: " + str(error), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
