#!/usr/bin/env python3
"""Visibility control for the exact Pi4 builder hostapd configuration."""

from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
import uuid


EXPECTED = {
    "interface": "ctrl0", "driver": "nl80211", "country_code": "DE",
    "ieee80211d": "1", "hw_mode": "g", "channel": "6", "wmm_enabled": "1",
    "ieee80211n": "1", "auth_algs": "1", "wpa": "2",
    "wpa_key_mgmt": "WPA-PSK", "rsn_pairwise": "CCMP",
    "wpa_psk_file": "/etc/hostapd/pi4.psk", "macaddr_acl": "1",
    "accept_mac_file": "/etc/hostapd/pi4.accept", "wps_state": "0",
    "ctrl_interface": "/run/hostapd",
}
NM_CONFIG = "[device-pi4-control]\nmatch-device=interface-name:ctrl0;driver:brcmfmac\nmanaged=0"
LINK_CONFIG = "[Match]\nDriver=brcmfmac\n[Link]\nName=ctrl0"
CLI = ["/usr/sbin/hostapd_cli", "-p", "/run/hostapd", "-i", "ctrl0"]
WORKER = "/usr/local/libexec/automations/ap"
UNIT = "automations-ap-apply.service"
STATE = "run/automations-ap/request.json"
BUS = ["/usr/bin/busctl", "call", "org.freedesktop.systemd1",
       "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager"]
HOSTAPD_UNIT = """[Unit]
Description=Access point and authentication server for Wi-Fi and Ethernet
Documentation=man:hostapd(8)
After=network.target
ConditionFileNotEmpty=/etc/hostapd/hostapd.conf
[Service]
Type=forking
PIDFile=/run/hostapd.pid
Restart=on-failure
RestartSec=2
Environment=DAEMON_CONF=/etc/hostapd/hostapd.conf
EnvironmentFile=-/etc/default/hostapd
ExecStart=/usr/sbin/hostapd -B -P /run/hostapd.pid $DAEMON_OPTS ${DAEMON_CONF}
[Install]
WantedBy=multi-user.target"""
HOSTAPD_DROPIN = """[Unit]
Requires=systemd-networkd.service
After=systemd-networkd.service sys-subsystem-net-devices-ctrl0.device
BindsTo=sys-subsystem-net-devices-ctrl0.device
[Service]
Restart=on-failure
RestartSec=2"""
START_PROPERTIES = ("FragmentPath,DropInPaths,NeedDaemonReload,Type,PIDFile,Environment,"
                    "EnvironmentFiles,ExecStart,ExecStartPre,ExecStartPost,ExecStop,"
                    "ExecStopPost,ExecReload,PassEnvironment,UnsetEnvironment")
EXEC_HOOKS = ("ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost", "ExecReload")


class APError(Exception):
    """An error safe to show without exposing configuration contents."""


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(64, f"{self.prog}: {message}\n")


def run_command(arguments):
    """No shell, user PATH, daemon output or credential values in diagnostics."""
    try:
        result = subprocess.run(arguments, text=True, encoding="utf-8", errors="replace",
                                capture_output=True, timeout=8, check=False,
                                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    except (OSError, subprocess.TimeoutExpired):
        raise APError("A required system command is unavailable or timed out.") from None
    if result.returncode:
        raise APError("A required system command failed; no command output was disclosed.")
    return result.stdout.strip()


def normalized(text):
    return "\n".join(line.strip() for line in text.splitlines()
                     if line.strip() and not line.lstrip().startswith("#"))


def parse_config(data):
    try:
        text = data.decode("utf-8")
    except UnicodeError:
        raise APError("The managed access point configuration is not valid UTF-8.") from None
    values = {}
    for line in normalized(text).splitlines():
        if "=" not in line:
            raise APError("Unrecognized access point configuration; nothing was changed.")
        key, value = line.split("=", 1)
        if key in values:
            raise APError("Duplicate access point setting; nothing was changed.")
        values[key] = value
    if (set(values) != set(EXPECTED) | {"ssid2", "ignore_broadcast_ssid"}
            or any(values[key] != value for key, value in EXPECTED.items())
            or not re.fullmatch(r"(?:[0-9a-fA-F]{2}){1,32}", values.get("ssid2", ""))
            or values.get("ignore_broadcast_ssid") not in {"0", "1"}):
        raise APError("Unrecognized access point configuration; nothing was changed.")
    return int(values["ignore_broadcast_ssid"])


class System:
    """Dependency-injectable for tests; production CLI always uses real system paths."""
    def __init__(self, root=Path("/"), runner=run_command, owner_uid=0,
                 clock=time.monotonic, sleep=time.sleep):
        self.root = Path(root)
        self.runner = runner
        self.owner_uid = owner_uid
        self.config = self.root / "etc/hostapd/hostapd.conf"
        self._metadata = None
        self.clock, self.sleep = clock, sleep

    def trusted_read(self, relative, limit=65536):
        path = self.root / relative
        # Reject replacement links and writable ancestors in managed files.
        current = path
        while current != self.root:
            info = current.lstat()
            if (stat.S_ISLNK(info.st_mode) or info.st_uid != self.owner_uid
                    or info.st_mode & 0o022):
                raise APError("Unsafe managed configuration ownership or path; nothing was changed.")
            current = current.parent
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != self.owner_uid or info.st_mode & 0o022):
                raise APError("Managed configuration must be a regular file without hard links.")
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise APError("Managed configuration exceeds the supported size.")
        return data, info

    def validate(self):
        try:
            os_release = (self.root / "etc/os-release").read_text(encoding="utf-8")
            if not re.search(r'(?m)^ID=(?:kali|"kali")$', os_release):
                raise APError("This command requires the managed Kali Pi4 image.")
            nm, _ = self.trusted_read("etc/NetworkManager/conf.d/90-pi4-control.conf")
            link, _ = self.trusted_read("etc/systemd/network/10-pi4-control.link")
            if normalized(nm.decode()) != NM_CONFIG or normalized(link.decode()) != LINK_CONFIG:
                raise APError("Control interface ownership is unrecognized; nothing was changed.")
            original, self._metadata = self.trusted_read("etc/hostapd/hostapd.conf")
            parse_config(original)
            return original
        except (OSError, UnicodeError):
            raise APError("Cannot read the managed Pi4 configuration; use sudo if access is denied.") from None

    def control(self, *command):
        return self.runner(CLI + list(command)).strip()

    def observe(self):
        interface = self.root / "sys/class/net/ctrl0"
        present = interface.exists()
        details = {"present": present, "addresses": [], "link": "missing",
                   "state": "unavailable", "live_visibility": None, "pid": None}
        if present:
            try:
                records = json.loads(self.runner(["/usr/sbin/ip", "-j", "address", "show", "dev", "ctrl0"]))
                if len(records) != 1 or records[0]["ifname"] != "ctrl0":
                    raise ValueError
                details["link"] = "up" if "UP" in records[0].get("flags", []) else "down"
                details["addresses"] = [f"{item['local']}/{item['prefixlen']}"
                                        for item in records[0].get("addr_info", [])]
            except (ValueError, KeyError, TypeError, AttributeError):
                raise APError("The control interface status could not be parsed.") from None
        service = self.runner(["/usr/bin/systemctl", "show", "hostapd.service",
                               "--property=ActiveState,MainPID"])
        fields = dict(line.split("=", 1) for line in service.splitlines() if "=" in line)
        details["service"] = fields.get("ActiveState", "unknown")
        pid = fields.get("MainPID", "0")
        if details["service"] != "active" or not present or not re.fullmatch(r"[1-9][0-9]*", pid):
            return details
        # Prove that the active daemon uses this one configuration, not another BSS.
        try:
            command = (self.root / "proc" / pid / "cmdline").read_bytes().split(b"\0")
            allowed = {b"", b"-B", b"-P", b"/run/hostapd.pid", b"/var/run/hostapd.pid",
                       b"/etc/hostapd/hostapd.conf"}
            if (not command or Path(os.fsdecode(command[0])).name != "hostapd"
                    or command.count(b"/etc/hostapd/hostapd.conf") != 1
                    or any(arg not in allowed for arg in command[1:])):
                raise APError("The active hostapd process does not use the supported configuration.")
        except OSError:
            raise APError("Cannot verify the active hostapd configuration.") from None
        details["pid"] = pid
        response = self.control("status")
        status = dict(line.split("=", 1) for line in response.splitlines() if "=" in line)
        if status.get("bss[0]") != "ctrl0" or "bss[1]" in status:
            raise APError("The active access point does not match ctrl0.")
        details["state"] = status.get("state", "unknown")
        visibility = self.control("get", "ignore_broadcast_ssid")
        if visibility in {"0", "1"}:
            details["live_visibility"] = int(visibility)
        elif visibility not in {"FAIL", "UNKNOWN COMMAND"}:
            raise APError("The live visibility response could not be interpreted.")
        return details

    @contextmanager
    def lock(self, wait=False):
        path = self.root / "run/lock/automations-ap.lock"
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.owner_uid
                    or info.st_nlink != 1 or info.st_mode & 0o077):
                raise APError("The AP operation lock is unsafe.")
            deadline = self.clock() + (10 if wait else 0)
            while True:
                try:
                    fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if self.clock() >= deadline:
                        raise APError("Another AP operation is running; try again after it finishes.") from None
                    self.sleep(0.1)
            yield
        finally:
            os.close(descriptor)

    def persist(self, data, expected):
        actual, metadata = self.trusted_read("etc/hostapd/hostapd.conf")
        if actual != expected:
            raise APError("The configuration changed during this operation; refusing to overwrite it.")
        descriptor, filename = tempfile.mkstemp(prefix=".auto-ap-", dir=self.config.parent)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                os.fchmod(stream.fileno(), stat.S_IMODE(metadata.st_mode))
                os.fchown(stream.fileno(), metadata.st_uid, metadata.st_gid)
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            latest, latest_info = self.trusted_read("etc/hostapd/hostapd.conf")
            if (latest != expected or (latest_info.st_dev, latest_info.st_ino,
                    latest_info.st_uid, latest_info.st_gid, latest_info.st_mode) !=
                    (metadata.st_dev, metadata.st_ino, metadata.st_uid,
                     metadata.st_gid, metadata.st_mode)):
                raise APError("The configuration changed before replacement; nothing was overwritten.")
            os.replace(filename, self.config)
            directory = os.open(self.config.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(filename):
                os.unlink(filename)


def replacement_for(original, value):
    parse_config(original)
    replacement = re.sub(rb"(?m)^ignore_broadcast_ssid=[01](\r?)$",
                         b"ignore_broadcast_ssid=" + str(value).encode() + rb"\1", original)
    if parse_config(replacement) != value:
        raise APError("Cannot safely replace the visibility setting.")
    return replacement


def read_record(system):
    if not (system.root / STATE).exists() and not (system.root / STATE).is_symlink():
        return None
    try:
        raw, metadata = system.trusted_read(STATE, 131072)
        if metadata.st_mode & 0o077:
            raise APError("The private AP operation record is unsafe.")
        record = json.loads(raw)
        keys = {"schema", "id", "target", "expected", "state", "phase", "original", "pid", "job", "error"}
        if (set(record) != keys or record["schema"] != 1
                or type(record["target"]) is not int or record["target"] not in (0, 1)
                or not re.fullmatch(r"[0-9a-f]{32}", record["id"])
                or not re.fullmatch(r"[0-9a-f]{64}", record["expected"])
                or not re.fullmatch(r"[1-9][0-9]*", record["pid"])
                or type(record["job"]) is not int or not 0 <= record["job"] <= 0xffffffff
                or record["state"] not in {"queued", "running", "applied", "recovered", "failed"}
                or record["phase"] not in {"queued", "prepared", "persisted", "restart", "done"}
                or record["error"] not in {None, "operation-failed", "recovery-failed"}):
            raise ValueError
        if record["original"] is not None:
            original = base64.b64decode(record["original"], validate=True)
            parse_config(original)
            if len(original) > 65536 or hashlib.sha256(original).hexdigest() != record["expected"]:
                raise ValueError
        return record
    except (ValueError, TypeError, KeyError):
        raise APError("The private AP operation record is invalid; nothing was changed.") from None


def write_record(system, record):
    directory = system.root / "run/automations-ap"
    run_info = directory.parent.lstat()
    if (not stat.S_ISDIR(run_info.st_mode) or run_info.st_uid != system.owner_uid
            or run_info.st_mode & 0o022):
        raise APError("The runtime directory is unsafe.")
    directory.mkdir(mode=0o700, exist_ok=True)
    info = directory.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != system.owner_uid or info.st_mode & 0o077):
        raise APError("The private AP operation directory is unsafe.")
    target = system.root / STATE
    previous = system.trusted_read(STATE, 131072)[0] if target.exists() or target.is_symlink() else None
    data = (json.dumps(record, sort_keys=True) + "\n").encode()
    if len(data) > 131072:
        raise APError("The private AP operation record is too large.")
    descriptor, filename = tempfile.mkstemp(prefix=".request-", dir=directory)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        current = system.trusted_read(STATE, 131072)[0] if target.exists() or target.is_symlink() else None
        if current != previous:
            raise APError("The AP operation record changed externally; nothing was overwritten.")
        os.replace(filename, target)
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        if os.path.exists(filename):
            os.unlink(filename)


def unit_fields(system, name, properties):
    text = system.runner(["/usr/bin/systemctl", "show", name, "--all", "--property=" + properties])
    return dict(line.split("=", 1) for line in text.splitlines() if "=" in line)


def current_job(system):
    fields = unit_fields(system, "hostapd.service", "Job")
    if fields.get("Job") == "":
        return 0  # Native systemd 262 prints Job= when no job is queued.
    if not re.fullmatch(r"[0-9]+", fields.get("Job", "")):
        raise APError("Cannot determine the hostapd service job; no recovery restart was attempted.")
    job = int(fields["Job"])
    if job > 0xffffffff:
        raise APError("The hostapd service job identity is out of range.")
    return job


def verify_start_definition(system):
    """Only the exact known unit/drop-in may be used for a future restart."""
    unit, _ = system.trusted_read("usr/lib/systemd/system/hostapd.service")
    dropin, _ = system.trusted_read("etc/systemd/system/hostapd.service.d/pi4.conf")
    defaults, _ = system.trusted_read("etc/default/hostapd")
    try:
        unit_text, dropin_text, defaults_text = (normalized(data.decode()) for data in (unit, dropin, defaults))
    except UnicodeError:
        raise APError("The hostapd start files are not valid UTF-8; no restart was attempted.") from None
    if unit_text != HOSTAPD_UNIT or dropin_text != HOSTAPD_DROPIN:
        raise APError("The hostapd start definition is unrecognized; no restart was attempted.")
    for line in defaults_text.splitlines():
        if line not in {'DAEMON_CONF="/etc/hostapd/hostapd.conf"',
                        "DAEMON_CONF=/etc/hostapd/hostapd.conf",
                        'DAEMON_OPTS=""', "DAEMON_OPTS=", "DAEMON_OPTS=''"}:
            raise APError("The hostapd environment file is unrecognized; no restart was attempted.")
    fields = unit_fields(system, "hostapd.service", START_PROPERTIES)
    required = {
        "FragmentPath": "/usr/lib/systemd/system/hostapd.service",
        "DropInPaths": "/etc/systemd/system/hostapd.service.d/pi4.conf",
        "NeedDaemonReload": "no", "Type": "forking", "PIDFile": "/run/hostapd.pid",
        "Environment": "DAEMON_CONF=/etc/hostapd/hostapd.conf",
        "EnvironmentFiles": "/etc/default/hostapd (ignore_errors=yes)",
        "PassEnvironment": "", "UnsetEnvironment": "",
    }
    if any(fields.get(key) != value for key, value in required.items()):
        raise APError("The loaded hostapd start definition is unrecognized; no restart was attempted.")
    # Native systemd 262 omits empty Exec arrays even with show --all. Query
    # their typed D-Bus values instead of treating a missing field as empty.
    for hook in EXEC_HOOKS:
        output = system.runner(["/usr/bin/busctl", "get-property", "org.freedesktop.systemd1",
                                "/org/freedesktop/systemd1/unit/hostapd_2eservice",
                                "org.freedesktop.systemd1.Service", hook])
        if fields.get(hook, "") or output != "a(sasbttttuii) 0":
            raise APError("The loaded hostapd hooks are unrecognized; no restart was attempted.")
    start = fields.get("ExecStart", "")
    prefix = ("{ path=/usr/sbin/hostapd ; argv[]=/usr/sbin/hostapd -B -P /run/hostapd.pid "
              "$DAEMON_OPTS ${DAEMON_CONF} ; ignore_errors=no ; ")
    if (not start.startswith(prefix) or not start.endswith(" }")
            or "{" in start[len(prefix):] or "}" in start[len(prefix):-2]):
        raise APError("The loaded hostapd command is unrecognized; no restart was attempted.")


def wait_job(system, job, cancel=False):
    """Cancel only our captured D-Bus job ID, never arbitrary systemd jobs."""
    deadline = system.clock() + 15
    cancelled = False
    while True:
        active = current_job(system)
        if not active:
            return
        if job and active != job:
            raise APError("An unrelated hostapd job is running; nothing was overwritten or restarted.")
        if cancel and job and not cancelled:
            system.runner(BUS + ["CancelJob", "u", str(job)])
            cancelled = True
        if system.clock() >= deadline:
            raise APError("The hostapd service job did not settle; recovery cannot safely continue.")
        system.sleep(0.2)


def ready(system, expected, old_pid):
    deadline = system.clock() + 10
    while True:
        if system.validate() != expected:
            raise APError("The configuration changed externally; no further restart was attempted.")
        observed = system.observe()
        if (observed["state"] == "ENABLED" and observed["link"] == "up"
                and "10.78.0.1/24" in observed["addresses"] and observed["pid"] != old_pid):
            return
        if system.clock() >= deadline:
            raise APError("The restarted access point did not become ready in time.")
        system.sleep(0.2)


def restart_ap(system, record, expected, old_pid):
    if system.validate() != expected:
        raise APError("The configuration changed externally; no restart was attempted.")
    verify_start_definition(system)
    if current_job(system):
        raise APError("Another hostapd service job is running; no restart was attempted.")
    # D-Bus returns this specific job's identity. Losing a waiting CLI process
    # cannot be mistaken for cancellation of an asynchronous service restart.
    reply = system.runner(BUS + ["RestartUnit", "ss", "hostapd.service", "fail"])
    match = re.fullmatch(r'o "/org/freedesktop/systemd1/job/([1-9][0-9]*)"', reply)
    if not match:
        raise APError("The hostapd restart job identity could not be verified.")
    record["job"] = int(match[1])
    write_record(system, record)
    wait_job(system, record["job"])
    record["job"] = 0
    write_record(system, record)
    ready(system, expected, old_pid)


def recover_locked(system, record):
    if record["state"] in {"applied", "recovered"}:
        return
    if record["original"] is None:
        record.update(state="recovered", phase="done", error="operation-failed")
        write_record(system, record)
        return
    original = base64.b64decode(record["original"], validate=True)
    replacement = replacement_for(original, record["target"])
    # First settle/cancel the exact old restart. An unrecorded job (e.g. the
    # process died after D-Bus replied) is only waited for, never cancelled.
    if record["phase"] == "restart":
        wait_job(system, record["job"], cancel=True)
        record["job"] = 0
        write_record(system, record)
    actual = system.validate()
    if actual not in (original, replacement):
        raise APError("The configuration changed externally; it was not overwritten or restarted.")
    if actual != original:
        system.persist(original, replacement)
    if record["phase"] == "restart":
        observed = system.observe()
        restart_ap(system, record, original, observed["pid"])
    record.update(state="recovered", phase="done", error="operation-failed")
    write_record(system, record)


def worker(system, recovery=False):
    with system.lock(wait=True):
        record = read_record(system)
        if record is None:
            raise APError("No AP operation has been scheduled.")
        if recovery:
            try:
                recover_locked(system, record)
            except BaseException:
                record.update(state="failed", error="recovery-failed")
                write_record(system, record)
                raise APError("AP recovery failed; the private operation record was retained.") from None
            return
        if record["state"] != "queued":
            raise APError("The AP operation is not queued; duplicate execution was refused.")
        try:
            original = system.validate()
            observed = system.observe()
            verify_start_definition(system)
            if (hashlib.sha256(original).hexdigest() != record["expected"]
                    or observed["pid"] != record["pid"] or observed["state"] != "ENABLED"):
                raise APError("The access point changed before the operation started.")
            replacement = replacement_for(original, record["target"])
            record.update(state="running", phase="prepared", original=base64.b64encode(original).decode())
            write_record(system, record)
            if original != replacement:
                system.persist(replacement, original)
            record["phase"] = "persisted"
            write_record(system, record)
            record["phase"] = "restart"
            write_record(system, record)
            restart_ap(system, record, replacement, observed["pid"])
            record.update(state="applied", phase="done")
            write_record(system, record)
        except BaseException:
            try:
                recover_locked(system, record)
            except BaseException:
                record.update(state="failed", error="recovery-failed")
                write_record(system, record)
                raise APError("AP change and recovery failed; inspect auto ap --status.") from None
            raise APError("AP change failed; inspect auto ap --status for the recovery result.") from None


def change_visibility(system, value):
    """Only schedule the one fixed worker; never mutate hostapd in this TTY."""
    with system.lock():
        original = system.validate()
        observed = system.observe()
        verify_start_definition(system)
        if (observed["state"] != "ENABLED" or observed["link"] != "up"
                or "10.78.0.1/24" not in observed["addresses"]):
            raise APError("The control access point is not enabled; nothing was changed.")
        binary, _ = system.trusted_read(WORKER.lstrip("/"), 1048576)
        if binary != Path(__file__).read_bytes():
            raise APError("The fixed installed AP worker does not match this command.")
        fields = unit_fields(system, UNIT, "LoadState,ActiveState")
        if fields.get("LoadState") != "not-found":
            raise APError("Another AP operation unit exists; wait for it to finish.")
        previous = read_record(system)
        if previous and previous["state"] not in {"applied", "recovered"}:
            raise APError("An unfinished AP operation needs recovery before another can be scheduled.")
        record = dict(schema=1, id=uuid.uuid4().hex, target=value,
                      expected=hashlib.sha256(original).hexdigest(), state="queued", phase="queued",
                      original=None, pid=observed["pid"], job=0, error=None)
        write_record(system, record)
        command = ["/usr/bin/systemd-run", "--quiet", "--no-block", "--collect",
                       "--unit=" + UNIT, "--property=Type=exec", "--property=User=root",
                       "--property=Group=root", "--property=UMask=0077",
                       "--property=RuntimeMaxSec=150s", "--property=TimeoutStopSec=60s",
                       "--property=KillMode=control-group", "--property=StandardInput=null",
                       "--property=StandardOutput=journal", "--property=StandardError=journal",
                       "--property=ExecStopPost=/usr/bin/python3 -I " + WORKER + " --internal-recover",
                       "/usr/bin/python3", "-I", WORKER, "--internal-worker"]
        try:
            system.runner(command)
        except BaseException:
            # A lost systemd-run client is not proof that the service failed to
            # start. Clear only a still-queued record if no unit exists and the
            # original configuration is unchanged; otherwise retain evidence.
            try:
                state = unit_fields(system, UNIT, "LoadState").get("LoadState")
                current = read_record(system)
                if (state == "not-found" and current and current["id"] == record["id"]
                        and current["state"] == "queued" and system.validate() == original):
                    current.update(state="recovered", phase="done", error="operation-failed")
                    write_record(system, current)
            except (APError, OSError):
                pass
            raise APError("AP scheduling could not be confirmed; check auto ap --status before retrying.") from None


def verify_worker_context(system):
    group = unit_fields(system, UNIT, "ControlGroup").get("ControlGroup")
    if group != "/system.slice/" + UNIT:
        raise APError("The internal worker requires its fixed system service.")
    if "0::" + group not in (system.root / "proc/self/cgroup").read_text().splitlines():
        raise APError("The internal worker is outside its fixed system service.")


def print_status(system):
    original = system.validate()
    observed = system.observe()
    print("Interface: ctrl0 (control WLAN)")
    configured_ssid = re.search(rb"(?m)^ssid2=([0-9a-fA-F]+)$", original)
    print("SSID: " + json.dumps(bytes.fromhex(configured_ssid[1].decode()).decode("utf-8"), ensure_ascii=True))
    print(f"Interface present: {'yes' if observed['present'] else 'no'}")
    print(f"Link: {observed['link']}")
    print(f"Addresses: {', '.join(observed['addresses']) or 'none'}")
    print(f"hostapd service: {observed['service']}")
    print(f"Live AP state: {observed['state']}")
    print(f"Configured visibility: {'visible' if parse_config(original) == 0 else 'invisible'}")
    print("Radio visibility: not independently verified by this command")
    record = read_record(system)
    if record:
        print("Last AP operation: " + record["state"])
        if record["state"] == "applied":
            print("Result: hostapd restarted and ready with the configured setting")
        elif record["state"] == "recovered":
            print("Result: operation failed; " + ("no configuration change was made" if record["original"] is None
                                                  else "previous configured state restored"))
        elif record["state"] == "failed":
            print("Result: recovery could not be confirmed; administrator inspection required")
    return 0


def main(argv=None, *, system=None, euid=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv in (["--internal-worker"], ["--internal-recover"]):
        if (os.geteuid() if euid is None else euid) != 0:
            print("auto ap: The internal worker requires root.", file=sys.stderr)
            return 77
        system = system if system is not None else System()
        try:
            verify_worker_context(system)
            def terminated(signum, frame):
                raise APError("The AP worker was interrupted.")
            signal.signal(signal.SIGTERM, terminated)
            signal.signal(signal.SIGHUP, terminated)
            worker(system, recovery=argv == ["--internal-recover"])
            return 0
        except (APError, OSError):
            print("auto ap: The internal AP operation failed; inspect auto ap --status.", file=sys.stderr)
            return 1
    parser = Parser(prog="auto ap", description="Show or change the control WLAN SSID visibility.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--visible", action="store_true", help="Save visible SSID and schedule a brief control WLAN restart")
    group.add_argument("--invisible", action="store_true", help="Save hidden SSID and schedule a brief control WLAN restart")
    group.add_argument("--status", action="store_true", help="Show interface, live AP state and configured visibility (default)")
    args = parser.parse_args(argv)
    system = system if system is not None else System()
    try:
        if args.visible or args.invisible:
            if (os.geteuid() if euid is None else euid) != 0:
                print("auto ap: Changes require root; run sudo auto ap with the same option.", file=sys.stderr)
                return 77
            value = int(args.invisible)
            change_visibility(system, value)
            print("AP change scheduled. Control WLAN will disconnect briefly. Check auto ap --status for completion.")
            return 0
        return print_status(system)
    except (APError, OSError):
        error = sys.exc_info()[1]
        message = str(error) if isinstance(error, APError) else "System access failed; configuration and command output were not disclosed."
        print(f"auto ap: {message}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("auto ap: Interrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
