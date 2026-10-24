#!/usr/bin/python3
"""Conservative control of the configured Kali host's normal OpenSSH service.

Only systemd enable/start/stop/disable are changed. Configuration, credentials,
firewall rules and existing sessions are never rewritten or individually killed.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import glob
import hashlib
import importlib.util
import ipaddress
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import time

SYSTEMCTL = "/usr/bin/systemctl"
SSHD = "/usr/sbin/sshd"
SS = "/usr/bin/ss"
CONFIG = "/etc/ssh/sshd_config"
LOCK = "/run/automations-host-ssh.lock"
SUPPORT = "/usr/local/libexec/automations-support/platform_support.py"
PROPERTIES = (
    "Id", "LoadState", "ActiveState", "SubState", "UnitFileState", "MainPID",
    "ControlGroup", "FragmentPath", "DropInPaths", "NeedDaemonReload", "Job",
    "ExecStart", "ExecStartPre", "ExecStartPost", "ExecCondition", "ExecStop",
    "ExecStopPost", "ExecReload", "Environment", "EnvironmentFiles", "PassEnvironment", "User",
    "Group", "DynamicUser", "RootDirectory", "RootImage", "PrivateNetwork",
    "NetworkNamespacePath", "Type", "KillMode", "TriggeredBy",
)


class Error(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise Error(message)


def run(args):
    """No shell, caller environment, command strings or unbounded subprocesses."""
    try:
        return subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True,
                              text=True, timeout=15, check=False,
                              env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    except subprocess.TimeoutExpired:
        raise Error("Command timed out: " + Path(args[0]).name) from None


def fields(output):
    result = {}
    for line in output.splitlines():
        require("=" in line, "Invalid systemd status response.")
        key, value = line.split("=", 1)
        if key in result:
            # systemctl emits one line per command for these supported lists.
            # Preserve order so validate_unit still rejects changed/extra hooks.
            require(key in ("ExecStartPre", "ExecReload"),
                    "Duplicate systemd status property.")
            result[key] += " ; " + value
        else:
            result[key] = value
    return result


def endpoint(value):
    require(isinstance(value, str) and ":" in value, "Invalid SSH listener address.")
    host, port = value.rsplit(":", 1)
    host = host.removeprefix("[").removesuffix("]")
    require(port.isdecimal() and 1 <= int(port) <= 65535, "Invalid SSH listener port.")
    require(host != "*", "Ambiguous wildcard listener; use numeric ss output.")
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        raise Error("Only numeric SSH listen addresses are supported.") from None
    return host, int(port)


class HostSSH:
    def __init__(self, profile, *, root=Path("/"), runner=None, owner_uid=0,
                 sleeper=time.sleep):
        require(profile.platform == "kali-host", "The host SSH backend requires a Kali host profile.")
        require(profile.ssh_service in ("ssh.service", "sshd.service"), "Unsupported SSH service.")
        self.profile, self.service = profile, profile.ssh_service
        self.root, self.run = Path(root), runner or run
        self.uid, self.sleep = owner_uid, sleeper
        self.pins = {}

    def path(self, absolute):
        require(absolute.startswith("/") and ".." not in Path(absolute).parts, "Unsafe system path.")
        return self.root / absolute.lstrip("/")

    def trusted(self, absolute, *, directory=False, executable=False):
        """Verify the resolved object AND every lexical/resolved parent."""
        path = self.path(absolute)
        resolved = path.resolve(strict=True)
        require(resolved.is_relative_to(self.root.resolve()), "System path escapes its root.")
        for candidate in set((path, *path.parents, resolved, *resolved.parents)):
            if not candidate.is_relative_to(self.root):
                continue
            info = candidate.lstat()
            require(info.st_uid == self.uid and (stat.S_ISLNK(info.st_mode) or not info.st_mode & 0o022),
                    "System path is not protected by its trusted owner: " + absolute)
        info = resolved.stat()
        require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode),
                "Unexpected system file type: " + absolute)
        require(not executable or info.st_mode & 0o111, "System executable is not executable.")
        if not directory:
            require(info.st_nlink == 1, "Unexpected hard-linked system file.")
            # Bounded metadata; binary fingerprints use stat instead of reading ELF contents.
            if executable:
                content = b""
            else:
                require(info.st_size <= 1024 * 1024, "System configuration is too large.")
                content = resolved.read_bytes()
            signature = (str(resolved), info.st_dev, info.st_ino, info.st_mode, info.st_uid,
                         info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
                         hashlib.sha256(content).hexdigest())
            previous = self.pins.setdefault(absolute, (signature, directory, executable))
            require(previous[0] == signature, "System configuration changed during SSH operation.")
            return content.decode("utf-8", errors="strict") if not executable else ""
        return ""

    def recheck(self):
        for path, (_, directory, executable) in list(self.pins.items()):
            self.trusted(path, directory=directory, executable=executable)

    def command(self, args, *, allowed=(0,)):
        require(args[0] in (SYSTEMCTL, SSHD, SS), "Unsupported executable.")
        self.trusted(args[0], executable=True)
        result = self.run(list(args))
        require(result.returncode in allowed,
                Path(args[0]).name + " failed (exit " + str(result.returncode) + ").")
        require(isinstance(result.stdout, str) and len(result.stdout) <= 1024 * 1024,
                "Invalid or excessive command output.")
        return result.stdout

    def show(self, service=None, properties=PROPERTIES):
        return fields(self.command([SYSTEMCTL, "show", service or self.service,
                                    "--property=" + ",".join(properties)], allowed=(0, 1)))

    @contextmanager
    def lock(self):
        self.trusted("/run", directory=True)
        fd = os.open(self.path(LOCK), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == self.uid and info.st_nlink == 1
                    and stat.S_IMODE(info.st_mode) == 0o600, "Unsafe SSH operation lock.")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Error("Another host SSH operation is running.") from None
            require(self.path(LOCK).stat().st_ino == info.st_ino, "SSH operation lock changed.")
            yield
        finally:
            os.close(fd)

    def config_files(self, absolute=CONFIG, seen=None):
        seen = set() if seen is None else seen
        require(absolute not in seen and len(seen) < 64, "Recursive or excessive SSH includes.")
        seen.add(absolute)
        raw = self.trusted(absolute)
        for line in raw.splitlines():
            words = shlex.split(line, comments=True, posix=True)
            if not words or words[0].lower() != "include":
                continue
            require(len(words) >= 2, "Invalid SSH Include directive.")
            for pattern in words[1:]:
                require(pattern.startswith("/etc/ssh/") and ".." not in Path(pattern).parts
                        and not any(c in pattern for c in ("%", "~", "\\")),
                        "Only protected absolute /etc/ssh includes are supported.")
                # Include expansion is local file discovery, never shell evaluation.
                parent = str(Path(pattern).parent)
                require(not glob.has_magic(parent), "Wildcard include directories are unsupported.")
                self.trusted(parent, directory=True)
                for included in sorted(glob.glob(str(self.path(pattern)))):
                    self.config_files("/" + str(Path(included).relative_to(self.root)), seen)
        return seen

    def executable_hooks(self, value):
        if not value:
            return []
        expressions = re.findall(r"\{ path=([^;]+) ; argv\[\]=(.*?) ; ignore_errors=(yes|no) ;[^}]*\}", value)
        residue = re.sub(r"\{ path=[^;]+ ; argv\[\]=.*? ; ignore_errors=(?:yes|no) ;[^}]*\}", "", value)
        require(expressions and not residue.strip(" ;"), "Unrecognized systemd execution hook.")
        commands = []
        for path, argv, ignored in expressions:
            require(ignored == "no", "Ignored SSH execution failures are unsupported.")
            words = shlex.split(argv)
            require(words and path == words[0], "Unrecognized systemd execution hook.")
            commands.append(tuple(words))
        return commands

    def validate_unit(self, unit):
        require(unit.get("LoadState") == "loaded", "SSH unit cannot be loaded.")
        require(unit.get("Id") in ("ssh.service", "sshd.service"), "Unexpected SSH unit identity.")
        require(unit.get("NeedDaemonReload") == "no", "SSH unit requires an administrator daemon-reload.")
        require(not unit.get("DropInPaths"), "SSH unit drop-ins are not supported; no changes made.")
        fragment = unit.get("FragmentPath", "")
        require(fragment in tuple(directory + "/" + name for directory in (
            "/usr/lib/systemd/system", "/lib/systemd/system", "/etc/systemd/system")
            for name in ("ssh.service", "sshd.service")), "Unexpected SSH unit fragment.")
        self.trusted(fragment)
        for name in ("ExecCondition", "ExecStartPost", "ExecStop", "ExecStopPost"):
            require(not unit.get(name), "Unsupported SSH execution hook: " + name)
        start = self.executable_hooks(unit.get("ExecStart", ""))
        require(start in [[(SSHD, "-D")], [(SSHD, "-D", "$SSHD_OPTS")]],
                "Only the standard foreground OpenSSH command is supported.")
        pre = self.executable_hooks(unit.get("ExecStartPre", ""))
        known_pre = {(SSHD, "-t"), ("/usr/bin/mkdir", "-p", "/run/sshd"),
                     ("/bin/mkdir", "-p", "/run/sshd")}
        require(pre and (SSHD, "-t") in pre and len(pre) <= 2 and len(set(pre)) == len(pre)
                and all(command in known_pre for command in pre), "Unsupported SSH pre-start hooks.")
        reload = self.executable_hooks(unit.get("ExecReload", ""))
        require(reload in ([], [(SSHD, "-t"), ("/bin/kill", "-HUP", "$MAINPID")],
                                  [(SSHD, "-t"), ("/usr/bin/kill", "-HUP", "$MAINPID")]),
                "Unsupported SSH reload hooks.")
        for command in pre + reload:
            self.trusted(command[0], executable=True)
        require(not unit.get("PassEnvironment"), "Inherited manager environment is unsupported.")
        require(unit.get("Environment", "") in ("", "SSHD_OPTS=", '"SSHD_OPTS="'),
                "Additional SSH service environment is unsupported.")
        environment = unit.get("EnvironmentFiles", "")
        require(environment in ("", "/etc/default/ssh (ignore_errors=yes)"),
                "Unsupported SSH environment file.")
        if environment and self.path("/etc/default/ssh").exists():
            lines = [line.strip() for line in self.trusted("/etc/default/ssh").splitlines()
                     if line.strip() and not line.lstrip().startswith("#")]
            require(len(lines) <= 1 and all(line in ("SSHD_OPTS=", 'SSHD_OPTS=""', "SSHD_OPTS=''")
                                           for line in lines), "Nonempty or unsupported SSHD_OPTS.")
        require(unit.get("User", "") in ("", "root") and unit.get("Group", "") in ("", "root")
                and unit.get("DynamicUser") == "no", "SSH unit must use the normal root daemon.")
        require(not any(unit.get(name) for name in ("RootDirectory", "RootImage", "NetworkNamespacePath"))
                and unit.get("PrivateNetwork") == "no", "Namespaced SSH units are unsupported.")
        require(unit.get("Type") in ("simple", "exec", "notify", "notify-reload")
                and unit.get("KillMode") in ("process", "mixed", "control-group"),
                "Unsupported SSH service lifecycle.")
        require(not unit.get("Job") or unit["Job"] in ("0", "0 /"), "SSH service already has a pending job.")
        require(set(unit.get("TriggeredBy", "").split()) <= {"ssh.socket", "sshd.socket"},
                "Unexpected SSH activation source.")
        for name in ("ssh.socket", "sshd.socket"):
            socket = self.show(name, ("LoadState", "ActiveState", "UnitFileState"))
            require(socket.get("LoadState") in ("loaded", "not-found"), "Cannot verify SSH socket activation.")
            if socket["LoadState"] == "loaded":
                require(socket.get("ActiveState") == "inactive" and socket.get("UnitFileState")
                        in ("disabled", "masked", "static"), "SSH socket activation must be inactive and disabled.")

    def configured_listeners(self, *, active=True):
        files = self.config_files()
        if active:
            self.command([SSHD, "-t", "-f", CONFIG])
        # systemd removes RuntimeDirectory=/run/sshd when the service stops.
        # -G still rejects invalid configuration, without -t's runtime/key tests.
        # The validated ExecStartPre runs -t after systemd creates its runtime
        # directory; active readback always retains the full -t/-T checks.
        output = self.command([SSHD, "-T" if active else "-G", "-f", CONFIG])
        ports, listeners = [], []
        for line in output.splitlines():
            key, _, value = line.partition(" ")
            if key == "port":
                require(value.isdecimal() and 1 <= int(value) <= 65535, "Invalid configured SSH port.")
                ports.append(int(value))
            elif key == "listenaddress":
                listeners.append(endpoint(value))
        require(ports and listeners and len(set(ports)) == len(ports)
                and len(set(listeners)) == len(listeners), "No unambiguous SSH listen configuration.")
        # Detect edited or newly added Include files before any service action.
        self.recheck()
        require(files == self.config_files(), "SSH include files changed during validation.")
        self.config_set = files
        return sorted(ports), sorted(listeners)

    def listeners(self, unit, expected):
        result = []
        main_pid = int(unit.get("MainPID", "0"))
        for family in ("-4", "-6"):
            output = self.command([SS, "-H", "-ltnp", family])
            for line in output.splitlines():
                parts = line.split()
                require(len(parts) >= 5 and parts[0] == "LISTEN", "Invalid listening socket response.")
                address = parts[3]
                if address.startswith("*:"):
                    address = ("0.0.0.0" if family == "-4" else "[::]") + address[1:]
                address = endpoint(address)
                owners = re.findall(r'\("([^"\n]+)",pid=([0-9]+),fd=[0-9]+\)', line)
                daemon = any(name in ("sshd", "sshd-session") for name, _ in owners)
                relevant = daemon or address in expected or any(address[1] == item[1] for item in expected)
                if not relevant:
                    continue
                require(owners, "Cannot determine ownership of a relevant SSH listener; run as root.")
                if daemon:
                    require(unit["ActiveState"] == "active" and main_pid > 0
                            and all(name == "sshd" and int(pid) == main_pid for name, pid in owners),
                            "A foreign SSH daemon or listener is present; no changes made.")
                    require(address in expected, "SSH daemon has an unexpected listen address.")
                    result.append(address)
                else:
                    # Conservative: never start SSH over an existing listener on its port.
                    raise Error("An unrelated service owns a configured SSH port; no changes made.")
        if unit["ActiveState"] == "active":
            require(main_pid > 0 and set(result) == set(expected), "SSH listeners do not match validated configuration.")
            proc = self.path("/proc/" + str(main_pid))
            require(os.readlink(proc / "exe") == SSHD, "SSH main process is not the expected executable.")
            status = (proc / "status").read_text()
            uid = re.search(r"^Uid:\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)$", status, re.M)
            require(uid and all(int(value) == 0 for value in uid.groups()), "SSH daemon has unexpected ownership.")
            group = "/system.slice/" + unit["Id"]
            require(unit.get("ControlGroup") == group and (proc / "cgroup").read_text().strip() == "0::" + group,
                    "SSH daemon is not owned by the selected systemd service.")
        else:
            require(main_pid == 0 and not result, "Inactive SSH service still has an unexpected process.")
        return sorted(result)

    def inspect(self):
        base = dict(service=self.service, configured=self.profile.configured, available=False,
                    active_state="unknown", sub_state="unknown", unit_file_state="unknown",
                    ports=[], configured_listeners=[], listeners=[], firewall_reachability="not assessed")
        if not self.path("/run/systemd/system").is_dir():
            return dict(base, reason="systemd is not running on this host")
        if not self.path(SYSTEMCTL).exists():
            return dict(base, reason="systemctl is not installed")
        unit = self.show()
        base.update(active_state=unit.get("ActiveState", "unknown"), sub_state=unit.get("SubState", "unknown"),
                    unit_file_state=unit.get("UnitFileState", "unknown"))
        if unit.get("LoadState") == "not-found":
            return dict(base, reason="the configured OpenSSH service is not installed")
        self.validate_unit(unit)
        require(unit["ActiveState"] in ("active", "inactive", "failed"), "SSH service is in a transitional state.")
        ports, expected = self.configured_listeners(active=unit["ActiveState"] == "active")
        observed = self.listeners(unit, expected)
        return dict(base, available=True, ports=ports, configured_listeners=expected,
                    listeners=observed, unit=unit, reason=None)

    def action(self, action):
        require(action in ("enable", "disable", "start", "stop"), "Unsupported SSH action.")
        self.recheck()
        require(self.config_set == self.config_files(), "SSH include files changed during operation.")
        # Recheck effective properties, including concurrent administrator daemon-reloads.
        self.validate_unit(self.show())
        self.command([SYSTEMCTL, action, self.service])

    def wait(self, active):
        wanted = "active" if active else "inactive"
        for attempt in range(30):
            unit = self.show()
            if unit.get("ActiveState") == wanted and (not unit.get("Job") or unit["Job"] in ("0", "0 /")):
                return
            if active and unit.get("ActiveState") == "failed":
                break
            if attempt < 29:
                self.sleep(.2)
        raise Error("SSH service did not reach the requested state within the bounded wait.")

    def change(self, enabled):
        require(os.geteuid() == 0, "Root privileges are required to change host SSH.")
        require(self.profile.configured is True, "Configure an explicit Kali host profile before changing SSH.")
        require(type(enabled) is bool, "Invalid SSH action.")
        with self.lock():
            before = self.inspect()
            require(before["available"], "Host SSH unavailable: " + str(before["reason"]))
            require(before["unit_file_state"] in ("enabled", "disabled"),
                    "Only persistently enabled or disabled SSH units can be changed.")
            require(before["active_state"] in ("active", "inactive"),
                    "Resolve the failed SSH service before changing its state.")
            was_active = before["active_state"] == "active"
            was_enabled = before["unit_file_state"] == "enabled"
            if was_active == enabled and was_enabled == enabled:
                return before, False
            try:
                if enabled:
                    if not was_enabled:
                        self.action("enable")
                    if not was_active:
                        self.action("start")
                else:
                    if was_active:
                        self.action("stop")
                    if was_enabled:
                        self.action("disable")
                self.wait(enabled)
                after = self.inspect()
                require(after["available"] and (after["active_state"] == "active") == enabled
                        and after["unit_file_state"] == ("enabled" if enabled else "disabled"),
                        "SSH state readback does not match the requested setting.")
                return after, True
            except (Exception, KeyboardInterrupt) as error:
                failures = []
                # Restore each independent state even if the other restoration fails.
                for action in ("start" if was_active else "stop", "enable" if was_enabled else "disable"):
                    try:
                        self.action(action)
                    except Exception as restore_error:
                        failures.append(str(restore_error))
                try:
                    self.wait(was_active)
                    restored = self.inspect()
                    require(restored["active_state"] == before["active_state"]
                            and restored["unit_file_state"] == before["unit_file_state"], "Previous SSH state differs.")
                except Exception as restore_error:
                    failures.append(str(restore_error))
                original = "Operation interrupted" if isinstance(error, KeyboardInterrupt) else str(error)
                if failures:
                    raise Error("SSH change failed; rollback incomplete: " + original + "; " + "; ".join(failures)) from None
                raise Error("SSH change failed; previous active/enabled state restored: " + original) from None


def print_status(state):
    print("Host SSH service: " + state["service"])
    print("Service state: " + state["active_state"] + " (" + state["sub_state"] + ")")
    print("Boot enablement: " + state["unit_file_state"])
    if not state["available"]:
        print("Unavailable: " + state["reason"])
        return
    print("Configured ports: " + ", ".join(map(str, state["ports"])))
    render = lambda item: ("[" + item[0] + "]" if ":" in item[0] else item[0]) + ":" + str(item[1])
    print("Configured listeners: " + ", ".join(map(render, state["configured_listeners"])))
    print("Observed SSH listeners: " + (", ".join(map(render, state["listeners"])) or "none"))
    print("Firewall and remote reachability: not assessed.")
    if not state["configured"]:
        print("Changes require an explicit configured Kali host profile.")


def load_profile():
    # Root-managed support location; never import a module from the current directory.
    from types import SimpleNamespace
    guard = HostSSH(SimpleNamespace(platform="kali-host", ssh_service="ssh.service", configured=False))
    guard.trusted(SUPPORT)
    spec = importlib.util.spec_from_file_location("automations_host_ssh_platform_support", SUPPORT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.load_profile()


def main(argv=None, profile=None):
    parser = argparse.ArgumentParser(prog="auto ssh", description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--on", action="store_true", help="Enable and start the configured host OpenSSH service")
    group.add_argument("--off", action="store_true", help="Stop and disable that service; existing sessions follow its unit policy")
    group.add_argument("--status", action="store_true", help="Show validated service, configuration and listener state")
    args = parser.parse_args(argv)
    try:
        if args.on or args.off:
            require(os.geteuid() == 0, "Root privileges are required; run sudo auto ssh with the requested option.")
        backend = HostSSH(profile if profile is not None else load_profile())
        if args.on or args.off:
            state, changed = backend.change(args.on)
            print("Host SSH setting updated." if changed else "Host SSH already matches.")
        else:
            state = backend.inspect()
        print_status(state)
        return 0 if state["available"] else 3
    except (Error, OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        print("ERROR: " + str(error), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("ERROR: Operation interrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
