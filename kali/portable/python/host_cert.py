#!/usr/bin/python3
"""Optional, separately owned public-CA download service for a Kali host.

No CA is generated or trusted, and no existing web server is reconfigured.
Setup is explicit: the fixed configuration, certificates and service must
already be installed by the administrator. CLI status performs no network I/O.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import errno
import fcntl
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
from socketserver import TCPServer
import ssl
import stat
import struct
import subprocess
import sys

SUPPORT = "/usr/local/libexec/automations-support/platform_support.py"
CONFIG = "/etc/automations/host-cert.json"
DIRECTORY = "/etc/automations/host-cert"
CA, CERT, KEY = (DIRECTORY + "/" + name for name in ("ca.crt", "server.crt", "server.key"))
SERVICE = "automations-host-cert.service"
UNIT = "/etc/systemd/system/" + SERVICE
PAYLOAD = "/usr/local/libexec/automations-host/cert"
LOCK = "/run/automations-host-cert.lock"
SYSTEMCTL, OPENSSL = "/usr/bin/systemctl", "/usr/bin/openssl"
BUSCTL = "/usr/bin/busctl"
BUS_NAME = "org.freedesktop.systemd1"
BUS_UNIT_OBJECT = "/org/freedesktop/systemd1/unit/automations_2dhost_2dcert_2eservice"
BUS_INTERFACE = BUS_NAME + ".Service"
CREDENTIALS = "/run/credentials/" + SERVICE
UNIT_TEXT = """[Unit]
Description=Automations host public CA download (optional)
After=network.target

[Service]
Type=notify
NotifyAccess=main
DynamicUser=yes
ExecStart=/usr/bin/python3 -B /usr/local/libexec/automations-host/cert --internal-serve
LoadCredential=server.key:/etc/automations/host-cert/server.key
TimeoutStartSec=20
TimeoutStopSec=10
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
UMask=0077

[Install]
WantedBy=multi-user.target
"""
PROPERTIES = (
    "Id", "LoadState", "ActiveState", "SubState", "UnitFileState", "Type",
    "FragmentPath", "DropInPaths", "NeedDaemonReload", "ExecStart", "DynamicUser",
    "Environment", "RootDirectory", "RootImage",
    "PrivateNetwork", "NetworkNamespacePath", "NoNewPrivileges", "ProtectSystem",
    "ProtectHome", "PrivateTmp", "PrivateDevices", "RestrictSUIDSGID", "CapabilityBoundingSet",
)


class Error(RuntimeError):
    pass


class NotAvailable(Error):
    pass


def require(condition, message):
    if not condition:
        raise Error(message)


def load_profile():
    """Load only the fixed, root-protected common profile implementation."""
    helper = Path(SUPPORT)
    for item in (helper, *helper.parents):
        info = item.lstat()
        require(not stat.S_ISLNK(info.st_mode) and info.st_uid == 0
                and not info.st_mode & 0o022, "Installed platform support is not root-protected.")
    require(helper.is_file() and helper.stat().st_size <= 65536, "Invalid platform support file.")
    content = helper.read_bytes()
    name = "_automations_host_cert_profile_" + hashlib.sha256(content).hexdigest()
    spec = importlib.util.spec_from_file_location(name, helper)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        exec(compile(content, str(helper), "exec"), module.__dict__)
        return module.load_profile()
    finally:
        sys.modules.pop(name, None)


def profile_key(profile):
    require(profile.platform == "kali-host" and type(profile.configured) is bool
            and isinstance(profile.identity, str) and re.fullmatch(r"[0-9a-f]{64}", profile.identity),
            "A valid Kali-host platform profile is required.")
    return profile.identity, profile.configured


def run(args):
    try:
        return subprocess.run(args, stdin=subprocess.DEVNULL, text=True, capture_output=True,
                              timeout=45, check=False,
                              env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
    except subprocess.TimeoutExpired:
        raise Error("Certificate service command timed out.") from None


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate certificate configuration field.")
        result[key] = value
    return result


def parse_config(content):
    try:
        value = json.loads(content.decode("utf-8"), object_pairs_hook=unique)
    except (UnicodeError, json.JSONDecodeError):
        raise Error("Host certificate configuration must be UTF-8 JSON.") from None
    require(isinstance(value, dict) and set(value) == {"schema_version", "listen_address", "port"}
            and type(value["schema_version"]) is int and value["schema_version"] == 1,
            "Unsupported host certificate configuration schema.")
    require(isinstance(value["listen_address"], str), "A numeric listen address is required.")
    try:
        address = ipaddress.ip_address(value["listen_address"])
    except ValueError:
        raise Error("A numeric listen address is required.") from None
    require(not (address.is_unspecified or address.is_multicast or address.is_link_local)
            and getattr(address, "ipv4_mapped", None) is None
            and str(address) != "255.255.255.255" and "%" not in str(address),
            "Use one explicit unicast or loopback listen address, without IPv4-mapped IPv6.")
    require(type(value["port"]) is int and 1024 <= value["port"] <= 65535,
            "The separate certificate service requires an unprivileged port (1024..65535).")
    return {"listen_address": str(address), "port": value["port"]}


class HostCert:
    def __init__(self, profile, *, root=Path("/"), runner=run, profile_loader=None, owner_uid=0):
        self.key = profile_key(profile)
        self.profile, self.root, self.run = profile, Path(root), runner
        self.loader = load_profile if profile_loader is None else profile_loader
        self.uid, self.pins = owner_uid, {}

    def path(self, absolute):
        require(absolute.startswith("/") and ".." not in Path(absolute).parts, "Unsafe host certificate path.")
        return self.root / absolute.lstrip("/")

    def file(self, absolute, *, limit=1024 * 1024, private=False, executable=False):
        path = self.path(absolute)
        for item in (path, *path.parents):
            if not item.is_relative_to(self.root):
                break
            info = item.lstat()
            require(not stat.S_ISLNK(info.st_mode) and info.st_uid == self.uid
                    and not info.st_mode & 0o022, "Host certificate files and paths must be root-protected.")
            require(stat.S_ISREG(info.st_mode) if item == path else stat.S_ISDIR(info.st_mode),
                    "Unexpected host certificate file type.")
        info = path.stat()
        require(info.st_nlink == 1 and info.st_size <= limit, "Invalid or excessive host certificate file.")
        require(not private or stat.S_IMODE(info.st_mode) == 0o600, "The server key must have mode 0600.")
        require(not executable or info.st_mode & 0o111, "The required system program is not executable.")
        content = b"" if private or executable else path.read_bytes()
        signature = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                     info.st_size, info.st_mtime_ns, info.st_ctime_ns, hashlib.sha256(content).digest())
        previous = self.pins.setdefault(absolute, signature)
        require(previous == signature, "Host certificate setup changed during the operation.")
        return content

    def recheck(self):
        require(profile_key(self.loader()) == self.key, "The installed host profile changed.")
        for absolute in list(self.pins):
            executable = absolute in (SYSTEMCTL, OPENSSL, BUSCTL)
            self.file(absolute, private=absolute == KEY, executable=executable,
                      limit=32 * 1024 * 1024 if executable else 1024 * 1024)

    def command(self, args):
        require(args[0] in (SYSTEMCTL, OPENSSL, BUSCTL), "Unsupported certificate service command.")
        self.file(args[0], executable=True, limit=32 * 1024 * 1024)
        result = self.run(list(args))
        require(isinstance(result.stdout, str) and len(result.stdout) <= 65536,
                "Invalid certificate service command output.")
        require(result.returncode == 0, "Certificate service command failed: " + Path(args[0]).name + ".")
        return result.stdout

    def bus_value(self, arguments, signature):
        """Read typed D-Bus data; systemctl cannot render these structured properties."""
        raw = self.command([BUSCTL, "--system", "--json=short", "--no-pager", "--timeout=10s", *arguments])
        try:
            value = json.loads(raw, object_pairs_hook=unique)
        except (ValueError, UnicodeError):
            raise Error("Invalid structured certificate unit response.") from None
        require(type(value) is dict and set(value) == {"type", "data"}
                and value["type"] == signature, "Unexpected certificate unit D-Bus signature.")
        return value["data"]

    def structured_unit(self):
        # GetUnit only finds an already loaded unit. Inactive units may be
        # garbage-collected between CLI processes. Property access at the
        # fixed unit path resolves the definition within each request instead.
        unit_id = self.bus_value(["get-property", BUS_NAME, BUS_UNIT_OBJECT,
                                  BUS_NAME + ".Unit", "Id"], "s")
        require(type(unit_id) is str and unit_id == SERVICE,
                "Invalid certificate service object identity.")
        credentials = self.bus_value(["get-property", BUS_NAME, BUS_UNIT_OBJECT, BUS_INTERFACE,
                                     "LoadCredential"], "a(ss)")
        require(credentials == [["server.key", KEY]],
                "The loaded certificate service has unexpected credential mappings.")
        environment_files = self.bus_value(["get-property", BUS_NAME, BUS_UNIT_OBJECT, BUS_INTERFACE,
                                           "EnvironmentFiles"], "a(sb)")
        require(environment_files == [], "The loaded certificate service has unexpected environment files.")

    def configuration(self):
        try:
            config = parse_config(self.file(CONFIG, limit=16384))
            ca = self.file(CA)
            require(re.fullmatch(rb"\s*-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+"
                                 rb"-----END CERTIFICATE-----\s*", ca),
                    "Provide one public CA certificate, never a private key or extra data.")
            self.file(CERT)
            self.file(KEY, private=True)
        except FileNotFoundError:
            raise NotAvailable("Optional host CA download is not configured; install " + CONFIG
                               + " and own ca.crt/server.crt/server.key first.") from None
        details = self.command([OPENSSL, "x509", "-in", str(self.path(CA)), "-noout",
                                "-checkend", "0", "-ext", "basicConstraints"])
        require(re.search(r"(?:^|\s)CA:TRUE(?:\s|,|$)", details),
                "The download certificate must be an unexpired X.509 CA certificate.")
        # Validate only against the explicitly supplied own CA, including the
        # numeric endpoint identity. No system trust store or network fetch.
        self.command([OPENSSL, "verify", "-CAfile", str(self.path(CA)), "-no-CApath", "-no-CAstore",
                      "-purpose", "sslserver", "-verify_ip", config["listen_address"], str(self.path(CERT))])
        return config, ca

    def service(self):
        try:
            require(self.file(UNIT).decode("utf-8") == UNIT_TEXT,
                    "The dedicated host certificate unit differs from its supported definition.")
            self.file(PAYLOAD)
        except FileNotFoundError:
            raise NotAvailable("The separate host CA download service is not installed.") from None
        output = self.command([SYSTEMCTL, "show", SERVICE, "--property=" + ",".join(PROPERTIES)])
        fields = {}
        for line in output.splitlines():
            require("=" in line, "Invalid certificate unit response.")
            key, value = line.split("=", 1)
            require(key not in fields, "Duplicate certificate unit property.")
            fields[key] = value
        expected = {"Id": SERVICE, "LoadState": "loaded", "FragmentPath": UNIT,
                    "DropInPaths": "", "NeedDaemonReload": "no", "DynamicUser": "yes", "Type": "notify",
                    "Environment": "",
                    "RootDirectory": "", "RootImage": "", "PrivateNetwork": "no", "NetworkNamespacePath": "",
                    "NoNewPrivileges": "yes", "ProtectSystem": "strict", "ProtectHome": "yes",
                    "PrivateTmp": "yes", "PrivateDevices": "yes", "RestrictSUIDSGID": "yes",
                    "CapabilityBoundingSet": ""}
        require(all(fields.get(key) == value for key, value in expected.items()),
                "The loaded host certificate service differs or needs daemon-reload.")
        self.structured_unit()
        executable = fields.get("ExecStart", "")
        require(len(re.findall(r"\{ path=", executable)) == 1
                and re.match(r"^\{ path=/usr/bin/python3 ; argv\[\]=/usr/bin/python3 -B "
                             + re.escape(PAYLOAD) + r" --internal-serve ; ignore_errors=no ;", executable),
                "Unexpected host certificate service command.")
        require(fields.get("ActiveState") in ("active", "inactive", "failed")
                and fields.get("UnitFileState") in ("enabled", "disabled"),
                "The host certificate service is not in a stable supported state.")
        return fields

    def inspect(self):
        result = {"available": False, "configured": self.profile.configured, "service": SERVICE,
                  "active_state": "unknown", "unit_file_state": "unknown", "reason": None,
                  "endpoint": None, "ca_sha256": None}
        try:
            unit = self.service()
            result.update(active_state=unit["ActiveState"], unit_file_state=unit["UnitFileState"])
            config, ca = self.configuration()
            address = config["listen_address"]
            authority = "[" + address + "]" if ":" in address else address
            result.update(available=True, active_state=unit["ActiveState"],
                          unit_file_state=unit["UnitFileState"],
                          endpoint=f"https://{authority}:{config['port']}/cert",
                          ca_sha256=hashlib.sha256(ca).hexdigest())
        except NotAvailable as error:
            result["reason"] = str(error)
        return result

    @contextmanager
    def lock(self):
        parent = self.path("/run")
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == self.uid and not info.st_mode & 0o022,
                "Unsafe certificate operation lock directory.")
        fd = os.open(self.path(LOCK), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == self.uid and info.st_nlink == 1
                    and stat.S_IMODE(info.st_mode) == 0o600, "Unsafe certificate operation lock.")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise Error("Another host certificate operation is running.") from None
            require(self.path(LOCK).lstat().st_ino == info.st_ino, "Certificate operation lock changed.")
            yield
        finally:
            os.close(fd)

    def action(self, action):
        self.recheck()
        self.command([SYSTEMCTL, action, SERVICE])

    def change(self, enabled):
        require(type(enabled) is bool, "Invalid certificate action.")
        require(os.geteuid() == 0, "Root privileges are required to switch host CA downloads.")
        require(self.profile.configured, "Install an explicit Kali-host profile before changing downloads.")
        with self.lock():
            self.recheck()
            before = self.service()
            if enabled:
                self.configuration()
            active, boot = before["ActiveState"] == "active", before["UnitFileState"] == "enabled"
            require(before["ActiveState"] != "failed" or not enabled,
                    "Inspect the failed certificate service before enabling it.")
            if active == enabled and boot == enabled:
                return self.inspect(), False
            try:
                if enabled:
                    if not boot:
                        self.action("enable")
                    if not active:
                        self.action("start")  # Type=notify returns only after TLS listener readiness.
                else:
                    if active or before["ActiveState"] == "failed":
                        self.action("stop")
                    if boot:
                        self.action("disable")
                after = self.service()
                require(after["ActiveState"] == ("active" if enabled else "inactive")
                        and after["UnitFileState"] == ("enabled" if enabled else "disabled"),
                        "Certificate service readback differs from the requested setting.")
                return self.inspect(), True
            except (Exception, KeyboardInterrupt) as original:
                failures = []
                for action in ("start" if active else "stop", "enable" if boot else "disable"):
                    try:
                        self.action(action)
                    except Exception:
                        failures.append(action)
                try:
                    restored = self.service()
                    require((restored["ActiveState"] == "active") == active
                            and (restored["UnitFileState"] == "enabled") == boot, "Restoration differs.")
                except Exception:
                    failures.append("readback")
                if failures:
                    raise Error("Certificate operation failed; rollback incomplete (" + ", ".join(failures) + ").") from original
                raise Error("Certificate operation failed; previous service state restored.") from original


def handler_for(ca):
    """Serve only captured public certificate bytes, never filesystem paths."""
    class Download(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_HEAD(self):
            if self.path not in ("/cert", "/automations-ca.crt"):
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/x-x509-ca-cert")
            self.send_header("Content-Disposition", 'attachment; filename="automations-ca.crt"')
            self.send_header("Content-Length", str(len(ca)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()

        def do_GET(self):
            self.do_HEAD()
            if self.path in ("/cert", "/automations-ca.crt"):
                self.wfile.write(ca)

    return Download


def notify_ready():
    address = os.environ.get("NOTIFY_SOCKET", "")
    require(address.startswith(("/", "@")) and len(address) <= 107,
            "The download worker requires its systemd notification socket.")
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as channel:
        channel.connect("\0" + address[1:] if address.startswith("@") else address)
        channel.sendall(b"READY=1")


def server_type(config, context):
    class TLSDownload(HTTPServer):
        address_family = socket.AF_INET6 if ":" in config["listen_address"] else socket.AF_INET

        def server_bind(self):
            # HTTPServer's default getfqdn() may trigger a reverse DNS query.
            # The configured numeric address needs no name resolution.
            TCPServer.server_bind(self)
            self.server_name = config["listen_address"]
            self.server_port = self.server_address[1]

        def get_request(self):
            connection, address = super().get_request()
            try:
                connection.settimeout(5)
                return context.wrap_socket(connection, server_side=True), address
            except BaseException:
                connection.close()
                raise

    return TLSDownload


def credential_acl(path, *, default=False):
    """Read only Linux ACL metadata, never credential contents."""
    try:
        return os.getxattr(path, "system.posix_acl_" + ("default" if default else "access"),
                           follow_symlinks=False)
    except OSError as error:
        if error.errno in (errno.ENODATA, errno.ENOTSUP):
            return None
        raise Error("Cannot safely inspect the service credential ACL.") from None


def credential_access(info, acl, uid, *, directory=False):
    """Accept systemd's exact root/worker ACL or its private-owner fallback.

    systemd v262 write_credential() adds ACL_READ for the service UID to a
    root-owned 0400 file. The resulting 0440 group bits describe the ACL mask;
    they do not give the owning group read access. Check the complete ACL.
    """
    permission = 5 if directory else 4
    mode = permission << 6
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode),
            "Unexpected service credential file type.")
    if acl is None:
        # systemd's fallback on filesystems without POSIX ACL support chowns
        # the credential to the service UID, then remounts it read-only.
        require(info.st_uid == uid and stat.S_IMODE(info.st_mode) == mode,
                "The service credential owner or private mode is invalid.")
        return
    require(isinstance(acl, bytes) and len(acl) == 44 and struct.unpack("<I", acl[:4])[0] == 2,
            "Unsupported service credential ACL.")
    entries = [struct.unpack("<HHI", acl[offset:offset + 8]) for offset in range(4, len(acl), 8)]
    undefined = 0xffffffff
    expected = [(1, permission, undefined), (2, permission, uid),
                (4, 0, undefined), (16, permission, undefined), (32, 0, undefined)]
    require(info.st_uid == 0 and info.st_gid == 0
            and stat.S_IMODE(info.st_mode) == mode | (permission << 3) and entries == expected,
            "The service credential ACL must allow only root and this worker.")


def credential_mount(content, info):
    """Require this service's exact private read-only memory-filesystem mount."""
    require(isinstance(content, str) and len(content) <= 1024 * 1024,
            "Invalid service credential mount metadata.")
    matches = []
    for line in content.splitlines():
        fields = line.split()
        if len(fields) < 6 or fields[4] != CREDENTIALS:
            continue
        try:
            separator = fields.index("-", 6)
        except ValueError:
            raise Error("Invalid service credential mount metadata.") from None
        require(separator + 3 < len(fields), "Invalid service credential mount metadata.")
        matches.append((fields, separator))
    require(len(matches) == 1, "The service credential requires its exact private mount.")
    fields, separator = matches[0]
    require(fields[2] == str(os.major(info.st_dev)) + ":" + str(os.minor(info.st_dev))
            and fields[3] == "/" and {"ro", "nosuid", "nodev", "noexec"} <= set(fields[5].split(","))
            and fields[separator + 1] in ("tmpfs", "ramfs")
            and "ro" in fields[separator + 3].split(","),
            "The service credential mount must be a protected read-only memory filesystem.")


def credential_file():
    directory = Path(CREDENTIALS)
    for parent in directory.parents:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                "Unsafe service credential parent.")
    info = directory.lstat()
    credential_access(info, credential_acl(directory), os.geteuid(), directory=True)
    require(credential_acl(directory, default=True) is None,
            "The service credential directory must not have a default ACL.")
    credential_mount(Path("/proc/self/mountinfo").read_text(encoding="utf-8"), info)
    require(os.statvfs(directory).f_flag & os.ST_RDONLY, "The service credential mount is writable.")
    credential = directory / "server.key"
    key_info = credential.lstat()
    require(key_info.st_nlink == 1 and key_info.st_dev == info.st_dev
            and 0 < key_info.st_size <= 1024 * 1024, "Invalid service credential file.")
    credential_access(key_info, credential_acl(credential), os.geteuid())
    return credential


def serve(backend):
    require(os.geteuid() != 0 and os.environ.get("CREDENTIALS_DIRECTORY") == CREDENTIALS,
            "The internal download worker requires its unprivileged credential service.")
    cgroup = Path("/proc/self/cgroup").read_text(encoding="utf-8")
    require(any(line.rsplit(":", 1)[-1].endswith("/" + SERVICE) for line in cgroup.splitlines()),
            "The internal download worker requires its fixed system service.")
    require(backend.profile.configured, "The host profile must be explicitly installed.")
    config, ca = backend.configuration()
    credential = credential_file()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(backend.path(CERT)), str(credential))

    with server_type(config, context)((config["listen_address"], config["port"]), handler_for(ca)) as server:
        notify_ready()
        server.serve_forever()


def print_status(value):
    print("Host CA downloads: " + ("configured" if value["available"] else "unavailable"))
    print("Dedicated service: " + value["active_state"] + "; boot " + value["unit_file_state"])
    if value["reason"]:
        print("Setup required: " + value["reason"])
    if value["endpoint"]:
        print("Own download endpoint: " + value["endpoint"])
        print("Public CA file SHA-256: " + value["ca_sha256"])
    print("No CA was generated or installed into any trust store; no existing web server was changed.")
    print("Status reports local configuration/service state, not client trust or a live HTTPS probe.")


def main(argv=None, *, profile_loader=None, backend_factory=HostCert):
    args = list(sys.argv[1:] if argv is None else argv)
    loader = load_profile if profile_loader is None else profile_loader
    parser = argparse.ArgumentParser(prog="auto cert", description=__doc__)
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--on", action="store_true", help="Enable and start only the optional own CA download service")
    actions.add_argument("--off", action="store_true", help="Stop and disable that separate service")
    actions.add_argument("--status", action="store_true", help="Show optional own CA configuration and service state")
    try:
        if args == ["--internal-serve"]:
            serve(backend_factory(loader(), profile_loader=loader))
            return 0
        parsed = parser.parse_args(args)
        backend = backend_factory(loader(), profile_loader=loader)
        if parsed.on or parsed.off:
            value, _ = backend.change(parsed.on)
            print_status(value)
            return 0
        value = backend.inspect()
        print_status(value)
        return 0 if value["available"] else 3
    except NotAvailable as error:
        print("Unavailable: " + str(error), file=sys.stderr)
        return 3
    except (Error, OSError, ValueError, TypeError, subprocess.SubprocessError):
        error = sys.exc_info()[1]
        print("ERROR: " + (str(error) if isinstance(error, Error) else
                          "Cannot safely inspect or control host CA downloads."), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("ERROR: Certificate operation interrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
