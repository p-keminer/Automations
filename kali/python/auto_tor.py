#!/usr/bin/env python3
"""Optional Tor client and fresh TorDNSEL exit-address verification."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import datetime as dt
import errno
import fcntl
import grp
import hashlib
import hmac
import http.client
import importlib.util
import ipaddress
import json
import math
import multiprocessing
import os
from pathlib import Path
import pwd
import re
import secrets
import socket
import ssl
import stat
import struct
import subprocess
import sys
import tempfile
import time

HOST = "check.torproject.org"
LIST_PATH = "/exit-addresses"
IP_PATH = "/api/ip"
LIST_URL = "https://" + HOST + LIST_PATH
IP_URL = "https://" + HOST + IP_PATH
STORE = Path("/var/lib/automations/tor-exits.json")
LOCK = Path("/run/automations-tor-check.lock")
SUPPORT = Path("/usr/local/libexec/automations-support/egress.py")
SERVICE = "automations-tor.service"
ROTATION_SERVICE = "automations-tor-rotation.service"
RECOVERY_SERVICE = "automations-tor-recovery.service"
RECOVERY_TIMER = "automations-tor-recovery.timer"
RUNTIME = "/usr/local/libexec/automations/tor"
CONTROL_DIR = Path("/run/automations-tor")
CONTROL_SOCKET = CONTROL_DIR / "control"
CONTROL_COOKIE = CONTROL_DIR / "control.authcookie"
ROTATION_LOCK = CONTROL_DIR / "rotation.lock"
ACCOUNT = "auto-tor"
TORRC = Path("/usr/local/share/automations/tor/torrc")
SYSUSERS = Path("/usr/local/share/automations/tor/tor-user.conf")
UNIT = Path("/etc/systemd/system/automations-tor.service")
RECOVERY_UNIT = UNIT.with_name(RECOVERY_SERVICE)
RECOVERY_TIMER_UNIT = UNIT.with_name(RECOVERY_TIMER)
DEFINITION_HASHES = {
    TORRC: "20a35637a158a4c24eb463c74fb84c4853ed9ee0c108407cabb01bcd5f2c35a0",
    SYSUSERS: "eb2f673178164700d52912d57d2db84fbba9a0aa663eebe7669b8fa10757eee7",
    UNIT: "2b28dcca5e08141f47e9f296f9ec22078664165624f38d089942a3210426fd0b",
    RECOVERY_UNIT: "8462af147d8463f2b2250d5370a46015d2adeb14b03cc540d9d21de2d8271f24",
    RECOVERY_TIMER_UNIT: "3bfb36f954d41a1954f50af67771955e6cae946b27eec99e344998144dfa5330",
}
MAX_LIST = 4 * 1024 * 1024
MAX_RECORDS = 25000
# Local acceptance policy, not a guarantee of complete Tor-network coverage.
MAX_SOURCE_AGE = 6 * 60 * 60
MAX_OBSERVATION_AGE = 24 * 60 * 60
FUTURE_SKEW = 5 * 60
HTTP_TIMEOUT = 40
NEWNYM_MINIMUM = 10
HTTPS_PHASES = (
    "starting the HTTPS worker", "resolving the endpoint", "connecting TCP",
    "connecting through Tor SOCKS", "negotiating TLS", "sending the HTTP request",
    "waiting for HTTP headers", "downloading the response body",
)


class Error(RuntimeError):
    pass


class _RetryableTransportError(Error):
    """Internal marker for a fixed idempotent GET interrupted in transport."""


def retryable_transport(error):
    if isinstance(error, ssl.SSLCertVerificationError):
        return False
    if isinstance(error, socket.gaierror):
        return error.errno == socket.EAI_AGAIN
    if isinstance(error, http.client.IncompleteRead):
        return True
    if isinstance(error, (TimeoutError, ConnectionError, ssl.SSLEOFError, http.client.RemoteDisconnected)):
        return True
    return isinstance(error, OSError) and error.errno in (
        errno.ECONNRESET, errno.ECONNABORTED, errno.EPIPE, errno.ETIMEDOUT)


# Only the exception class loaded from verified shared-runtime bytes may expose text.
_SHARED_RUNTIME_ERROR = None
_SHARED_RUNTIME_BUSY = None


def require(ok, message):
    if not ok:
        raise Error(message)


def utc_now():
    return dt.datetime.now(dt.timezone.utc)


def timestamp(value):
    return value.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def source_time(value):
    require(bool(re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", value)),
            "The Tor exit list contains an invalid timestamp.")
    try:
        return dt.datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(tzinfo=dt.timezone.utc)
    except ValueError as exc:
        raise Error("The Tor exit list contains an invalid timestamp.") from exc


def public_ip(value):
    require(isinstance(value, str) and len(value) <= 45 and "%" not in value,
            "A public IPv4 or IPv6 address is required.")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise Error("A public IPv4 or IPv6 address is required.") from exc
    require(address.is_global and not address.is_multicast and not address.is_unspecified
            and not address.is_reserved and not address.is_loopback and not address.is_link_local,
            "A public IPv4 or IPv6 address is required.")
    return address


def parse_exit_list(raw, now):
    """Parse the timestamped TorDNSEL format, never HTML/plain bulk-IP data."""
    require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_LIST,
            "The Tor exit list is empty or exceeds the size limit.")
    try:
        lines = raw.decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise Error("The Tor exit list is not valid ASCII data.") from exc
    require(len(lines) <= MAX_RECORDS * 8, "The Tor exit list exceeds the record limit.")
    records = []
    record = None
    seen_nodes = set()
    for line in lines:
        require(len(line) <= 256, "The Tor exit list contains an oversized line.")
        if not line:
            continue
        if line == "@type tordnsel 1.0" and record is None and not records:
            continue
        if line.startswith("ExitNode "):
            if record is not None:
                require(set(record) == {"node", "published", "status", "addresses"} and record["addresses"],
                        "The Tor exit list contains an incomplete record.")
                records.append(record)
            node = line[9:]
            require(bool(re.fullmatch(r"[A-Fa-f0-9]{40}", node)) and node.upper() not in seen_nodes,
                    "The Tor exit list contains an invalid or duplicate relay.")
            seen_nodes.add(node.upper())
            require(len(seen_nodes) <= MAX_RECORDS, "The Tor exit list exceeds the record limit.")
            record = {"node": node.upper(), "addresses": []}
        elif line.startswith("Published ") or line.startswith("LastStatus "):
            key = "published" if line.startswith("Published ") else "status"
            require(record is not None and key not in record and not record["addresses"],
                    "The Tor exit list contains misplaced timestamps.")
            value = source_time(line.split(" ", 1)[1])
            require((value - now).total_seconds() <= FUTURE_SKEW,
                    "The Tor exit list contains future-dated source data; check the system clock.")
            record[key] = value
        elif line.startswith("ExitAddress "):
            require(record is not None and "published" in record and "status" in record,
                    "The Tor exit list contains an address without source timestamps.")
            parts = line.split(" ")
            require(len(parts) == 4, "The Tor exit list contains a malformed address record.")
            address, observed = public_ip(parts[1]), source_time(" ".join(parts[2:]))
            # This source is an observed IPv4 exit set. Do not infer IPv6 coverage.
            require(address.version == 4, "The Tor exit list has an unsupported address-family format.")
            require((observed - now).total_seconds() <= FUTURE_SKEW,
                    "The Tor exit list contains future-dated exit observations; check the system clock.")
            record["addresses"].append((str(address), observed))
            require(len(record["addresses"]) <= 128, "The Tor exit list has too many addresses for one relay.")
        else:
            raise Error("The Tor exit list contains an unrecognized record.")
    require(record is not None and set(record) == {"node", "published", "status", "addresses"}
            and record["addresses"], "The Tor exit list is empty or incomplete.")
    records.append(record)
    source_at = max(item["status"] for item in records)
    require((now - source_at).total_seconds() <= MAX_SOURCE_AGE,
            "The Tor exit list source data is older than six hours.")
    addresses = {}
    for item in records:
        if (now - item["status"]).total_seconds() > MAX_OBSERVATION_AGE:
            continue
        for address, observed in item["addresses"]:
            if (now - observed).total_seconds() <= MAX_OBSERVATION_AGE:
                addresses[address] = max(observed, addresses.get(address, observed))
    require(addresses, "The Tor exit list has no IPv4 observations from the last 24 hours.")
    return {"version": 1, "source": LIST_URL, "fetched_at": timestamp(now),
            "source_at": timestamp(source_at), "raw_sha256": hashlib.sha256(raw).hexdigest(),
            "coverage": "observed-ipv4", "addresses": {
                key: timestamp(addresses[key]) for key in sorted(addresses, key=ipaddress.ip_address)}}


def read_exact(stream, count):
    chunks = []
    while count:
        block = stream.recv(count)
        if not block:
            raise _RetryableTransportError("The Tor SOCKS connection ended unexpectedly.")
        chunks.append(block)
        count -= len(block)
    return b"".join(chunks)


def socks_socket(timeout):
    """Only the fixed local Tor SOCKS endpoint; hostname resolution is remote."""
    stream = socket.create_connection(("127.0.0.1", 19050), timeout=timeout)
    try:
        stream.sendall(b"\x05\x01\x00")
        require(read_exact(stream, 2) == b"\x05\x00", "The Tor SOCKS endpoint rejected the request.")
        name = HOST.encode("ascii")
        stream.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + struct.pack("!H", 443))
        reply = read_exact(stream, 4)
        require(reply[:3] == b"\x05\x00\x00", "The Tor SOCKS connection could not be established.")
        if reply[3] == 1:
            read_exact(stream, 4)
        elif reply[3] == 4:
            read_exact(stream, 16)
        elif reply[3] == 3:
            read_exact(stream, read_exact(stream, 1)[0])
        else:
            raise Error("The Tor SOCKS endpoint returned an invalid address type.")
        read_exact(stream, 2)
        return stream
    except BaseException:
        stream.close()
        raise


def ipv4_connection(address, timeout, source_address=None, phase=None):
    """Use the current IPv4 route, never wait for blocked application IPv6 first."""
    require(address == (HOST, 443) and source_address is None, "The requested HTTPS destination is not allowed.")
    deadline = time.monotonic() + timeout
    if phase:
        phase(1)
    endpoints = socket.getaddrinfo(HOST, 443, socket.AF_INET, socket.SOCK_STREAM)
    last = None
    for family, kind, protocol, _, peer in endpoints[:8]:
        require(family == socket.AF_INET and kind == socket.SOCK_STREAM and public_ip(peer[0]).version == 4,
                "The Tor Project endpoint did not resolve to a public IPv4 address.")
        remaining = deadline - time.monotonic()
        require(remaining > 0, "The Tor Project IPv4 connection exceeded its deadline.")
        stream = socket.socket(family, kind, protocol)
        try:
            stream.settimeout(remaining)
            if phase:
                phase(2)
            stream.connect(peer)
            if phase:
                phase(4)
            return stream
        except OSError as exc:
            last = exc
            stream.close()
    if retryable_transport(last):
        raise _RetryableTransportError("The Tor Project IPv4 transport was interrupted.") from last
    raise Error("Unable to connect to the Tor Project endpoint through the current IPv4 route.") from last


class HTTPS:
    def __init__(self, socks=False, timeout=HTTP_TIMEOUT):
        self.socks = socks
        self.timeout = timeout

    def _phase(self, value):
        progress = getattr(self, "_progress", None)
        if progress is not None:
            progress.value = value

    def get(self, path, limit):
        require(path in (LIST_PATH, IP_PATH), "The requested endpoint is not allowed.")
        require(type(limit) is int and 0 < limit <= MAX_LIST, "Invalid Tor HTTPS response limit.")
        # A socket timeout alone does not bound getaddrinfo or a slow HTTP-header
        # stream. Keep this entire fixed request in one killable same-UID child.
        context = multiprocessing.get_context("fork")
        progress = context.RawValue("B", 0)
        receive, send = context.Pipe(duplex=False)
        worker = context.Process(target=https_fetch_child, args=(self, path, limit, send, progress), daemon=True)
        try:
            worker.start()
        except BaseException:
            receive.close()
            send.close()
            worker.close()
            raise
        send.close()
        try:
            require(receive.poll(self.timeout),
                    "The Tor Project HTTPS request exceeded its total deadline while "
                    + HTTPS_PHASES[progress.value] + ".")
            try:
                packet = receive.recv_bytes(limit + 8192)
            except (EOFError, OSError) as exc:
                raise Error("The Tor Project HTTPS request could not complete safely.") from exc
            require(packet and packet[:1] in (b"+", b"!"), "Invalid internal HTTPS worker response.")
            if packet[:1] == b"!":
                raise Error(packet[1:].decode("utf-8", errors="replace"))
            require(0 < len(packet) - 1 <= limit, "Invalid internal HTTPS worker response size.")
            return packet[1:]
        finally:
            receive.close()
            if worker.is_alive():
                worker.terminate()
            worker.join(1)
            if worker.is_alive():
                worker.kill()
                worker.join()
            worker.close()

    def _get(self, path, limit):
        require(path in (LIST_PATH, IP_PATH), "The requested endpoint is not allowed.")
        deadline = time.monotonic() + self.timeout
        for attempt in range(3):
            require(time.monotonic() < deadline, "The Tor Project HTTPS request exceeded its total deadline.")
            try:
                return self._get_once(path, limit, deadline)
            except _RetryableTransportError as error:
                if attempt == 2:
                    raise Error("Unable to reach the Tor Project HTTPS endpoint after three transport attempts. "
                                "Last failure: " + str(error)) from error

    def _get_once(self, path, limit, deadline):
        remaining = deadline - time.monotonic()
        require(remaining > 0, "The Tor Project HTTPS request exceeded its total deadline.")
        connection = http.client.HTTPSConnection(HOST, 443, timeout=remaining,
                                                   context=ssl.create_default_context())
        connection._create_connection = lambda *args, **kwargs: ipv4_connection(*args, phase=self._phase, **kwargs)
        try:
            if self.socks:
                self._phase(3)
                raw = socks_socket(remaining)
                try:
                    self._phase(4)
                    connection.sock = connection._context.wrap_socket(raw, server_hostname=HOST)
                except BaseException:
                    raw.close()
                    raise
            else:
                connection.connect()
            # http.client never uses proxy environment variables or follows redirects.
            self._phase(5)
            connection.request("GET", path, headers={"Accept": "application/json" if path == IP_PATH else "text/plain",
                                                      "Accept-Encoding": "identity", "Cache-Control": "no-cache",
                                                      "User-Agent": "Automations-Tor/0.1.0"})
            self._phase(6)
            response = connection.getresponse()
            require(response.status == 200, "The Tor Project HTTPS endpoint returned an unsuccessful response.")
            require(response.getheader("Content-Encoding", "identity") == "identity",
                    "The Tor Project HTTPS endpoint returned unsupported content encoding.")
            length = response.getheader("Content-Length")
            require(length is None or (length.isdecimal() and int(length) <= limit),
                    "The Tor Project HTTPS response exceeds the size limit.")
            chunks, size = [], 0
            self._phase(7)
            while size <= limit:
                remaining = deadline - time.monotonic()
                require(remaining > 0, "The Tor Project HTTPS response exceeded the download deadline.")
                # getresponse() may close connection.sock while its response
                # file still owns the body. The parent bounds the entire read.
                block = response.read1(min(65536, limit + 1 - size))
                if not block:
                    break
                chunks.append(block)
                size += len(block)
            data = b"".join(chunks)
            require(len(data) <= limit, "The Tor Project HTTPS response exceeds the size limit.")
            if length is not None and len(data) != int(length):
                raise _RetryableTransportError("The Tor Project HTTPS response was truncated in transport.")
            require(data, "The Tor Project HTTPS response is empty.")
            return data
        except Error:
            raise
        except ssl.SSLCertVerificationError as exc:
            raise Error("Unable to verify the Tor Project HTTPS certificate.") from exc
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            if retryable_transport(exc):
                raise _RetryableTransportError("The Tor Project HTTPS transport was interrupted.") from exc
            raise Error("Unable to reach the Tor Project HTTPS endpoint securely.") from exc
        finally:
            connection.close()


def https_fetch_child(fetcher, path, limit, output, progress=None):
    fetcher._progress = progress
    try:
        output.send_bytes(b"+" + fetcher._get(path, limit))
    except Error as exc:
        output.send_bytes(b"!" + str(exc).encode("utf-8")[:4096])
    except Exception:
        output.send_bytes(b"!Unable to complete the Tor Project HTTPS request securely.")
    finally:
        output.close()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "The JSON response contains duplicate fields.")
        result[key] = value
    return result


def observe_ip(fetcher):
    try:
        value = json.loads(fetcher.get(IP_PATH, 16384), object_pairs_hook=unique_object)
        require(isinstance(value, dict) and set(value) == {"IP", "IsTor"}
                and type(value["IsTor"]) is bool, "The public-IP endpoint returned an invalid response.")
        address = public_ip(value["IP"])
        return {"ip": str(address), "tor_reported": value["IsTor"], "observed_at": timestamp(utc_now())}
    except (ValueError, UnicodeError) as exc:
        raise Error("The public-IP endpoint returned invalid JSON.") from exc


def trusted_directory(path):
    for parent in reversed((path, *path.parents)):
        metadata = parent.lstat()
        require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == 0
                and not metadata.st_mode & 0o022, "An Automations directory is not trusted.")


def trusted_read(path, limit=MAX_LIST):
    trusted_directory(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        meta = os.fstat(fd)
        require(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and meta.st_nlink == 1
                and not meta.st_mode & 0o022 and meta.st_size <= limit,
                "An Automations file is not trusted.")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            value = stream.read(limit + 1)
        require(len(value) <= limit, "An Automations file exceeds the size limit.")
        return value
    finally:
        os.close(fd)


def installed_definition(path):
    require(hashlib.sha256(trusted_read(path, 16384)).hexdigest() == DEFINITION_HASHES[path],
            "An installed Tor definition differs from this supported component version.")


def interval(value):
    match = re.fullmatch(r"([1-9][0-9]{0,5})([smh])", value)
    require(match is not None, "Rotation interval must use s, m or h (30 seconds to 24 hours).")
    seconds = int(match[1]) * {"s": 1, "m": 60, "h": 3600}[match[2]]
    require(30 <= seconds <= 86400, "Rotation interval must be between 30 seconds and 24 hours.")
    return seconds


def control_identity():
    uid = pwd.getpwnam(ACCOUNT).pw_uid
    require(0 < uid < 65534, "The dedicated Tor account is invalid.")
    trusted_directory(CONTROL_DIR.parent)
    directory = CONTROL_DIR.lstat()
    require(stat.S_ISDIR(directory.st_mode) and directory.st_uid == uid
            and stat.S_IMODE(directory.st_mode) == 0o700, "The Tor control directory is not trusted.")
    endpoint = CONTROL_SOCKET.lstat()
    require(stat.S_ISSOCK(endpoint.st_mode) and endpoint.st_uid == uid
            and not endpoint.st_mode & 0o077, "The local Tor control socket is not trusted.")
    fd = os.open(CONTROL_COOKIE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        metadata = os.fstat(fd)
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == uid and metadata.st_nlink == 1
                and metadata.st_size == 32 and not metadata.st_mode & 0o077,
                "The local Tor control cookie is not trusted.")
        cookie = os.read(fd, 33)
        require(len(cookie) == 32, "The local Tor control cookie has an invalid size.")
    finally:
        os.close(fd)
    return uid, cookie


class Control:
    """Small fixed SAFECOOKIE/NEWNYM client; no arbitrary control command API."""
    def __init__(self, stream, cookie, nonce=None, monotonic=time.monotonic):
        self.stream, self.cookie = stream, cookie
        self.nonce = nonce or secrets.token_bytes(32)
        self.monotonic, self.buffer = monotonic, bytearray()

    def line(self, deadline):
        while b"\r\n" not in self.buffer:
            remaining = deadline - self.monotonic()
            require(remaining > 0, "Tor did not confirm NEWNYM; its rate limit may have deferred or ignored the request.")
            self.stream.settimeout(remaining)
            try:
                block = self.stream.recv(1024)
            except socket.timeout as exc:
                raise Error("Tor did not confirm NEWNYM; its rate limit may have deferred or ignored the request.") from exc
            require(block, "The local Tor control connection ended unexpectedly.")
            self.buffer.extend(block)
            require(len(self.buffer) <= 8192, "The local Tor control reply exceeded the size limit.")
        line, _, rest = self.buffer.partition(b"\r\n")
        self.buffer = bytearray(rest)
        require(len(line) <= 4096, "The local Tor control reply exceeded the line limit.")
        return bytes(line)

    def authenticate(self):
        deadline = self.monotonic() + 5
        self.stream.sendall(b"AUTHCHALLENGE SAFECOOKIE " + self.nonce.hex().encode() + b"\r\n")
        response = self.line(deadline)
        match = re.fullmatch(rb"250 AUTHCHALLENGE SERVERHASH=([A-Fa-f0-9]{64}) SERVERNONCE=([A-Fa-f0-9]{64})", response)
        require(match is not None, "The Tor control endpoint rejected SAFECOOKIE authentication.")
        server_nonce = bytes.fromhex(match[2].decode())
        payload = self.cookie + self.nonce + server_nonce
        expected = hmac.digest(b"Tor safe cookie authentication server-to-controller hash", payload, "sha256")
        require(hmac.compare_digest(expected, bytes.fromhex(match[1].decode())),
                "The Tor control endpoint failed its SAFECOOKIE identity check.")
        proof = hmac.digest(b"Tor safe cookie authentication controller-to-server hash", payload, "sha256")
        self.stream.sendall(b"AUTHENTICATE " + proof.hex().encode() + b"\r\n")
        require(self.line(deadline) == b"250 OK", "Tor control authentication failed.")
        self.stream.sendall(b"SETEVENTS SIGNAL\r\n")
        require(self.line(deadline) == b"250 OK", "Tor refused NEWNYM confirmation events.")

    def newnym(self):
        self.stream.sendall(b"SIGNAL NEWNYM\r\n")
        deadline, acknowledged, acted = self.monotonic() + 15, False, False
        for _ in range(16):
            response = self.line(deadline)
            if response == b"250 OK":
                acknowledged = True
            elif response == b"650 SIGNAL NEWNYM":
                acted = True
            elif response.startswith(b"650 SIGNAL "):
                continue
            else:
                raise Error("Tor rejected the NEWNYM request.")
            if acknowledged and acted:
                return
        raise Error("Tor did not confirm the NEWNYM action within the reply limit.")


def rotate_client(identity=control_identity, connector=None, monotonic=time.monotonic):
    uid, cookie = identity()
    fd = os.open(ROTATION_LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        metadata = os.fstat(fd)
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
                and stat.S_IMODE(metadata.st_mode) == 0o600 and metadata.st_size <= 64,
                "The Tor rotation lock is not trusted.")
        if metadata.st_uid == 0 and os.geteuid() == 0 and metadata.st_size == 0:
            os.fchown(fd, uid, pwd.getpwnam(ACCOUNT).pw_gid)
            metadata = os.fstat(fd)
        require(stat.S_ISREG(metadata.st_mode) and metadata.st_uid == uid and metadata.st_nlink == 1
                and stat.S_IMODE(metadata.st_mode) == 0o600 and metadata.st_size <= 64,
                "The Tor rotation lock is not trusted.")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Error("Another Tor rotation request is running.") from exc
        raw = os.read(fd, 65)
        now = monotonic()
        if raw:
            try:
                previous = float(raw)
            except ValueError as exc:
                raise Error("The Tor rotation rate-limit record is invalid.") from exc
            require(math.isfinite(previous) and 0 <= previous <= now, "The Tor rotation rate-limit record is invalid.")
            remaining = NEWNYM_MINIMUM - (now - previous)
            require(remaining <= 0, f"Tor rotation is rate-limited. Wait {max(1, math.ceil(remaining))} seconds.")
        stream = connector() if connector else socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            if connector is None:
                stream.settimeout(5)
                stream.connect(str(CONTROL_SOCKET))
            control = Control(stream, cookie, monotonic=monotonic)
            control.authenticate()
            os.lseek(fd, 0, os.SEEK_SET)
            os.ftruncate(fd, 0)
            os.write(fd, str(monotonic()).encode("ascii"))
            os.fsync(fd)
            control.newnym()
            # Start the shared minimum interval at the confirmed action, including
            # any delay imposed by Tor, not at connection/authentication time.
            os.lseek(fd, 0, os.SEEK_SET)
            os.ftruncate(fd, 0)
            os.write(fd, str(monotonic()).encode("ascii"))
            os.fsync(fd)
        finally:
            stream.close()
    finally:
        os.close(fd)


def rotation_worker(seconds, rotate=rotate_client, sleep=time.sleep):
    require(type(seconds) is int and 30 <= seconds <= 86400, "Invalid rotation worker interval.")
    require(os.geteuid() == pwd.getpwnam(ACCOUNT).pw_uid and os.geteuid() != 0,
            "The rotation worker must run as the dedicated Tor account.")
    while True:
        sleep(seconds)
        try:
            rotate()
        except (Error, OSError) as exc:
            print("ERROR: " + (str(exc) if isinstance(exc, Error) else "The Tor rotation request failed."), file=sys.stderr, flush=True)


class ExitStore:
    def __init__(self, path=STORE, lock=LOCK):
        self.path, self.lock_path = Path(path), Path(lock)

    @contextmanager
    def locked(self):
        trusted_directory(self.lock_path.parent)
        fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            meta = os.fstat(fd)
            require(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and meta.st_nlink == 1
                    and stat.S_IMODE(meta.st_mode) == 0o600, "The Tor exit-list lock is not trusted.")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise Error("Another Tor exit-list check is running.") from exc
            yield
        finally:
            os.close(fd)

    def current(self):
        try:
            return trusted_read(self.path)
        except FileNotFoundError:
            return None

    def replace(self, value):
        trusted_directory(self.path.parent.parent)
        try:
            self.path.parent.mkdir(mode=0o755)
        except FileExistsError:
            pass
        trusted_directory(self.path.parent)
        old = self.current()
        raw = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("ascii")
        require(len(raw) <= MAX_LIST, "The normalized Tor exit list exceeds the size limit.")
        fd, filename = tempfile.mkstemp(prefix=".tor-exits-", dir=self.path.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                os.fchmod(stream.fileno(), 0o644)
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            require(self.current() == old, "The Tor exit-list file changed concurrently; update refused.")
            os.replace(filename, self.path)
            directory = os.open(self.path.parent, os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(filename):
                os.unlink(filename)

    def describe(self):
        raw = self.current()
        if raw is None:
            return "Exit list: not downloaded\nExit list path: " + str(self.path)
        try:
            value = json.loads(raw, object_pairs_hook=unique_object)
            require(isinstance(value, dict) and value.get("version") == 1 and value.get("source") == LIST_URL
                    and value.get("coverage") == "observed-ipv4" and isinstance(value.get("addresses"), dict),
                    "The stored Tor exit-list metadata is invalid.")
            for key in ("source_at", "fetched_at"):
                require(isinstance(value.get(key), str)
                        and bool(re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value[key])),
                        "The stored Tor exit-list timestamp is invalid.")
            return (f"Exit list path: {self.path}\nExit list source: {LIST_URL}\n"
                    f"Stored source time: {value['source_at']}\nLast downloaded: {value['fetched_at']}\n"
                    "Stored data has not been verified by this status request.")
        except (ValueError, UnicodeError) as exc:
            raise Error("The stored Tor exit-list metadata is invalid.") from exc


def check_exit(fetcher, store, supplied_ip=None, now=None):
    requested = public_ip(supplied_ip) if supplied_ip is not None else None
    with store.locked():
        try:
            raw = fetcher.get(LIST_PATH, MAX_LIST)
        except Error as exc:
            raise Error("Unable to download the Tor exit list securely. No previous list was used. Reason: " + str(exc)) from exc
        value = parse_exit_list(raw, now or utc_now())
        store.replace(value)
        address = requested or public_ip(observe_ip(fetcher)["ip"])
        require(address.version == 4,
                "The fresh TorDNSEL list covers observed IPv4 exits only; this IPv6 address cannot be checked.")
        found = str(address) in value["addresses"]
        return {"result": "VERIFIED" if found else "NOT LISTED", "ip": str(address),
                "source": LIST_URL, "source_at": value["source_at"], "fetched_at": value["fetched_at"]}


def load_egress():
    global _SHARED_RUNTIME_ERROR, _SHARED_RUNTIME_BUSY
    _SHARED_RUNTIME_ERROR = None
    _SHARED_RUNTIME_BUSY = None
    raw = trusted_read(SUPPORT, 512 * 1024)
    spec = importlib.util.spec_from_file_location("automations_egress", SUPPORT)
    require(spec is not None and spec.loader is not None, "The optional anonymity runtime is unavailable.")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    exec(compile(raw, str(SUPPORT), "exec"), module.__dict__)
    error_type = getattr(module, "Error", None)
    require(isinstance(error_type, type) and issubclass(error_type, RuntimeError),
            "The anonymity runtime has an unsupported error interface.")
    busy_type = getattr(module, "Busy", None)
    require(busy_type is None or isinstance(busy_type, type) and busy_type is not error_type
            and issubclass(busy_type, error_type) and getattr(module.Runtime, "Busy", None) is busy_type,
            "The anonymity runtime has an unsupported lock interface.")
    _SHARED_RUNTIME_ERROR = error_type
    _SHARED_RUNTIME_BUSY = busy_type
    return module


class Platform:
    def run(self, args, timeout=35, accepted=(0,)):
        try:
            result = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                    timeout=timeout, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise Error("A required Tor service command failed or timed out.") from exc
        require(result.returncode in accepted, "A required Tor service command failed.")
        return result.stdout

    def account(self):
        installed_definition(SYSUSERS)
        self.run(["systemd-sysusers", str(SYSUSERS)])
        entry = pwd.getpwnam(ACCOUNT)
        require(0 < entry.pw_uid < 65534 and entry.pw_dir == "/var/lib/automations-tor"
                and entry.pw_shell == "/usr/sbin/nologin", "The dedicated Tor account does not match its definition.")
        require(entry.pw_uid != pwd.getpwnam("kali").pw_uid, "The Tor account must be separate from the login account.")
        group = grp.getgrnam(ACCOUNT)
        require(group.gr_gid == entry.pw_gid and not group.gr_mem
                and [item.pw_name for item in pwd.getpwall() if item.pw_uid == entry.pw_uid] == [ACCOUNT],
                "The Tor account or group is shared with another account.")
        home = Path(entry.pw_dir)
        try:
            meta = home.lstat()
        except FileNotFoundError:
            pass
        else:
            require(stat.S_ISDIR(meta.st_mode) and meta.st_uid == entry.pw_uid and meta.st_gid == entry.pw_gid
                    and stat.S_IMODE(meta.st_mode) == 0o700, "The Tor data directory is not owned exclusively by its account.")
        return entry.pw_uid

    def definition(self):
        installed_definition(UNIT)
        installed_definition(TORRC)
        values = dict(line.split("=", 1) for line in self.run([
            "systemctl", "show", SERVICE, "--property=FragmentPath,DropInPaths,NeedDaemonReload"]).splitlines() if "=" in line)
        require(values.get("FragmentPath") == str(UNIT) and values.get("DropInPaths") == ""
                and values.get("NeedDaemonReload") == "no", "The Tor service definition is not the supported installed unit.")

    def recovery_definition(self):
        for path in (RECOVERY_UNIT, RECOVERY_TIMER_UNIT):
            installed_definition(path)
            values = dict(line.split("=", 1) for line in self.run([
                "systemctl", "show", path.name, "--property=FragmentPath,DropInPaths,NeedDaemonReload"
            ]).splitlines() if "=" in line)
            require(values.get("FragmentPath") == str(path) and values.get("DropInPaths") == ""
                    and values.get("NeedDaemonReload") == "no",
                    "The Tor recovery definition is not the supported installed unit.")

    def recovery_enabled(self):
        self.recovery_definition()
        value = self.run(["systemctl", "show", RECOVERY_TIMER, "--property=ActiveState", "--value"]).strip()
        require(value in ("active", "inactive", "failed", "activating", "deactivating"),
                "The Tor recovery timer state could not be observed.")
        return value == "active"

    def recovery_start(self):
        self.recovery_definition()
        self.run(["systemctl", "start", RECOVERY_TIMER])
        require(self.recovery_enabled(), "Automatic Tor recovery did not become active.")

    def recovery_stop(self):
        self.recovery_definition()
        # A probe already in flight may finish. It must recheck the timer,
        # guard and service invocation under the shared lock before publishing.
        self.run(["systemctl", "stop", RECOVERY_TIMER])

    def start(self):
        self.definition()
        self.run(["systemctl", "start", SERVICE])

    def stop(self):
        self.definition()
        self.run(["systemctl", "stop", SERVICE])

    def active(self):
        values = dict(line.split("=", 1) for line in self.run([
            "systemctl", "show", SERVICE, "--property=ActiveState,MainPID"]).splitlines() if "=" in line)
        require(values.get("ActiveState") in ("active", "inactive", "failed", "activating", "deactivating")
                and values.get("MainPID", "").isdecimal(), "The Tor service state could not be observed.")
        return values["ActiveState"] == "active" and int(values["MainPID"]) > 0

    def generation(self):
        values = dict(line.split("=", 1) for line in self.run([
            "systemctl", "show", SERVICE, "--property=ActiveState,MainPID,InvocationID"
        ]).splitlines() if "=" in line)
        require(values.get("ActiveState") in ("active", "inactive", "failed", "activating", "deactivating")
                and values.get("MainPID", "").isdecimal(), "The Tor service identity could not be observed.")
        if values["ActiveState"] != "active" or int(values["MainPID"]) == 0:
            return None
        require(re.fullmatch(r"[a-f0-9]{32}", values.get("InvocationID", "")) is not None,
                "The Tor service invocation could not be verified.")
        return values["InvocationID"], int(values["MainPID"])

    def rotation(self):
        values = dict(line.split("=", 1) for line in self.run([
            "systemctl", "show", ROTATION_SERVICE,
            "--property=LoadState,ActiveState,FragmentPath,DropInPaths,Transient,User,Group,ExecStart,BindsTo,Type"
        ], accepted=(0, 1)).splitlines() if "=" in line)
        if values.get("LoadState") == "not-found":
            return {"active": False, "seconds": None}
        require(values.get("LoadState") == "loaded" and values.get("Transient") == "yes"
                and values.get("FragmentPath") == "/run/systemd/transient/" + ROTATION_SERVICE
                and values.get("DropInPaths") == "" and values.get("User") == ACCOUNT
                and values.get("Group") == ACCOUNT and values.get("Type") == "exec"
                and values.get("BindsTo") == RECOVERY_TIMER,
                "The Tor rotation unit is not the supported transient service.")
        match = re.fullmatch(r"\{ path=" + re.escape(RUNTIME) + r" ; argv\[\]=" + re.escape(RUNTIME)
                             + r" --rotation-worker ([1-9][0-9]{1,4}) ; ignore_errors=no"
                             + r" ; start_time=[^;{}\r\n]+ ; stop_time=[^;{}\r\n]+ ; pid=[0-9]+"
                             + r" ; code=[^;{}\r\n]+ ; status=[^;{}\r\n]+ \}", values.get("ExecStart", ""))
        require(match is not None and 30 <= int(match[1]) <= 86400
                and values.get("ActiveState") in ("active", "inactive", "failed", "activating", "deactivating"),
                "The Tor rotation unit has an unsupported command or state.")
        return {"active": values["ActiveState"] in ("active", "activating"), "seconds": int(match[1])}

    def rotation_stop(self):
        state = self.rotation()
        if state["seconds"] is not None:
            self.run(["systemctl", "stop", ROTATION_SERVICE])

    def rotation_start(self, seconds):
        require(type(seconds) is int and 30 <= seconds <= 86400, "Invalid Tor rotation interval.")
        state = self.rotation()
        if state["active"] and state["seconds"] == seconds:
            return
        if state["seconds"] is not None:
            self.rotation_stop()
        trusted_read(Path(RUNTIME), 512 * 1024)
        self.run(["systemd-run", "--quiet", "--collect", "--service-type=exec", "--unit=" + ROTATION_SERVICE,
                  "--property=User=" + ACCOUNT, "--property=Group=" + ACCOUNT,
                  "--property=BindsTo=" + RECOVERY_TIMER, "--property=After=" + RECOVERY_TIMER,
                  "--property=NoNewPrivileges=yes", "--property=ProtectSystem=strict", "--property=ProtectHome=yes",
                  "--property=PrivateTmp=yes", "--property=ReadWritePaths=" + str(CONTROL_DIR),
                  "--property=RestrictAddressFamilies=AF_UNIX", "--property=TimeoutStopSec=5",
                  "--property=UMask=0077", "--setenv=PATH=/usr/sbin:/usr/bin:/sbin:/bin", "--setenv=LC_ALL=C",
                  RUNTIME, "--rotation-worker", str(seconds)])
        result = self.rotation()
        require(result["active"] and result["seconds"] == seconds, "The Tor rotation worker did not become active.")

    def wait_ready(self, seconds=180, fetcher=None, monotonic=time.monotonic, sleep=time.sleep):
        fetcher = fetcher or HTTPS(socks=True, timeout=10)
        deadline = monotonic() + seconds
        while monotonic() < deadline:
            generation = self.generation()
            require(generation is not None,
                    "The Tor client did not remain active. Internet traffic stays blocked; automatic recovery will retry.")
            try:
                result = observe_ip(fetcher)
                require(result["tor_reported"], "The Tor test endpoint did not confirm Tor use.")
                require(self.generation() == generation, "The Tor service changed during its readiness check.")
                return result
            except Error:
                if monotonic() >= deadline:
                    break
                sleep(2)
        raise Error("Tor bootstrap or its HTTPS exit-IP check did not finish. Internet traffic stays blocked; automatic recovery will retry.")


def recovery_step(runtime, platform, fetcher=None):
    """One bounded attempt. An old probe can never reopen a stopped/new mode."""
    with runtime.operation("tor") as operation:
        state = runtime.state()
        if state is None or not platform.recovery_enabled():
            return "off"
        platform.definition()
        generation = platform.generation()
        # No mutation or readiness claim on this fast path. Full routing/UID/
        # uplink verification is required before every actual recovery attempt.
        if state["phase"] == "active" and generation is not None:
            return "active"
        status = runtime.status()
        require(not status.get("error"), status.get("error") or "Tor routing could not be verified.")
        operation.recover()
        if generation is None:
            platform.start()
            generation = platform.generation()
            require(generation is not None, "Tor could not restart; traffic remains blocked and recovery will retry.")
        expected = runtime.state()
    # Keep DNS/TCP of ordinary users and controllers closed during bootstrap.
    # This root-only probe uses SOCKS explicitly and cannot fall back to a
    # direct socket. Do not hold the CLI lock over its network request.
    observed = observe_ip(fetcher or HTTPS(socks=True, timeout=10))
    require(observed["tor_reported"], "Tor recovery was not verified; traffic remains blocked and recovery will retry.")
    with runtime.operation("tor") as operation:
        if (runtime.state() != expected or not platform.recovery_enabled()
                or platform.generation() != generation):
            return "superseded"
        operation.ready()
    print(f"Tor recovered and verified. Observed exit IP: {observed['ip']}.", flush=True)
    return "recovered"


def observe_active_ip(runtime, platform, fetcher):
    """Observe under the caller's operation lock without turning a probe error into an outage."""
    generation = platform.generation()
    require(generation is not None, "The Tor service is no longer active. Traffic stays blocked.")
    observed, observation_error = None, None
    try:
        observed = observe_ip(fetcher)
    except Error as exc:
        observation_error = exc
    state = runtime.status()
    require(state["mode"] == "tor" and state["ready"] and platform.generation() == generation,
            "The Tor service, guard or selected uplink changed during the IP observation. Traffic stays blocked.")
    if observed is not None:
        require(observed["tor_reported"], "The public-IP request was not confirmed as Tor. Traffic stays blocked.")
    return observed, observation_error


def parser():
    result = argparse.ArgumentParser(prog="auto tor", description=(
        "Optional Tor mode for the Pi and shared clients. Requires healthy auto share. "
        "Failed Tor services recover automatically with traffic blocked until verified. "
        "Unsupported UDP, external IPv6 and DNS-over-TCP fail closed. No automatic boot activation."))
    mode = result.add_mutually_exclusive_group()
    mode.add_argument("--on", action="store_true", help="Enable Tor with a guarded bootstrap and report the observed exit IP.")
    mode.add_argument("--off", action="store_true", help="Stop Tor and restore the previous share path.")
    mode.add_argument("--status", action="store_true", help="Show routing state and measure the current public IP.")
    mode.add_argument("--rotate", action="store_true", help="Request clean Tor circuits for new connections and report the observed IP.")
    mode.add_argument("--rotation-off", action="store_true", help="Stop scheduled rotation without stopping Tor.")
    result.add_argument("--rotate-every", metavar="INTERVAL", help="Schedule NEWNYM every 30s..24h (s/m/h); optionally combine with --on.")
    result.add_argument("--rotation-worker", type=int, help=argparse.SUPPRESS)
    result.add_argument("--recovery-worker", action="store_true", help=argparse.SUPPRESS)
    result.add_argument("--check", action="store_true", help="Download and replace the fresh exit list, then check an IP; with --status only show status/list path.")
    result.add_argument("--ip", help="Check this public IP instead of measuring this device; requires --check.")
    return result


def main(argv=None, platform=None, runtime=None, fetcher=None, store=None):
    args = parser().parse_args(argv)
    if args.rotation_worker is not None:
        require(not any((args.on, args.off, args.status, args.rotate, args.rotation_off, args.rotate_every, args.check, args.ip, args.recovery_worker)),
                "The internal rotation worker accepts no public options.")
        return rotation_worker(args.rotation_worker)
    if args.recovery_worker:
        require(not any((args.on, args.off, args.status, args.rotate, args.rotation_off, args.rotate_every, args.check, args.ip)),
                "The internal recovery worker accepts no public options.")
        require(os.geteuid() == 0, "The recovery worker must run as root.")
        runtime = runtime or load_egress().Runtime()
        try:
            recovery_step(runtime, platform or Platform(), fetcher)
        except Exception as error:
            if type(error) is not getattr(runtime, "Busy", None):
                raise
            print("Tor recovery deferred: another sharing operation is running.", flush=True)
        return 0
    require(not (args.check and (args.on or args.off or args.rotate or args.rotation_off or args.rotate_every)),
            "--check cannot be combined with a Tor mutation or rotation.")
    require(not args.rotate_every or not any((args.off, args.status, args.rotate, args.rotation_off, args.check, args.ip)),
            "--rotate-every is used alone or with --on.")
    seconds = interval(args.rotate_every) if args.rotate_every else None
    require(not args.ip or (args.check and not args.status), "--ip requires --check without --status.")
    if args.ip is not None:
        public_ip(args.ip)
    require(os.geteuid() == 0, "Run this command with sudo; --help is available without root.")
    platform, fetcher, store = platform or Platform(), fetcher or HTTPS(), store or ExitStore()
    if args.check and not args.status:
        result = check_exit(fetcher, store, args.ip)
        print(f"{result['result']}: {result['ip']}\nSource: {result['source']}\n"
              f"Source time: {result['source_at']}\nDownloaded: {result['fetched_at']}\n"
              "This verifies list membership only, not all network traffic.")
        return 0
    runtime = runtime or load_egress().Runtime()
    if args.on:
        observation_error = None
        with runtime.operation("tor") as operation:
            require(callable(getattr(operation, "recover", None)),
                    "Update anonymity-runtime before enabling automatic Tor recovery.")
            state = runtime.status()
            if state["mode"] == "tor":
                platform.definition()
                platform.recovery_start()
                if state["ready"] and platform.active():
                    observed, observation_error = observe_active_ip(runtime, platform, fetcher)
                else:
                    operation.recover()
                    if not platform.active():
                        platform.start()
                    observed = platform.wait_ready()
                    operation.ready()
            else:
                require(not platform.active(),
                        "The Tor service is already active without matching routing state. Run --off before --on.")
                uid = platform.account()
                platform.definition()
                operation.activate(uid, 19040, 19053)
                platform.recovery_start()
                platform.start()
                observed = platform.wait_ready()
                operation.ready()
            if seconds is not None and observation_error is None:
                platform.rotation_start(seconds)
        if observation_error is not None:
            raise Error("Tor remains enabled, but the exit-IP observation failed: " + str(observation_error))
        print(f"Tor enabled. Observed exit IP: {observed['ip']} ({observed['observed_at']}).")
        return 0
    if args.off:
        with runtime.operation("tor") as operation:
            platform.rotation_stop()
            platform.recovery_stop()
            operation.block()
            platform.stop()
            operation.deactivate()
        print("Tor disabled. The previous share path is restored.")
        return 0
    if args.rotate or args.rotation_off or seconds is not None:
        rotation_error = None
        observation_error = None
        with runtime.operation("tor"):
            if args.rotation_off:
                platform.rotation_stop()
            else:
                state = runtime.status()
                require(state["mode"] == "tor" and state["ready"] and platform.active(),
                        "Enable a healthy Tor mode before requesting rotation.")
                platform.definition()
                if args.rotate:
                    try:
                        rotate_client()
                    except (Error, OSError) as exc:
                        rotation_error = exc if isinstance(exc, Error) else Error("The Tor rotation request failed.")
                    if rotation_error is None:
                        observed, observation_error = observe_active_ip(runtime, platform, fetcher)
                else:
                    platform.rotation_start(seconds)
        if rotation_error is not None:
            raise rotation_error
        if observation_error is not None:
            raise Error("Tor confirmed NEWNYM, but the exit-IP observation failed; Tor remains enabled: " + str(observation_error))
        if args.rotate:
            print(f"Tor confirmed NEWNYM for new connections. Observed exit IP: {observed['ip']} ({observed['observed_at']}).\n"
                  "An IP change is not guaranteed; existing connections were not terminated.")
        elif args.rotation_off:
            print("Scheduled Tor rotation disabled. Tor remains in its current mode.")
        else:
            print(f"Scheduled Tor rotation: every {seconds} seconds; IP changes are not guaranteed.")
        return 0
    state = runtime.status()
    active = platform.active()
    rotation = platform.rotation()
    recovery = platform.recovery_enabled()
    print(f"Privacy mode: {state['mode']}\nState: {state['phase']}\n"
          f"Upstream interface: {state['interface'] or 'none'}\nTor service: {'active' if active else 'inactive'}")
    print("Scheduled rotation: " + (f"every {rotation['seconds']} seconds" if rotation["active"] else "off"))
    print("Automatic recovery: " + ("enabled" if recovery else "off"))
    if state.get("error"):
        print("Routing observation: " + state["error"])
    if args.check:
        print(store.describe())
    require(not (state["mode"] == "tor" and (not state["ready"] or not active)),
            "Tor is not active and verified. Internet traffic is blocked. "
            + ("Automatic recovery will retry." if recovery else "Run auto tor --on to retry without removing the guard."))
    require(not (state["mode"] != "tor" and active),
            "The Tor service is active without matching Tor routing state.")
    observed = observe_ip(fetcher)
    print(f"Observed public IP: {observed['ip']} ({observed['observed_at']})\n"
          f"Tor Project reports this request through Tor: {'yes' if observed['tor_reported'] else 'no'}")
    return 0


def cli(argv=None):
    """Report audited operational errors without disclosing arbitrary exceptions."""
    try:
        return main(argv)
    except Exception as error:
        known = isinstance(error, Error) or type(error) is _SHARED_RUNTIME_ERROR or type(error) is _SHARED_RUNTIME_BUSY
        message = (str(error) if known else
                   "The operation could not be completed safely. No configuration contents were disclosed.")
        print("Error: " + message, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(cli())
