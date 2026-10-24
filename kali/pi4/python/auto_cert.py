#!/usr/bin/env python3
"""Control only the Pi4 public CA download routes, without stopping nginx."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from typing import NamedTuple

CONFIG = Path("/etc/nginx/conf.d/pi4-remote.conf")
LOCK = Path("/run/lock/automations-cert.lock")
ENABLED = (
    ("alias", "/etc/pi4/tls/ca.crt"),
    ("default_type", "application/x-x509-ca-cert"),
    ("add_header", "Content-Disposition", 'attachment; filename="pi4-ca.crt"'),
)
ON_BODY = """
        alias /etc/pi4/tls/ca.crt;
        default_type application/x-x509-ca-cert;
        add_header Content-Disposition 'attachment; filename="pi4-ca.crt"';
    """
OFF_BODY = """
        # Disabled by auto cert; the TLS certificate and Guacamole stay active.
        return 404;
    """
LISTENERS = {
    ("listen", "0.0.0.0:80", "default_server"): ("http", ("/cert", "/pi4-ca.crt")),
    ("listen", "0.0.0.0:443", "ssl", "default_server"): ("https", ("/cert",)),
}


class CertError(RuntimeError):
    pass


class Token(NamedTuple):
    value: str
    start: int
    end: int


class Block(NamedTuple):
    header: tuple[str, ...]
    body_start: int
    body_end: int
    children: list


def _tokens(text: str) -> list[Token]:
    """Small strict lexer: comments/quoted braces cannot masquerade as blocks."""
    result = []
    i = 0
    while i < len(text):
        if text[i].isspace():
            i += 1
            continue
        if text[i] == "#":
            end = text.find("\n", i)
            i = len(text) if end < 0 else end + 1
            continue
        start = i
        if text[i] in "{};":
            result.append(Token(text[i], i, i + 1))
            i += 1
            continue
        if text[i] in "'\"":
            quote = text[i]
            i += 1
            value = ""
            while i < len(text) and text[i] != quote:
                if text[i] == "\\":
                    i += 1
                    if i >= len(text):
                        raise CertError("Unterminated nginx escape.")
                value += text[i]
                i += 1
            if i >= len(text):
                raise CertError("Unterminated nginx string.")
            i += 1
            result.append(Token(value, start, i))
            continue
        while i < len(text) and not text[i].isspace() and text[i] not in "{};#'\"":
            i += 1
        if start == i:
            raise CertError("Unsupported nginx token.")
        result.append(Token(text[start:i], start, i))
    return result


def _parse(text: str) -> list:
    tokens = _tokens(text)

    def parse_items(index: int, nested: bool):
        items, head = [], []
        while index < len(tokens):
            token = tokens[index]
            index += 1
            if token.value == ";" and text[token.start:token.end] == ";":
                if not head:
                    raise CertError("Empty nginx directive.")
                items.append(tuple(head))
                head = []
            elif token.value == "{" and text[token.start:token.end] == "{":
                if not head:
                    raise CertError("Unnamed nginx block.")
                children, index, close = parse_items(index, True)
                items.append(Block(tuple(head), token.end, close.start, children))
                head = []
            elif token.value == "}" and text[token.start:token.end] == "}":
                if head or not nested:
                    raise CertError("Malformed nginx block.")
                return items, index, token
            else:
                head.append(token.value)
        if head or nested:
            raise CertError("Incomplete nginx configuration.")
        return items, index, None

    return parse_items(0, False)[0]


def routes(text: str) -> list[tuple[str, Block, str]]:
    """Accept only the three unambiguous v05 download blocks."""
    servers = [item for item in _parse(text) if isinstance(item, Block) and item.header == ("server",)]
    if len(servers) != 2:
        raise CertError("Expected exactly the two Pi4 HTTP/HTTPS server blocks.")
    found = []
    protocols = set()
    for server in servers:
        listeners = [item for item in server.children if isinstance(item, tuple)
                     and not isinstance(item, Block) and item and item[0] == "listen"]
        if len(listeners) != 1 or listeners[0] not in LISTENERS:
            raise CertError("Unrecognized Pi4 listener configuration; no changes made.")
        protocol, paths = LISTENERS[listeners[0]]
        if protocol in protocols:
            raise CertError("Duplicate Pi4 listener.")
        protocols.add(protocol)
        for path in paths:
            candidates = [item for item in server.children
                          if isinstance(item, Block) and item.header == ("location", "=", path)]
            if len(candidates) != 1:
                raise CertError(f"Expected one exact {protocol} {path} download block.")
            block = candidates[0]
            directives = block.children
            if any(isinstance(item, Block) for item in directives):
                raise CertError("Nested certificate download directives are unsupported.")
            if len(directives) == 3 and set(directives) == set(ENABLED):
                state = "on"
            elif directives == [("return", "404")]:
                state = "off"
            else:
                raise CertError(f"Unrecognized {protocol} {path} download directives; no changes made.")
            found.append((f"{protocol} {path}", block, state))
        # Never silently overlook a duplicate, prefix, or alternate cert route.
        cert_locations = [item for item in server.children if isinstance(item, Block)
                          and item.header and item.header[0] == "location"
                          and any(value in ("/cert", "/pi4-ca.crt") for value in item.header[1:])]
        if len(cert_locations) != len(paths):
            raise CertError("Unexpected or duplicate certificate download location.")
    return found


def configured_state(text: str) -> str:
    states = {item[2] for item in routes(text)}
    return states.pop() if len(states) == 1 else "mixed"


def transform(text: str, enabled: bool) -> str:
    desired = "on" if enabled else "off"
    replacements = [(block.body_start, block.body_end) for _, block, state in routes(text)
                    if state != desired]
    body = ON_BODY if enabled else OFF_BODY
    for start, end in sorted(replacements, reverse=True):
        text = text[:start] + body + text[end:]
    return text


def run_command(arguments: list[str]):
    try:
        return subprocess.run(
            arguments, text=True, capture_output=True, timeout=30, check=False,
            env={**os.environ, "LC_ALL": "C", "PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CertError(f"Could not run {arguments[0]}: {type(exc).__name__}.") from exc


def service_state(runner=run_command) -> str:
    result = runner(["systemctl", "show", "nginx.service", "--property=ActiveState", "--value"])
    state = result.stdout.strip()
    if result.returncode or state not in {
        "active", "inactive", "failed", "activating", "deactivating", "reloading", "maintenance"
    }:
        raise CertError("Could not determine the nginx service state.")
    return state


def read_config(path: Path) -> tuple[bytes, os.stat_result]:
    flags = os.O_RDONLY | os.O_NOFOLLOW
    try:
        with os.fdopen(os.open(path, flags), "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 1024 * 1024:
                raise CertError("nginx configuration must be a regular file below 1 MiB.")
            data = stream.read(1024 * 1024 + 1)
            if len(data) > 1024 * 1024:
                raise CertError("nginx configuration is too large.")
    except OSError as exc:
        raise CertError(f"Cannot read {path}: {exc.strerror}.") from exc
    return data, metadata


def decode(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CertError("nginx configuration is not UTF-8.") from exc


def atomic_replace(path: Path, data: bytes, expected: bytes, metadata: os.stat_result):
    current, current_stat = read_config(path)
    if current != expected or (current_stat.st_uid, current_stat.st_gid, stat.S_IMODE(current_stat.st_mode)) != (
        metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)
    ):
        raise CertError("Configuration changed concurrently; refusing to overwrite it.")
    temporary = None
    try:
        descriptor, name = tempfile.mkstemp(prefix=".auto-cert-", dir=path.parent)
        temporary = Path(name)
        with os.fdopen(descriptor, "wb") as stream:
            os.fchown(stream.fileno(), metadata.st_uid, metadata.st_gid)
            os.fchmod(stream.fileno(), stat.S_IMODE(metadata.st_mode))
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        # Catch concurrent editors again immediately before the atomic rename.
        if read_config(path)[0] != expected:
            raise CertError("Configuration changed concurrently; refusing to overwrite it.")
        os.replace(temporary, path)
        temporary = None
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


@contextmanager
def exclusive_lock(path: Path):
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
            raise CertError("Unsafe certificate-control lock file.")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise CertError("Another certificate-control operation is running.") from exc
        yield
    finally:
        os.close(descriptor)


def describe(configured: str, service: str) -> str:
    return (f"Certificate downloads: configured {configured}; nginx {service}.\n"
            "This reports the configuration file and service state, not a live route probe.")


def change(enabled: bool, *, config: Path = CONFIG, lock: Path = LOCK, runner=run_command) -> str:
    """Paths and runner are injected only by offline tests, never by CLI flags."""
    with exclusive_lock(lock):
        original, metadata = read_config(config)
        text = decode(original)
        candidate = transform(text, enabled).encode("utf-8")
        state = service_state(runner)
        if state not in {"active", "inactive", "failed"}:
            raise CertError(f"nginx is {state}; retry once its state is stable.")
        if candidate == original:
            return "Already configured as requested.\n" + describe(configured_state(text), state)
        if runner(["nginx", "-t"]).returncode:
            raise CertError("The existing nginx configuration is invalid; no changes made.")
        reload_attempted = False
        try:
            atomic_replace(config, candidate, original, metadata)
            if runner(["nginx", "-t"]).returncode:
                raise CertError("nginx rejected the candidate configuration.")
            if state == "active":
                reload_attempted = True
                if runner(["systemctl", "reload", "nginx.service"]).returncode:
                    raise CertError("nginx reload failed.")
                if service_state(runner) != "active":
                    raise CertError("nginx did not remain active after reload.")
        except (CertError, OSError, KeyboardInterrupt) as exc:
            reason = str(exc) or "Operation interrupted."
            try:
                current, _ = read_config(config)
                if current == candidate:
                    atomic_replace(config, original, candidate, metadata)
                elif current != original:
                    raise CertError("Configuration changed externally; refusing to overwrite it.")
                if runner(["nginx", "-t"]).returncode:
                    raise CertError("Restored nginx configuration did not validate.")
                if reload_attempted:
                    if runner(["systemctl", "reload", "nginx.service"]).returncode:
                        raise CertError("Could not reload the restored configuration.")
                    if service_state(runner) != "active":
                        raise CertError("nginx is not active after restoring the configuration.")
            except (CertError, OSError) as rollback:
                raise CertError(f"{reason} Rollback needs attention: {rollback}") from rollback
            raise CertError(f"{reason} Original configuration restored.") from exc
        if state == "active":
            return f"Certificate downloads configured {'on' if enabled else 'off'}; nginx validated and reloaded."
        return (f"Certificate downloads configured {'on' if enabled else 'off'} and validated. "
                f"nginx is {state}; it was not started. The change applies when nginx next starts.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="auto cert", description="Enable or disable only public Pi4 CA certificate downloads."
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--on", action="store_true", help="Enable the three public CA download routes")
    group.add_argument("--off", action="store_true", help="Return HTTP 404 from those routes")
    group.add_argument("--status", action="store_true", help="Show configuration and nginx service state (default)")
    args = parser.parse_args(argv)
    try:
        if args.on or args.off:
            if os.geteuid() != 0:
                raise CertError("Run this operation as root: sudo auto cert --on or --off.")
            print(change(args.on))
        else:
            data, _ = read_config(CONFIG)
            print(describe(configured_state(decode(data)), service_state()))
        return 0
    except (CertError, OSError) as exc:
        print(f"auto cert: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
