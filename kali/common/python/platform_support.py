"""Strict, read-only platform identity shared by Automations commands."""

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat


PROFILE_PATH = Path("etc/automations/platform.json")
MAX_PROFILE_BYTES = 16 * 1024
MAX_DT_BYTES = 4096
INTERFACE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}")
PI4_MODEL = re.compile(rb"Raspberry Pi 4 Model B(?: Rev [0-9]+\.[0-9]+)?")
PROFILE_FIELDS = frozenset({
    "schema_version", "platform", "protected_interfaces", "ssh_service",
})


class ProfileError(ValueError):
    """The platform identity cannot be read or trusted."""


@dataclass(frozen=True)
class Profile:
    platform: str
    configured: bool
    protected_interfaces: tuple[str, ...]
    ssh_service: str
    identity: str


def _require(condition, message):
    if not condition:
        raise ProfileError(message)


def _safe_stat(info, *, directory, owner_uid):
    _require(not stat.S_ISLNK(info.st_mode), "Platform identity paths must not be symlinks.")
    _require(
        stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode),
        "Platform identity path has an unsupported file type.",
    )
    _require(info.st_uid == owner_uid, "Platform identity paths must be root-owned.")
    _require(
        not info.st_mode & 0o022,
        "Platform identity paths must not be writable by group or others.",
    )


def _read_file(root, relative, limit, owner_uid):
    """Missing files return None; unsafe existing path components are errors."""
    current = root
    try:
        _safe_stat(current.lstat(), directory=True, owner_uid=owner_uid)
        for index, part in enumerate(relative.parts):
            current = current / part
            try:
                info = current.lstat()
            except FileNotFoundError:
                return None
            _safe_stat(
                info, directory=index < len(relative.parts) - 1,
                owner_uid=owner_uid,
            )
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        descriptor = os.open(current, flags)
        try:
            info = os.fstat(descriptor)
            _safe_stat(info, directory=False, owner_uid=owner_uid)
            _require(info.st_size <= limit, "Platform identity file is too large.")
            with os.fdopen(descriptor, "rb", closefd=False) as stream:
                content = stream.read(limit + 1)
            _require(len(content) <= limit, "Platform identity file is too large.")
            return content
        finally:
            os.close(descriptor)
    except ProfileError:
        raise
    except OSError:
        raise ProfileError("Cannot safely read platform identity.") from None


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "Platform profile contains a duplicate JSON key.")
        result[key] = value
    return result


def _profile(platform, configured, protected_interfaces, ssh_service):
    protected = tuple(sorted(protected_interfaces))
    effective = {
        "schema_version": 1, "platform": platform, "configured": configured,
        "protected_interfaces": list(protected), "ssh_service": ssh_service,
    }
    encoded = json.dumps(effective, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return Profile(
        platform=platform, configured=configured, protected_interfaces=protected,
        ssh_service=ssh_service, identity=hashlib.sha256(encoded).hexdigest(),
    )


def _is_pi4(root, owner_uid):
    directory = Path("sys/firmware/devicetree/base")
    model = _read_file(root, directory / "model", MAX_DT_BYTES, owner_uid)
    if model is None or PI4_MODEL.fullmatch(model.removesuffix(b"\0")) is None:
        return False
    compatible = _read_file(root, directory / "compatible", MAX_DT_BYTES, owner_uid)
    return (
        compatible is not None
        and compatible.endswith(b"\0")
        and {b"raspberrypi,4-model-b", b"brcm,bcm2711"}
        <= set(compatible.split(b"\0"))
    )


def load_profile(root=Path("/"), *, _owner_uid=0):
    """Load a trusted host profile or detect the unconfigured platform.

    root and _owner_uid exist for internal filesystem fixtures only. There is
    no CLI or environment override and this function never creates state.
    """
    _require(
        type(_owner_uid) is int and _owner_uid >= 0,
        "Invalid internal platform ownership expectation.",
    )
    root = Path(os.path.abspath(root))
    content = _read_file(root, PROFILE_PATH, MAX_PROFILE_BYTES, _owner_uid)
    if content is None:
        if _is_pi4(root, _owner_uid):
            return _profile("pi4", False, ("ctrl0",), "ssh.service")
        return _profile("kali-host", False, (), "ssh.service")
    try:
        value = json.loads(content.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError):
        raise ProfileError("Platform profile must be valid UTF-8 JSON.") from None
    _require(
        isinstance(value, dict) and set(value) == PROFILE_FIELDS,
        "Platform profile has missing or unknown fields.",
    )
    _require(
        type(value["schema_version"]) is int and value["schema_version"] == 1,
        "Unsupported platform profile schema.",
    )
    _require(value["platform"] == "kali-host", "Explicit platform must be kali-host.")
    protected = value["protected_interfaces"]
    _require(
        isinstance(protected, list) and len(protected) <= 32
        and all(isinstance(name, str) and INTERFACE.fullmatch(name) for name in protected),
        "Protected interfaces must be a bounded list of valid interface names.",
    )
    _require(len(set(protected)) == len(protected), "Protected interfaces must be unique.")
    service = value["ssh_service"]
    _require(
        service in ("ssh.service", "sshd.service"),
        "SSH service must be ssh.service or sshd.service.",
    )
    return _profile("kali-host", True, protected, service)
