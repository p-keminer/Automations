#!/usr/bin/python3
"""Read installed completion metadata without executing Automations commands."""
from pathlib import Path
import hashlib
import importlib.util
import os
import json
import re
import stat
import sys

COMMANDS = Path('/usr/local/libexec/automations')
DATA = Path('/usr/local/share/automations/completions')
SYSNET = Path('/sys/class/net')
SUPPORT = Path('/usr/local/libexec/automations-support')
TEMPLATES = Path('/usr/local/share/automations/hotspot/templates')
PROFILE_PATH = Path('etc/automations/platform.json')
PROFILE_HELPER = Path('usr/local/libexec/automations-support/platform_support.py')
HOST_DIRECTORY = Path('usr/local/libexec/automations-host')
NAME = re.compile(r'[a-z][a-z0-9]*(?:-[a-z0-9]+)*')
OPTION = re.compile(r'--[a-z][a-z0-9-]*')
INTERFACE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}')
VALUES = {'--interface', '--to', '--from', '--ip', '--rotate-every', '--password-file', '--template'}


def regular(path, executable=False):
    return path.is_file() and not path.is_symlink() and (not executable or os.access(path, os.X_OK))


def options(path):
    if not regular(path) or path.stat().st_size > 65536:
        return []
    return list(dict.fromkeys(line for line in path.read_text(encoding='utf-8').splitlines()
                              if OPTION.fullmatch(line) or line == 'ap'))


def _trusted_path(path, root, owner_uid, *, executable=False):
    """Use the dispatcher's fixed-path trust contract, without loading commands."""
    relative = path.relative_to(root)
    current = root
    entries = [root]
    for part in relative.parts:
        current = current / part
        entries.append(current)
    for index, entry in enumerate(entries):
        info = entry.lstat()
        final = index == len(entries) - 1
        expected_type = stat.S_ISREG if final else stat.S_ISDIR
        if (stat.S_ISLNK(info.st_mode) or not expected_type(info.st_mode)
                or info.st_uid != owner_uid or info.st_mode & 0o022):
            raise ValueError('Unsafe host completion support or backend path.')
    if executable and not os.access(path, os.X_OK):
        raise ValueError('The host backend is not executable.')


def _host_profile(root, owner_uid):
    """Only an explicit trusted profile selects host mode; absence stays legacy."""
    if type(owner_uid) is not int or owner_uid < 0:
        raise ValueError('Invalid internal ownership expectation.')
    try:
        (root / PROFILE_PATH).lstat()
    except FileNotFoundError:
        return None
    helper = root / PROFILE_HELPER
    _trusted_path(helper, root, owner_uid)
    content = helper.read_bytes()
    name = '_automations_completion_platform_' + hashlib.sha256(
        str(helper).encode('utf-8') + b'\0' + content
    ).hexdigest()
    spec = importlib.util.spec_from_file_location(name, helper)
    if spec is None:
        raise ValueError('Cannot load trusted platform support.')
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        # Only the verified platform helper is evaluated, never a command or
        # backend. Compile the checked bytes without writing a bytecode cache.
        exec(compile(content, str(helper), 'exec'), module.__dict__)
        profile = module.load_profile(root=root, _owner_uid=owner_uid)
        if profile.platform != 'kali-host' or profile.configured is not True:
            raise ValueError('The fixed profile must configure kali-host.')
    except (ImportError, AttributeError, SyntaxError, TypeError, UnicodeError) as error:
        raise ValueError('Cannot load trusted platform support.') from error
    finally:
        if previous is not None:
            sys.modules[name] = previous
        else:
            sys.modules.pop(name, None)
    return profile


def _installed_commands(directory):
    if not directory.exists():
        return {}
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('The command directory must be a real directory.')
    return {entry.name: entry for entry in sorted(directory.iterdir())
            if NAME.fullmatch(entry.name) and regular(entry, executable=True)}


def _host_radio(entry, sysroot):
    """Match host Wi-Fi's physical identity checks using only sysfs reads."""
    phy = (entry / 'phy80211').resolve(strict=True)
    device = (entry / 'device').resolve(strict=True)
    index = int((entry / 'ifindex').read_text(encoding='ascii').strip())
    if (sysroot not in phy.parents or sysroot not in device.parents or index <= 0
            or not re.fullmatch(r'phy[0-9]+', phy.name)):
        raise ValueError('Invalid wireless hardware identity.')
    for ancestor in (device, *device.parents):
        vendor, product = ancestor / 'idVendor', ancestor / 'idProduct'
        if vendor.is_file() or product.is_file():
            identifier = vendor.read_text(encoding='ascii').strip().lower() + ':' + product.read_text(encoding='ascii').strip().lower()
            if (not re.fullmatch(r'[0-9a-f]{4}:[0-9a-f]{4}', identifier)
                    or (ancestor / 'subsystem').resolve(strict=True) != sysroot / 'bus/usb'):
                raise ValueError('Invalid USB hardware identity.')
            return phy, device
        if ancestor == sysroot:
            break
    for ancestor in (device, *device.parents):
        if ancestor == sysroot:
            break
        subsystem = ancestor / 'subsystem'
        if not (subsystem.exists() or subsystem.is_symlink()):
            continue
        if subsystem.resolve(strict=True) != sysroot / 'bus/pci':
            break
        vendor = (ancestor / 'vendor').read_text(encoding='ascii').strip().lower()
        identifier = (ancestor / 'device').read_text(encoding='ascii').strip().lower()
        if not (re.fullmatch(r'0x[0-9a-f]{4}', vendor)
                and re.fullmatch(r'0x[0-9a-f]{4}', identifier)):
            raise ValueError('Invalid PCI wireless hardware identity.')
        return phy, device
    return None


def _host_interfaces(sysnet, words, profile, *, clients=False):
    sysroot = sysnet.parent.parent.resolve(strict=True)
    devices = {}
    wifi_command = words[0] == 'wifi' or words[:2] == ['share', 'ap']
    for entry in sorted(sysnet.iterdir()):
        name = entry.name
        if not INTERFACE.fullmatch(name) or name == 'lo' or not entry.is_dir():
            continue
        if wifi_command:
            if not (entry / 'phy80211').exists() and not (entry / 'phy80211').is_symlink():
                continue
            identity = _host_radio(entry, sysroot)
            if identity is not None:
                devices[name] = identity
        else:
            # HostShare accepts existing physical client networks of either
            # medium. Its --wifi/--lan switch describes only the uplink.
            if not (entry / 'device').exists():
                continue
            device = (entry / 'device').resolve(strict=True)
            if not device.is_relative_to(sysroot / 'devices'):
                continue
            phy = (entry / 'phy80211').resolve(strict=True) if (entry / 'phy80211').exists() else None
            devices[name] = (phy, device)
    protected = [devices[name] for name in profile.protected_interfaces if name in devices]
    result = []
    for name, (phy, device) in devices.items():
        if (name in profile.protected_interfaces
                or any(device == other_device or (phy is not None and phy == other_phy)
                       for other_phy, other_device in protected)):
            continue
        if not clients and not wifi_command:
            if '--wifi' in words and phy is None:
                continue
            if '--lan' in words and phy is not None:
                continue
        result.append(name)
    return result


def interfaces(sysnet, words):
    result = []
    control_phy = sysnet/'ctrl0/phy80211'
    for entry in sorted(sysnet.iterdir()):
        name = entry.name
        if not INTERFACE.fullmatch(name) or name == 'lo' or not entry.is_dir():
            continue
        phy = entry/'phy80211'
        if name == 'ctrl0' or (phy.exists() and control_phy.exists() and phy.resolve() == control_phy.resolve()):
            continue
        wifi = 'wifi' in words[:2] or words[:2] == ['share', 'ap'] or '--wifi' in words
        if wifi and not phy.exists():
            continue
        if '--lan' in words and phy.exists():
            continue
        result.append(name)
    return result


def sources(sysnet, state, boot_id):
    # No commands or privileged reads: offer only confirmed client roles.
    result = ['ctrl0'] if (sysnet/'ctrl0').is_dir() else []
    try:
        if not regular(state) or state.stat().st_size > 65536:
            return result
        value = json.loads(state.read_text(encoding='utf-8'))
        if not isinstance(value, dict) or value.get('phase') != 'active' or value.get('version') != 1:
            return result
        if value.get('boot_id') != boot_id.read_text().strip():
            return result
        if value.get('veth_index') != int((sysnet/'autoap0/ifindex').read_text()):
            return result
        adapter = value.get('adapter')
        name = adapter[0] if isinstance(adapter, list) and adapter else None
        if isinstance(name, str) and INTERFACE.fullmatch(name) and name not in {'ctrl0', 'autoap0', 'lo'}:
            result.append(name)
    except (OSError, ValueError, TypeError):
        pass
    return result


def value_candidates(flag, current, words, sysnet, state, boot_id, profile=None, templates=TEMPLATES):
    if flag == '--template':
        if words[:2] != ['share', 'ap'] or templates.is_symlink() or not templates.is_dir():
            return []
        return [path.name for path in sorted(templates.iterdir())
                if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', path.name)
                and not path.is_symlink() and path.is_dir() and regular(path/'index.html')
                and path.name.startswith(current)][:256]
    if flag in {'--interface', '--to', '--from'}:
        if profile is not None:
            names = _host_interfaces(sysnet, words, profile, clients=flag == '--from')
            if flag == '--from':
                names = list(dict.fromkeys(['host', *names]))
        else:
            names = sources(sysnet, state, boot_id) if flag == '--from' else interfaces(sysnet, words)
        if flag == '--from' and ',' in current:
            chosen, _, prefix = current.rpartition(',')
            selected = set(chosen.split(','))
            if profile is not None and 'host' in selected:
                return []
            return [chosen+','+name for name in names if name not in selected and name.startswith(prefix)
                    and not (profile is not None and name == 'host')]
        return [name for name in names if name.startswith(current)]
    if flag == '--rotate-every':
        return [value for value in ['30s', '1m', '2m', '5m', '1h', '24h'] if value.startswith(current)]
    return []


def candidates(words, index, *, commands=COMMANDS, data=DATA, sysnet=SYSNET, support=SUPPORT, templates=TEMPLATES,
               state=Path('/run/automations-hotspot/state.json'),
               boot_id=Path('/proc/sys/kernel/random/boot_id'),
               _profile_root=Path('/'), _owner_uid=0):
    """Return literal candidates; shell completion handles sudo's command context."""
    if not 0 <= index < len(words) or len(words) > 256:
        return []
    if not words or Path(words[0]).name != 'auto':
        return []
    try:
        profile_root = Path(os.path.abspath(_profile_root))
        profile = _host_profile(profile_root, _owner_uid)
        if profile is not None:
            installed = _installed_commands(commands)
            backends = _installed_commands(profile_root / HOST_DIRECTORY)
            if index == 1:
                available_commands = {name: backends[name] for name in installed if name in backends}
                for path in available_commands.values():
                    _trusted_path(path, profile_root, _owner_uid, executable=True)
            elif index >= 2:
                name = words[1]
                if name not in installed or name not in backends:
                    return []
                _trusted_path(backends[name], profile_root, _owner_uid, executable=True)
    except (OSError, ValueError, UnicodeError):
        return []
    current = words[index]
    if index == 1:
        names = ['--help'] + (list(available_commands) if profile is not None else
                             [entry.name for entry in sorted(commands.iterdir())
                              if NAME.fullmatch(entry.name) and regular(entry, executable=True)])
        return [name for name in names if name.startswith(current)]
    if index < 2 or not NAME.fullmatch(words[1]) or not regular(commands/words[1], executable=True):
        return []
    context = words[1:index]
    if '--' in context:
        return []
    nested = context[:2] == ['share', 'ap']
    hotspot = profile is None and regular(support/'hotspot.py') and regular(data/'share-ap')
    if profile is not None and regular(support/'host_ap.py') and regular(data/'share-ap-vm'):
        try:
            _trusted_path(support/'host_ap.py', profile_root, _owner_uid)
            _trusted_path(data/'share-ap-vm', profile_root, _owner_uid)
            hotspot = True
        except (OSError, ValueError):
            hotspot = False
    if nested and not hotspot:
        return []
    name = 'share-ap' if nested else words[1]
    metadata = data/name
    if profile is not None and regular(data/(name+'-vm')):
        try:
            _trusted_path(data/(name+'-vm'), profile_root, _owner_uid)
        except (OSError, ValueError):
            return []
        metadata = data/(name+'-vm')
    available = options(metadata)
    if profile is not None and name == 'share':
        available = [option for option in available if option != '--interface' and (option != 'ap' or hotspot)]
    if words[1] != 'share' or nested or not hotspot:
        available = [option for option in available if option != 'ap']
    if not available:
        return []
    value_flags = set(available)
    if name == 'share' and '--to' in value_flags:
        value_flags.add('--interface')  # Accepted legacy alias; do not advertise it.
    previous = words[index-1]
    if previous == '--template' and previous not in value_flags:
        return []
    if previous in VALUES and previous in value_flags:
        try:
            return value_candidates(previous, current, context, sysnet, state, boot_id, profile, templates)
        except (OSError, ValueError, UnicodeError):
            return []
    flag, separator, value = current.partition('=')
    if separator and flag in VALUES and flag in value_flags:
        try:
            return [flag+'='+candidate for candidate in value_candidates(flag, value, context, sysnet, state, boot_id, profile, templates)]
        except (OSError, ValueError, UnicodeError):
            return []
    return [option for option in available if option.startswith(current)]


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    try:
        index = int(args[0])
        for candidate in candidates(args[1:], index):
            print(candidate)
    except (ValueError, IndexError, OSError, UnicodeError):
        pass  # Incomplete or disappeared metadata must not produce a file fallback.
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
