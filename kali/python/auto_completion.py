#!/usr/bin/python3
"""Read installed completion metadata without executing Automations commands."""
from pathlib import Path
import os
import json
import re
import sys

COMMANDS = Path('/usr/local/libexec/automations')
DATA = Path('/usr/local/share/automations/completions')
SYSNET = Path('/sys/class/net')
SUPPORT = Path('/usr/local/libexec/automations-support')
NAME = re.compile(r'[a-z][a-z0-9]*(?:-[a-z0-9]+)*')
OPTION = re.compile(r'--[a-z][a-z0-9-]*')
INTERFACE = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}')
VALUES = {'--interface', '--to', '--from', '--ip', '--rotate-every'}


def regular(path, executable=False):
    return path.is_file() and not path.is_symlink() and (not executable or os.access(path, os.X_OK))


def options(path):
    if not regular(path) or path.stat().st_size > 65536:
        return []
    return list(dict.fromkeys(line for line in path.read_text(encoding='utf-8').splitlines()
                              if OPTION.fullmatch(line) or line == 'ap'))


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


def value_candidates(flag, current, words, sysnet, state, boot_id):
    if flag in {'--interface', '--to', '--from'}:
        names = sources(sysnet, state, boot_id) if flag == '--from' else interfaces(sysnet, words)
        if flag == '--from' and ',' in current:
            chosen, _, prefix = current.rpartition(',')
            selected = set(chosen.split(','))
            return [chosen+','+name for name in names if name not in selected and name.startswith(prefix)]
        return [name for name in names if name.startswith(current)]
    if flag == '--rotate-every':
        return [value for value in ['30s', '1m', '2m', '5m', '1h', '24h'] if value.startswith(current)]
    return []


def candidates(words, index, *, commands=COMMANDS, data=DATA, sysnet=SYSNET, support=SUPPORT,
               state=Path('/run/automations-hotspot/state.json'),
               boot_id=Path('/proc/sys/kernel/random/boot_id')):
    """Return literal candidates; shell completion handles sudo's command context."""
    if not 0 <= index < len(words) or len(words) > 256:
        return []
    if not words or Path(words[0]).name != 'auto':
        return []
    current = words[index]
    if index == 1:
        names = ['--help'] + [entry.name for entry in sorted(commands.iterdir())
                             if NAME.fullmatch(entry.name) and regular(entry, executable=True)]
        return [name for name in names if name.startswith(current)]
    if index < 2 or not NAME.fullmatch(words[1]) or not regular(commands/words[1], executable=True):
        return []
    context = words[1:index]
    if '--' in context:
        return []
    nested = context[:2] == ['share', 'ap']
    hotspot = regular(support/'hotspot.py') and regular(data/'share-ap')
    if nested and not hotspot:
        return []
    name = 'share-ap' if nested else words[1]
    available = options(data/name)
    if words[1] != 'share' or nested or not hotspot:
        available = [option for option in available if option != 'ap']
    if not available:
        return []
    value_flags = set(available)
    if name == 'share' and '--to' in value_flags:
        value_flags.add('--interface')  # Accepted legacy alias; do not advertise it.
    previous = words[index-1]
    if previous in VALUES and previous in value_flags:
        return value_candidates(previous, current, context, sysnet, state, boot_id)
    flag, separator, value = current.partition('=')
    if separator and flag in VALUES and flag in value_flags:
        return [flag+'='+candidate for candidate in value_candidates(flag, value, context, sysnet, state, boot_id)]
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
