#!/usr/bin/python3
"""VM Tor adapter; reuse the audited Tor protocol and service lifecycle."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import sys

COMMON = Path('/usr/local/libexec/automations/tor')
SUPPORT = Path('/usr/local/libexec/automations-support/host_egress.py')
PROFILE = Path('/usr/local/libexec/automations-support/platform_support.py')
RUNTIME = '/usr/local/libexec/automations-host/tor'
TORRC = Path('/usr/local/share/automations/tor/torrc-vm')
# Bound to the exact VM definitions, never accept arbitrary service overrides.
DEFINITION_HASHES = {
    TORRC: '39480f7253b8900d3c92d04db5e971117875f1f4ae65dd4ebbbfea72b87db471',
    Path('/etc/systemd/system/automations-tor.service'):
        'f67033031afcd47c57a60377ec9aef2abfb48cfc771415b414d070d7acdd6523',
    Path('/etc/systemd/system/automations-tor-recovery.service'):
        '55b94e1e52f5a3cf0af9cae2865ba345a4009fae6af8d50f5375ea813d4b76fc',
}


class Error(RuntimeError):
    pass


def trusted_read(path, maximum=512 * 1024):
    for entry in (path, *path.parents):
        info = entry.lstat()
        if (stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                or not (stat.S_ISREG(info.st_mode) if entry == path else stat.S_ISDIR(info.st_mode))):
            raise Error('VM Tor support must be root-owned and protected from other users.')
    data = path.read_bytes()
    if not 0 < len(data) <= maximum:
        raise Error('VM Tor support exceeds its size limit.')
    return data


def load(path, name):
    raw = trusted_read(path)
    spec = importlib.util.spec_from_loader(name, loader=None, origin=str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        exec(compile(raw, str(path), 'exec'), module.__dict__)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def selection_args(argv):
    """Consume only VM selection options, leaving all common validation intact."""
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument('--to', metavar='IFACE')
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--lan', action='store_const', const='lan', dest='mode')
    modes.add_argument('--wifi', action='store_const', const='wifi', dest='mode')
    args, remaining = parser.parse_known_args(argv)
    if args.to is not None or args.mode is not None:
        if '--on' not in remaining or not args.to or not args.mode:
            parser.error('--to and --lan/--wifi are used together with --on only')
    return args, remaining


def configure(common):
    common.SUPPORT = SUPPORT
    common.RUNTIME = RUNTIME
    common.TORRC = TORRC
    common.DEFINITION_HASHES = {**common.DEFINITION_HASHES, **DEFINITION_HASHES}
    common.DEFINITION_HASHES.pop(Path('/usr/local/share/automations/tor/torrc'), None)
    return common


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    args, remaining = selection_args(argv)
    profile = load(PROFILE, '_automations_host_tor_profile').load_profile()
    if profile.platform != 'kali-host' or profile.configured is not True:
        raise Error('VM Tor needs an explicitly configured Kali host profile.')
    common = configure(load(COMMON, '_automations_shared_tor'))
    if remaining == ['--help']:
        common.parser().print_help()
        print('\nVM: --on --lan|--wifi --to IFACE selects an existing uplink without Share.\n'
              'With active Share, omit selection to use its exact existing uplink/client networks.')
        return 0
    # Workers are launched by the fixed root-owned units and reuse the state
    # selected by the root command. They never infer a default network.
    if '--rotation-worker' in remaining:
        return common.main(remaining)
    egress = common.load_egress()
    runtime = egress.Runtime(profile=profile, uplink=args.to, mode=args.mode)
    return common.main(remaining, runtime=runtime)


def cli(argv=None):
    try:
        return main(argv)
    except Exception as error:
        common = sys.modules.get('_automations_shared_tor')
        known = (isinstance(error, Error)
                 or common is not None and (isinstance(error, common.Error)
                    or type(error) in (common._SHARED_RUNTIME_ERROR, common._SHARED_RUNTIME_BUSY)))
        print('Error: ' + (str(error) if known else
              'VM Tor could not complete safely; no configuration contents were disclosed.'), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(cli())
