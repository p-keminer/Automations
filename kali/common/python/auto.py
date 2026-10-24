#!/usr/bin/python3
"""Dispatch explicitly installed Automations commands without a shell."""
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import stat
import sys

MODULE_DIRECTORY = Path('/usr/local/libexec/automations')
PROFILE_PATH = Path('etc/automations/platform.json')
PROFILE_HELPER = Path('usr/local/libexec/automations-support/platform_support.py')
HOST_DIRECTORY = Path('usr/local/libexec/automations-host')
NAME = re.compile(r'[a-z][a-z0-9]*(?:-[a-z0-9]+)*')


def installed_commands(directory=MODULE_DIRECTORY):
    if not directory.exists():
        return {}
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('The command directory must be a real directory.')
    return {path.name: path for path in sorted(directory.iterdir())
            if NAME.fullmatch(path.name) and not path.is_symlink()
            and path.is_file() and os.access(path, os.X_OK)}


def validate_privileged_command(path):
    """A root dispatcher must not execute payload replaceable by another user."""
    if os.geteuid() != 0:
        return
    for entry in (path, *path.parents):
        info = entry.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('Privileged commands and their parent directories must '
                             'be root-owned and not writable by other users.')


def _trusted_path(path, root, owner_uid, *, executable=False):
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
            raise ValueError('Host support and its paths must be root-owned, '
                             'non-symlink and not writable by other users.')
    if executable and not os.access(path, os.X_OK):
        raise ValueError('The host backend is not executable.')


def _host_profile(root, owner_uid):
    """Only the fixed profile activates host routing; absent means legacy."""
    profile_path = root / PROFILE_PATH
    try:
        profile_path.lstat()
    except FileNotFoundError:
        return False
    helper = root / PROFILE_HELPER
    _trusted_path(helper, root, owner_uid)
    content = helper.read_bytes()
    name = '_automations_trusted_platform_' + hashlib.sha256(
        str(helper).encode('utf-8') + b'\0' + content
    ).hexdigest()
    spec = importlib.util.spec_from_file_location(name, helper)
    if spec is None:
        raise ValueError('Cannot load trusted platform support.')
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        # Compile verified support bytes without creating a bytecode cache.
        # Command discovery never executes an installed command module.
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
    return True


def main(argv=None, directory=MODULE_DIRECTORY, execute=os.execve, *,
         _profile_root=Path('/'), _owner_uid=0):
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        if type(_owner_uid) is not int or _owner_uid < 0:
            raise ValueError('Invalid internal ownership expectation.')
        profile_root = Path(os.path.abspath(_profile_root))
        host = _host_profile(profile_root, _owner_uid)
        commands = installed_commands(directory)
        backends = installed_commands(profile_root / HOST_DIRECTORY) if host else {}
        if not args or args == ['--help']:
            available = commands
            if host:
                available = {name: backends[name] for name in commands if name in backends}
                for path in available.values():
                    _trusted_path(path, profile_root, _owner_uid, executable=True)
            print('Usage: auto <command> [options]\n')
            print('Installed commands:')
            if available:
                for name in available:
                    print(f'  {name}')
            else:
                print('  No installed commands have an available kali-host backend.'
                      if host else '  No optional commands are installed.')
            print('\nUse auto <command> --help for command-specific help.')
            return 0
        name = args[0]
        if not NAME.fullmatch(name) or name not in commands:
            print('ERROR: Command is not installed. Use auto --help to list commands.',
                  file=sys.stderr)
            return 64
        if host:
            if name not in backends:
                print('ERROR: The installed command is unavailable for kali-host; '
                      'its host backend is not installed.', file=sys.stderr)
                return 69
            path = backends[name]
            _trusted_path(path, profile_root, _owner_uid, executable=True)
        else:
            path = commands[name]
            validate_privileged_command(path)
        # Payloads may use /usr/bin/env; choose the system interpreter/tools.
        environment = {**os.environ, 'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'}
        execute(str(path), [str(path), *args[1:]], environment)
        return 0
    except (OSError, ValueError) as error:
        print(f'ERROR: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
