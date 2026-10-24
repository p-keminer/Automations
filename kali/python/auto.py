#!/usr/bin/python3
"""Dispatch explicitly installed Automations commands without a shell."""
import os
from pathlib import Path
import re
import stat
import sys

MODULE_DIRECTORY = Path('/usr/local/libexec/automations')
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


def main(argv=None, directory=MODULE_DIRECTORY, execute=os.execve):
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        commands = installed_commands(directory)
        if not args or args == ['--help']:
            print('Usage: auto <command> [options]\n')
            print('Installed commands:')
            if commands:
                for name in commands:
                    print(f'  {name}')
            else:
                print('  No optional commands are installed.')
            print('\nUse auto <command> --help for command-specific help.')
            return 0
        name = args[0]
        if not NAME.fullmatch(name) or name not in commands:
            print('ERROR: Command is not installed. Use auto --help to list commands.',
                  file=sys.stderr)
            return 64
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
