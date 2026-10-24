#!/usr/bin/python3
"""Install a reviewed Kali-host bundle; refuse replacement of unowned or changed files."""
from __future__ import annotations
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tarfile
import tempfile

REGISTRY = Path('/var/lib/automations-vm/install.json')
PROFILE = Path('/etc/automations/platform.json')
EXPECTED_PROFILE = dict(schema_version=1, platform='kali-host', protected_interfaces=[], ssh_service='ssh.service')


def require(value, message):
    if not value:
        raise ValueError(message)


def trusted(path):
    for entry in (path, *path.parents):
        info = entry.lstat()
        require(not stat.S_ISLNK(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                'Installation paths must be root-owned and protected: ' + str(entry))
        require(stat.S_ISREG(info.st_mode) if entry == path else stat.S_ISDIR(info.st_mode),
                'Unexpected installation path type.')


def destination(value):
    name = PurePosixPath(value)
    require(not name.is_absolute() and '..' not in name.parts, 'Unsafe bundle destination.')
    allowed = (value == 'usr/bin/auto' or value == 'etc/bash_completion.d/auto'
               or value.startswith(('usr/local/libexec/automations/', 'usr/local/libexec/automations-host/',
                                    'usr/local/libexec/automations-support/', 'usr/local/share/automations/',
                                    'usr/local/share/zsh/site-functions/'))
               or value in ('usr/local/bin/auto', 'usr/local/bin/awus-status')
               or value.startswith('etc/systemd/system/automations-') and '/' not in value[19:])
    require(allowed, 'Destination is outside the VM payload: ' + value)
    return Path('/') / name


def read_bundle(path):
    contents = {}
    with tarfile.open(path, 'r:') as bundle:
        for member in bundle:
            name = PurePosixPath(member.name)
            require(member.isfile() and not name.is_absolute() and '..' not in name.parts
                    and 0 <= member.size <= 1024 * 1024 and member.name not in contents,
                    'Unsafe bundle member.')
            contents[member.name] = bundle.extractfile(member).read()
            require(sum(len(data) for data in contents.values()) <= 8 * 1024 * 1024, 'Bundle exceeds limit.')
    manifest = json.loads(contents.pop('vm-deployment.json'))
    require(manifest['schema_version'] == 1 and manifest['platform'] == 'kali-host', 'Not a VM bundle.')
    files = {}
    for item in manifest['files']:
        target = destination(item['destination'])
        data = contents[item['source']]
        require(hashlib.sha256(data).hexdigest() == item['sha256'] and item['mode'] in ('0644', '0755')
                and target not in files, 'Invalid VM payload hash, mode or duplicate.')
        files[target] = (data, int(item['mode'], 8))
    return manifest, files


def check_parent_directories(path, *, create=False, public=True, _root=Path('/'), _owner_uid=0):
    """Validate parents; chmod only a directory successfully created here.

    Public CLI/worker payloads need traversal by unprivileged users. An existing
    protected but private parent needs explicit administrator review, never an
    automatic migration. The ownership receipt itself is private, not a public
    payload. _root/_owner_uid are internal filesystem-fixture inputs only.
    """
    path, root = Path(path), Path(_root)
    require(path.is_absolute() and root.is_absolute() and '..' not in path.parts
            and path.is_relative_to(root) and path != root, 'Unsafe destination parent path.')
    parent = root
    parents = [root]
    for part in path.parent.relative_to(root).parts:
        parent = parent / part
        parents.append(parent)
    for parent in parents:
        created = False
        try:
            info = parent.lstat()
        except FileNotFoundError:
            if not create:
                return
            try:
                parent.mkdir(mode=0o755)
                created = True
            except FileExistsError:
                # Another root operation may have created it. Do not chmod it.
                pass
            info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
                and info.st_uid == _owner_uid and not info.st_mode & 0o022,
                'Unsafe destination parent: ' + str(parent))
        if created:
            descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                actual = os.fstat(descriptor)
                require((actual.st_dev, actual.st_ino) == (info.st_dev, info.st_ino),
                        'New destination directory changed: ' + str(parent))
                # mkdir's mode is filtered by umask; public workers cannot use
                # the resulting 0750 when installation runs with umask 0027.
                os.fchmod(descriptor, 0o755)
                info = os.fstat(descriptor)
                require(stat.S_IMODE(info.st_mode) == 0o755,
                        'New destination directory mode readback failed: ' + str(parent))
            finally:
                os.close(descriptor)
        require(not public or info.st_mode & 0o001,
                'Public payload parent is not traversable by other users; '
                'review its ownership and permissions explicitly: ' + str(parent))


def atomic_write(path, data, mode, *, public=True, _root=Path('/'), _owner_uid=0):
    check_parent_directories(path, create=True, public=public, _root=_root, _owner_uid=_owner_uid)
    descriptor, temporary = tempfile.mkstemp(prefix='.automations-install-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


@contextmanager
def installation_lock():
    descriptors = []
    try:
        for name in ('automations-vm-install.lock', 'automations-host-share.lock',
                     'automations-host-ap.lock', 'automations-wifi.lock'):
            path = Path('/run') / name
            info = path.parent.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                    'Unsafe installer coordination directory.')
            descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            descriptors.append(descriptor)
            info = os.fstat(descriptor)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                    and stat.S_IMODE(info.st_mode) == 0o600, 'Unsafe installer coordination lock.')
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise ValueError('Another installer or network operation is running.') from None
        yield
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def install(bundle, *, apply=False, previous_test_receipt=None):
    require(os.geteuid() == 0, 'Run the installer as root.')
    with installation_lock():
        return install_locked(bundle, apply=apply, previous_test_receipt=previous_test_receipt)


def install_locked(bundle, *, apply=False, previous_test_receipt=None):
    manifest, files = read_bundle(bundle)
    missing = []
    for package in manifest['packages']:
        require(isinstance(package, str) and re.fullmatch(r'[a-z0-9][a-z0-9+.-]*', package),
                'Invalid package dependency.')
        status = subprocess.run(['/usr/bin/dpkg-query', '-W', '-f=${db:Status-Status}', package],
                                capture_output=True, text=True, timeout=10)
        if status.returncode != 0 or status.stdout != 'installed':
            missing.append(package)
    require(not missing, 'Install the VM dependencies first: ' + ', '.join(missing))
    ownership = {}
    previous = REGISTRY
    if not previous.exists() and previous_test_receipt is not None:
        previous = Path(previous_test_receipt)
        require(previous == Path('/var/lib/automations-vm-test/deployment.json'), 'Unsupported test migration receipt.')
    if previous.exists():
        trusted(previous)
        require(stat.S_IMODE(previous.stat().st_mode) == 0o600, 'Ownership receipt must be private.')
        for item in json.loads(previous.read_text())['files']:
            value = item['mode']
            mode = int(value, 0) if value.startswith('0o') else int(value, 8)
            require(mode in (0o644, 0o755), 'Invalid ownership receipt mode.')
            ownership[Path(item['path'])] = (item['sha256'], mode)
    if PROFILE.exists() or PROFILE.is_symlink():
        trusted(PROFILE)
        require(json.loads(PROFILE.read_text()) == EXPECTED_PROFILE, 'Existing host profile differs; preserve it.')
        if PROFILE in ownership:
            files[PROFILE] = (PROFILE.read_bytes(), stat.S_IMODE(PROFILE.stat().st_mode))
    else:
        files[PROFILE] = ((json.dumps(EXPECTED_PROFILE, sort_keys=True) + '\n').encode(), 0o644)
    old = {}
    targets = set(files) | set(ownership)
    for path in targets | {PROFILE}:
        check_parent_directories(path)
    check_parent_directories(REGISTRY, public=False)
    for path in targets:
        if path != PROFILE:
            require(destination(str(path).lstrip('/')) == path, 'Unsafe ownership receipt destination.')
        if path.exists() or path.is_symlink():
            trusted(path)
            content = path.read_bytes()
            require(path in ownership and (hashlib.sha256(content).hexdigest(), stat.S_IMODE(path.stat().st_mode)) == ownership[path],
                    'Refuse replacement/removal of an unowned or changed file: ' + str(path))
            old[path] = (content, stat.S_IMODE(path.stat().st_mode))
        else:
            require(path not in ownership, 'A previously installed file is missing: ' + str(path))
            old[path] = None
    result = dict(platform='kali-host', components=manifest['components'],
                  files=[dict(path=str(path), sha256=hashlib.sha256(data).hexdigest(), mode=oct(mode))
                         for path, (data, mode) in sorted(files.items())],
                  removed_owned_files=[str(path) for path in sorted(set(ownership) - set(files))],
                  source_bundle_sha256=hashlib.sha256(Path(bundle).read_bytes()).hexdigest())
    if not apply:
        return dict(result, applied=False)
    for path in ('/run/automations-host-share/state.json', '/run/automations-host-tor/state.json',
                 '/run/automations-host-ap/state.json'):
        require(not Path(path).exists() and not Path(path).is_symlink(),
                'Stop the owned network mode before installing: ' + path)
    completed = []
    try:
        for path, (data, mode) in files.items():
            if path in old and old[path] == (data, mode):
                continue
            atomic_write(path, data, mode)
            completed.append(path)
        for path in set(ownership) - set(files):
            path.unlink()
            completed.append(path)
        require(all(path.read_bytes() == data and stat.S_IMODE(path.stat().st_mode) == mode
                    for path, (data, mode) in files.items()), 'Installed payload readback failed.')
        subprocess.run(['/usr/bin/systemctl', 'daemon-reload'], check=True, timeout=30)
        atomic_write(REGISTRY, (json.dumps(result, indent=2) + '\n').encode(), 0o600, public=False)
    except BaseException:
        for path in reversed(completed):
            if old[path] is None:
                path.unlink(missing_ok=True)
            else:
                atomic_write(path, *old[path])
        subprocess.run(['/usr/bin/systemctl', 'daemon-reload'], check=True, timeout=30)
        raise
    return dict(result, applied=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('bundle', type=Path)
    parser.add_argument('--apply', action='store_true', help='Default only verifies and lists the proposed payload')
    parser.add_argument('--migrate-test-receipt', action='store_true')
    args = parser.parse_args(argv)
    result = install(args.bundle, apply=args.apply, previous_test_receipt=(
        '/var/lib/automations-vm-test/deployment.json' if args.migrate_test_receipt else None))
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
