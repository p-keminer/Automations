#!/usr/bin/python3
"""Static portal bundles shared by the additional Pi4 and Kali-host APs."""
from __future__ import annotations

import argparse
import hashlib
import html
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from urllib.parse import unquote, urlsplit

ROOT = Path('/usr/local/share/automations/hotspot/templates')
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}')
MAX_FILES, MAX_FILE, MAX_TOTAL = 64, 2 * 1024 * 1024, 10 * 1024 * 1024
CSP = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
CAPTIVE_HOSTS = ('captive.apple.com', 'www.apple.com', 'connectivitycheck.gstatic.com',
                 'connectivitycheck.android.com', 'clients3.google.com', 'www.gstatic.com', 'www.google.com',
                 'www.msftconnecttest.com', 'www.msftncsi.com', 'msftconnecttest.com', 'msftncsi.com',
                 'detectportal.firefox.com')
CAPTIVE_PATHS = {'/generate_204', '/gen_204', '/hotspot-detect.html', '/library/test/success.html',
                 '/connecttest.txt', '/ncsi.txt', '/redirect', '/canonical.html', '/success.txt'}
PORTAL_URL = 'http://10.79.0.1/'


class Error(ValueError):
    pass


def require(value, message):
    if not value:
        raise Error(message)


def relative(name):
    path = PurePosixPath(name)
    require(isinstance(name, str) and 0 < len(name) <= 192 and not path.is_absolute()
            and str(path) == name and all(NAME.fullmatch(part) for part in path.parts),
            'Portal paths must use ordinary file/directory names without traversal.')
    return path


def trusted(path, *, directory=False, owner_uid=0, anchor=Path('/')):
    path, anchor = Path(path), Path(anchor)
    require(path.is_absolute() and path.is_relative_to(anchor), 'Portal path escapes its trusted root.')
    for item in (path, *path.parents):
        if not item.is_relative_to(anchor):
            continue
        info = item.lstat()
        require(not stat.S_ISLNK(info.st_mode) and info.st_uid == owner_uid and not info.st_mode & 0o022,
                'Portal files and directories must be owned by root and not writable by other users.')
        if item != path:
            require(stat.S_ISDIR(info.st_mode), 'Invalid portal parent directory.')
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode) and info.st_nlink == 1,
            'Portal templates may contain only real directories and regular files, without links.')
    return path


def names(root=ROOT, *, owner_uid=0, anchor=Path('/')):
    root = trusted(root, directory=True, owner_uid=owner_uid, anchor=anchor)
    result = []
    for path in sorted(root.iterdir()):
        if NAME.fullmatch(path.name) and not path.is_symlink() and path.is_dir():
            try:
                trusted(path, directory=True, owner_uid=owner_uid, anchor=anchor)
                trusted(path/'index.html', owner_uid=owner_uid, anchor=anchor)
            except (OSError, Error):
                continue
            result.append(path.name)
    require(len(result) <= 256, 'There are too many portal templates.')
    return result


def select(name=None, root=ROOT, *, owner_uid=0, anchor=Path('/'), reader=None,
           stdin=None, stdout=None):
    available = names(root, owner_uid=owner_uid, anchor=anchor)
    require(available, 'No portal templates found. Add a directory containing index.html under ' + str(root) + '.')
    if name is None:
        stdin, stdout = stdin or sys.stdin, stdout or sys.stdout
        require(stdin.isatty() and stdout.isatty(),
                'Choose a portal with --template NAME. Available templates: ' + ', '.join(available))
        print('Available portal templates:', file=stdout)
        for number, entry in enumerate(available, 1):
            print(f'  {number}. {entry}', file=stdout)
        try:
            value = (reader or input)('Portal template (number or directory name): ').strip()
        except EOFError:
            raise Error('Portal selection cancelled; no AP was changed.') from None
        name = available[int(value)-1] if value.isascii() and value.isdecimal() and 1 <= int(value) <= len(available) else value
    require(isinstance(name, str) and NAME.fullmatch(name) and name in available,
            'Unknown portal template. Available templates: ' + ', '.join(available))
    return name


def digest(files):
    return hashlib.sha256(json.dumps({name: hashlib.sha256(data).hexdigest()
        for name, data in sorted(files.items())}, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def snapshot(name, root=ROOT, *, owner_uid=0, anchor=Path('/')):
    require(isinstance(name, str) and NAME.fullmatch(name), 'Use a portal directory name, not a path or URL.')
    source = trusted(Path(root)/name, directory=True, owner_uid=owner_uid, anchor=anchor)
    files, total = {}, 0
    def visit(directory):
        nonlocal total
        for path in sorted(directory.iterdir()):
            key = str(path.relative_to(source))
            relative(key)
            require(len(PurePosixPath(key).parts) <= 8, 'Portal directories are nested too deeply.')
            if path.is_dir() and not path.is_symlink():
                trusted(path, directory=True, owner_uid=owner_uid, anchor=anchor)
                visit(path)
            else:
                trusted(path, owner_uid=owner_uid, anchor=anchor)
                require(path.stat().st_size <= MAX_FILE, 'A portal asset exceeds 2 MiB.')
                with path.open('rb') as stream:
                    data = stream.read(MAX_FILE+1)
                require(len(data) <= MAX_FILE, 'A portal asset exceeds 2 MiB.')
                files[key] = data
                total += len(data)
                require(len(files) <= MAX_FILES and total <= MAX_TOTAL, 'Portal bundle exceeds 64 files or 10 MiB.')
    visit(source)
    require('index.html' in files, 'A portal template needs index.html.')
    for key, data in files.items():
        if key.endswith(('.html', '.htm')):
            require(b'\0' not in data, 'Portal HTML must be UTF-8 without NUL bytes.')
            data.decode('utf-8')
    return files


def render(files, ssid):
    result = {name: (data.decode('utf-8').replace('{{SSID}}', html.escape(ssid, quote=True)).encode('utf-8')
                   if name.endswith(('.html', '.htm')) else data) for name, data in files.items()}
    require(all(len(data) <= MAX_FILE for data in result.values()) and sum(map(len, result.values())) <= MAX_TOTAL,
            'Rendered portal bundle exceeds its size limit.')
    return result


def manifest(files):
    return {name: hashlib.sha256(data).hexdigest() for name, data in sorted(files.items())}


def validate_manifest(value):
    require(type(value) is dict and 1 <= len(value) <= MAX_FILES and 'index.html' in value,
            'Invalid portal runtime manifest.')
    for name, sha in value.items():
        relative(name)
        require(isinstance(sha, str) and re.fullmatch(r'[0-9a-f]{64}', sha), 'Invalid portal file digest.')
    return value


def write_runtime(directory, files, *, owner_uid=0, anchor=Path('/')):
    directory = Path(directory)
    validate_manifest(manifest(files))
    trusted(directory.parent, directory=True, owner_uid=owner_uid, anchor=anchor)
    directory.mkdir(mode=0o755)
    directory.chmod(0o755)
    try:
        for name, data in sorted(files.items()):
            path = directory / name
            path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            parent = path.parent
            while parent != directory:
                parent.chmod(0o755)
                parent = parent.parent
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
            with os.fdopen(descriptor, 'wb') as stream:
                stream.write(data)
            path.chmod(0o644)
    except BaseException:
        remove_runtime(directory, manifest(files), owner_uid=owner_uid, anchor=anchor)
        raise


def verify_runtime(directory, expected, *, owner_uid=0, anchor=Path('/'), partial=False):
    validate_manifest(expected)
    directory = trusted(directory, directory=True, owner_uid=owner_uid, anchor=anchor)
    allowed_dirs = {str(parent) for name in expected for parent in PurePosixPath(name).parents if str(parent) != '.'}
    actual = set()
    for parent, directories, filenames in os.walk(directory, followlinks=False):
        for name in directories:
            path = Path(parent)/name
            key = str(path.relative_to(directory))
            require(key in allowed_dirs, 'Unexpected portal runtime directory; cleanup stopped.')
            trusted(path, directory=True, owner_uid=owner_uid, anchor=anchor)
        for name in filenames:
            path = Path(parent)/name
            key = str(path.relative_to(directory))
            require(key in expected, 'Unexpected portal runtime file; cleanup stopped.')
            trusted(path, owner_uid=owner_uid, anchor=anchor)
            require(path.stat().st_size <= MAX_FILE and hashlib.sha256(path.read_bytes()).hexdigest() == expected[key],
                    'A served portal asset changed; cleanup stopped.')
            actual.add(key)
    require(partial or actual == set(expected), 'A served portal asset is missing.')
    return directory


def remove_runtime(directory, expected, *, owner_uid=0, anchor=Path('/')):
    directory = verify_runtime(directory, expected, owner_uid=owner_uid, anchor=anchor, partial=True)
    for parent, directories, filenames in os.walk(directory, topdown=False):
        for name in filenames:
            (Path(parent)/name).unlink()
        for name in directories:
            (Path(parent)/name).rmdir()
    directory.rmdir()


class Handler(SimpleHTTPRequestHandler):
    server_version = 'Portal'
    sys_version = ''

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, *args):
        pass

    def end_headers(self):
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy', CSP)
        super().end_headers()

    def list_directory(self, path):
        self.send_error(404)
        return None

    def send_head(self):
        path = unquote(urlsplit(self.path).path)
        if '\\' in path or any(part in ('.', '..') for part in path.split('/')):
            self.send_error(404)
            return None
        candidate = Path(self.directory)/path.lstrip('/')
        if any(part.startswith('.') for part in path.split('/') if part):
            self.send_error(404)
            return None
        host = self.headers.get('Host', '').split(':', 1)[0].lower()
        if path in CAPTIVE_PATHS or host not in ('', self.server.server_address[0]):
            self.send_response(302)
            self.send_header('Location', PORTAL_URL)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return None
        if not candidate.exists() and (path in CAPTIVE_PATHS or '.' not in Path(path).name):
            self.path = '/index.html'
        return super().send_head()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--serve', action='store_true', required=True)
    parser.add_argument('--directory', type=Path, required=True)
    parser.add_argument('--bind', choices=['10.79.0.1'], required=True)
    args = parser.parse_args(argv)
    from functools import partial
    server = ThreadingHTTPServer((args.bind, 80), partial(Handler, directory=str(args.directory)))
    server.daemon_threads = True
    server.serve_forever()


if __name__ == '__main__':
    main()
